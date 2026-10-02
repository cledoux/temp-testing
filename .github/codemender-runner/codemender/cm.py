# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Code for running the `cm` binary and reading its output.

Two audiences, kept apart on purpose:

*   **New commands (`cli/`)** run `cm` only through `CmAdapter`. It starts `cm`
    itself, with a timeout and with output captured, and returns a `CmResult`
    this module owns. It never touches the legacy `utils` module.
*   **The legacy pipeline (`runners/`)** keeps using `parse_findings_json`,
    `extract_session_id` and `log_cm_version`, which still go through `utils`.
    Those imports happen inside the functions, so importing this module does
    not load `utils` (and through it, `requests`). `cm-runner version` has to
    work before `requirements.txt` is installed.
"""

import dataclasses
import json
import logging
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union


logger = logging.getLogger("codemender-orchestrator")


# ---------------------------------------------------------------------------
# New path: CmAdapter
# ---------------------------------------------------------------------------

# How long `cm --version` may take before we give up on it.
_VERSION_TIMEOUT_SEC = 30

# cm prints one of these lines per model call it makes, e.g.
# "Tokens: 41.5k in / 1.2k out / 42.7k total".
_TOKENS_RE = re.compile(
    r"Tokens:\s*([0-9.kMgG]+)\s*in\s*/\s*([0-9.kMgG]+)\s*out\s*/\s*([0-9.kMgG]+)\s*total"
)
_TOKEN_SUFFIXES = {"k": 1_000, "m": 1_000_000, "g": 1_000_000_000}


@dataclasses.dataclass(frozen=True)
class TokenUsage:
  """Model token counts reported by one `cm` call, summed across its lines."""

  in_tokens: int = 0
  out_tokens: int = 0
  total_tokens: int = 0


@dataclasses.dataclass(frozen=True)
class CmResult:
  """The outcome of one `cm` call, already processed.

  Attributes:
    args: The full command that was run, binary first.
    exit_code: `cm`'s exit code, or None if it never finished (see `error`).
    stdout: Everything `cm` wrote to stdout.
    stderr: Everything `cm` wrote to stderr. Kept separate from stdout.
    tokens: Token counts parsed from the output.
    error: Why `cm` could not be started or did not finish, or None.
  """

  args: Tuple[str, ...]
  exit_code: Optional[int]
  stdout: str
  stderr: str
  tokens: TokenUsage
  error: Optional[str] = None

  @property
  def ok(self) -> bool:
    """True when `cm` ran to completion and exited 0."""
    return self.error is None and self.exit_code == 0


# How long `cm report` and `cm report import` may take. Both only read or
# write `cm`'s local database.
_REPORT_TIMEOUT_SEC = 60.0


@dataclasses.dataclass(frozen=True)
class Finding:
  """One finding in `cm`'s local database, as read from `cm report --format json`.

  Attributes:
    finding_id: The ID `cm` assigned to the finding.
    status: `cm`'s lifecycle status (e.g. "OPEN", "FIXED", "VERIFIED").
    title: Short title reported by `cm`, if present.
    severity: Severity reported by `cm`, if present.
    file_path: Repository-relative file path reported by `cm`, if present.
  """

  finding_id: str
  status: str = ""
  title: str = ""
  severity: str = ""
  file_path: str = ""

  @classmethod
  def from_report_item(cls, item: Dict[str, Any]) -> Optional["Finding"]:
    """Builds a `Finding` from one JSON object in `cm report --format json`."""
    finding_id = item.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id:
      return None
    return cls(
        finding_id=finding_id,
        status=str(item.get("status") or ""),
        title=str(item.get("title") or ""),
        severity=str(item.get("severity") or ""),
        file_path=str(item.get("file_path") or ""),
    )

  @property
  def is_fixed(self) -> bool:
    """True when `cm fix` has marked this finding FIXED."""
    return self.status == "FIXED"


def _parse_token_count(text: str) -> int:
  """Converts a token count such as "561", "41.5k" or "1.2M" to an integer.

  Raises:
    ValueError: If `text` is not a number with an optional k/M/G suffix.
  """
  text = text.strip()
  if not text:
    raise ValueError("Empty token count.")
  multiplier = _TOKEN_SUFFIXES.get(text[-1].lower())
  if multiplier:
    return int(float(text[:-1]) * multiplier)
  return int(float(text))


def parse_token_usage(output: str) -> TokenUsage:
  """Sums every `Tokens: N in / N out / N total` line in `output`.

  Every current `cm` release prints these lines, so this always parses them.
  Output with no such lines yields zero counts.

  Args:
    output: Text written by `cm`.

  Returns:
    The summed token counts.
  """
  in_tokens = out_tokens = total_tokens = 0
  for match in _TOKENS_RE.finditer(output or ""):
    try:
      counts = [_parse_token_count(group) for group in match.groups()]
    except ValueError:
      continue
    in_tokens += counts[0]
    out_tokens += counts[1]
    total_tokens += counts[2]
  return TokenUsage(in_tokens, out_tokens, total_tokens)


def _as_text(output: Union[str, bytes, None]) -> str:
  """Returns captured output as text.

  `subprocess.TimeoutExpired` can carry bytes even when the call used
  `text=True`, so partial output from a timed-out call is decoded here.
  """
  if output is None:
    return ""
  if isinstance(output, bytes):
    return output.decode("utf-8", errors="replace")
  return output


class CmAdapter:
  """Runs one `cm` binary for the new commands and processes what it prints.

  Every call:

  *   closes `cm`'s stdin, so `cm` can never read the runner's own input;
  *   captures stdout and stderr separately, so nothing `cm` prints can reach
      the runner's stdout, which carries only JSON events (ADR-0001);
  *   honours a timeout, when one is given;
  *   never raises for a `cm` failure. A binary that cannot be started, a
      timeout and a non-zero exit all come back as a `CmResult`.
  """

  def __init__(self, binary: str):
    """Initialises the adapter.

    Args:
      binary: Path to the `cm` executable, or a name to look up on PATH.
    """
    self.binary = binary
    # Set by the first successful `version()` call.
    self._version: Optional[str] = None

  @classmethod
  def locate(cls, binary: Optional[str] = None) -> Optional["CmAdapter"]:
    """Returns an adapter for `binary`, or for the first `cm` on PATH.

    Args:
      binary: Explicit path to `cm`. When None, `cm` is looked up on PATH.

    Returns:
      An adapter, or None when no `cm` binary could be found.
    """
    path = binary or shutil.which("cm")
    return cls(path) if path else None

  def run(
      self,
      args: Sequence[str],
      cwd: Optional[str] = None,
      env: Optional[Dict[str, str]] = None,
      timeout_sec: Optional[float] = None,
  ) -> CmResult:
    """Runs `cm` with `args` and returns the processed result.

    Args:
      args: Arguments after the binary name, e.g. `["find", "."]`.
      cwd: Working directory for `cm`.
      env: Full environment for `cm`. None inherits the runner's environment.
      timeout_sec: Seconds to wait before stopping `cm`. None waits forever.

    Returns:
      A `CmResult`. Check `ok` before trusting `stdout`.
    """
    cmd = (self.binary, *args)
    logger.debug("Running: %s", " ".join(cmd))
    try:
      completed = subprocess.run(
          list(cmd),
          cwd=cwd,
          env=env,
          stdin=subprocess.DEVNULL,
          capture_output=True,
          text=True,
          timeout=timeout_sec,
          check=False,
      )
    except subprocess.TimeoutExpired as exc:
      stdout, stderr = _as_text(exc.stdout), _as_text(exc.stderr)
      return CmResult(
          args=cmd,
          exit_code=None,
          stdout=stdout,
          stderr=stderr,
          tokens=parse_token_usage(stdout + "\n" + stderr),
          error=f"timed out after {timeout_sec} s",
      )
    except (OSError, subprocess.SubprocessError) as exc:
      return CmResult(
          args=cmd,
          exit_code=None,
          stdout="",
          stderr="",
          tokens=TokenUsage(),
          error=f"could not run: {exc}",
      )

    stdout, stderr = completed.stdout or "", completed.stderr or ""
    return CmResult(
        args=cmd,
        exit_code=completed.returncode,
        stdout=stdout,
        stderr=stderr,
        tokens=parse_token_usage(stdout + "\n" + stderr),
    )

  def version(self, timeout_sec: float = _VERSION_TIMEOUT_SEC) -> Optional[str]:
    """Returns the bare `cm` version, e.g. "0.9.0", or None if unreadable.

    `cm` has no `version` subcommand, only the `--version` flag. Only stdout
    is parsed, so a notice `cm` prints on stderr is never taken for the
    version.

    Once a version has been read it is kept, so later calls return it without
    running `cm` again. A failed read is not kept.

    Args:
      timeout_sec: Seconds to wait for `cm --version`.
    """
    if self._version is not None:
      return self._version
    result = self.run(["--version"], timeout_sec=timeout_sec)
    if result.error:
      logger.warning(
          "Could not read cm version from %s: %s", self.binary, result.error
      )
      return None
    if result.exit_code != 0:
      logger.warning(
          "cm --version exited %d: %s", result.exit_code, result.stderr.strip()
      )
      return None
    self._version = _normalise_version(result.stdout)
    return self._version

  def list_findings(
      self,
      timeout_sec: float = _REPORT_TIMEOUT_SEC,
  ) -> Optional[Dict[str, Finding]]:
    """Returns every finding in `cm`'s local database, keyed by `finding_id`.

    Reads `cm report --format json`. On `cm` 0.11.0 that prints a JSON array on
    stdout, one object per finding with snake_case keys (`[]` when there are
    none), and only log lines on stderr. Without `cm init` it exits 1.

    Args:
      timeout_sec: Seconds to wait for `cm`.

    Returns:
      Each `Finding` keyed by `finding_id`, or None, with the reason logged, if
      `cm` failed or printed something else.
    """
    result = self.run(["report", "--format", "json"], timeout_sec=timeout_sec)
    if result.stderr.strip():
      logger.debug(
          "cm report --format json stderr:\n%s", result.stderr.rstrip()
      )
    if not result.ok:
      logger.error(
          "'cm report --format json' failed (exit %s, error %s). stderr:\n%s",
          result.exit_code,
          result.error,
          result.stderr.rstrip(),
      )
      return None
    try:
      raw_findings = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
      logger.error("'cm report --format json' did not print JSON: %s", exc)
      return None
    if not isinstance(raw_findings, list):
      logger.error(
          "'cm report --format json' printed a JSON %s, not a list of"
          " findings.",
          type(raw_findings).__name__,
      )
      return None
    findings: Dict[str, Finding] = {}
    for item in raw_findings:
      if isinstance(item, dict):
        finding = Finding.from_report_item(item)
        if finding is not None:
          findings[finding.finding_id] = finding
    return findings

  def import_finding(
      self,
      finding_file: str,
      project_dir: str,
      timeout_sec: float = _REPORT_TIMEOUT_SEC,
  ) -> Optional[Finding]:
    """Imports one finding into `cm`'s database and returns the `Finding`.

    `cm fix` and `cm verify` take the ID of a finding already in `cm`'s
    database, not a file. `cm report import` accepts a JSON or SARIF file, but
    it does not print the ID it assigns, and it assigns a new one on every
    import, even of the same file. So the findings are listed before and after
    the import, and exactly one must be new. This also works when the database
    already holds findings from earlier runs.

    Args:
      finding_file: Path to a JSON or SARIF file holding exactly one finding.
      project_dir: The repository the finding's file paths are relative to.
      timeout_sec: Seconds to wait for each `cm` call.

    Returns:
      The newly imported `Finding`, or None, with the reason logged, if any
      step failed or the import did not add exactly one finding.
    """
    before = self.list_findings(timeout_sec)
    if before is None:
      return None

    result = self.run(
        ["report", "import", "-f", finding_file, "-p", project_dir],
        timeout_sec=timeout_sec,
    )
    if result.stdout.strip():
      logger.info("cm report import: %s", result.stdout.strip())
    if result.stderr.strip():
      logger.debug("cm report import stderr:\n%s", result.stderr.rstrip())
    if not result.ok:
      logger.error(
          "'cm report import -f %s' failed (exit %s, error %s). stderr:\n%s",
          finding_file,
          result.exit_code,
          result.error,
          result.stderr.rstrip(),
      )
      return None

    after = self.list_findings(timeout_sec)
    if after is None:
      return None
    new_ids = sorted(set(after) - set(before))
    if len(new_ids) != 1:
      logger.error(
          "Expected 'cm report import' to add exactly one finding; it added %d"
          " (%s).",
          len(new_ids),
          ", ".join(new_ids) or "none",
      )
      return None
    return after[new_ids[0]]

  def get_finding(
      self,
      finding_id: str,
      timeout_sec: float = _REPORT_TIMEOUT_SEC,
  ) -> Optional[Finding]:
    """Returns one `Finding` from `cm report --format json`.

    `cm fix` and `cm verify` exit 0 whatever the outcome, so their result has to
    be read from the finding's status afterwards.

    Args:
      finding_id: The finding to look up.
      timeout_sec: Seconds to wait for `cm`.

    Returns:
      The `Finding`, or None, with the reason logged, if `cm` failed or the
      finding is not in its database.
    """
    findings = self.list_findings(timeout_sec)
    if findings is None:
      return None
    if finding_id not in findings:
      logger.error("Finding %s is not in cm's database.", finding_id)
      return None
    return findings[finding_id]


def _normalise_version(raw: Optional[str]) -> Optional[str]:
  """Extracts the bare version from `cm --version` output.

  `cm --version` prints "cm version 0.9.0"; we want "0.9.0".

  Args:
    raw: Raw stdout from the version call, or None.

  Returns:
    The trailing version token, or None if there was nothing to parse.
  """
  if not raw:
    return None
  lines = [line.strip() for line in raw.splitlines() if line.strip()]
  if not lines:
    return None
  for line in lines:
    if "version" in line.lower():
      parts = line.split()
      if parts:
        return parts[-1]
  parts = lines[0].split()
  return parts[-1] if parts else None


def detect_cm(
    adapter: CmAdapter,
    timeout_sec: float = _VERSION_TIMEOUT_SEC,
) -> Dict[str, Any]:
  """Reads the version of an already located cm without ever raising.

  Args:
    adapter: The cm found by `CmAdapter.locate`.
    timeout_sec: How long to wait for `cm --version` before giving up.

  Returns:
    A dict with `found`, `version` and `path` keys. `found` is always True;
    it stays so the `version` event keeps the shape published in ADR-0001.
    `version` may be None if the binary could not be executed, timed out,
    or its output could not be parsed.
  """
  return {
      "found": True,
      "version": adapter.version(timeout_sec=timeout_sec),
      "path": adapter.binary,
  }


# ---------------------------------------------------------------------------
# Legacy pipeline helpers (runners/). Kept working, not extended.
# ---------------------------------------------------------------------------

# Canonical PascalCase finding schema per docs/architecture/guardrails.md Section 6.
# cm CLI 0.7.0 (cl/974628022) switched `cm report --format json` to snake_case keys,
# so both casings are normalized to the canonical form for version-agnostic parsing.
_FINDING_KEY_ALIASES = {
    "finding_id": "FindingID",
    "session_id": "SessionID",
    "title": "Title",
    "file_path": "FilePath",
    "severity": "Severity",
    "confidence": "Confidence",
    "analysis": "Analysis",
    "snippet": "Snippet",
    "vuln_type": "VulnType",
    "vuln_id": "VulnID",
    "fingerprint": "Fingerprint",
    "status": "Status",
    "source_stage": "SourceStage",
    "finding_json": "FindingJSON",
    "updated_at": "UpdatedAt",
    "start_line": "StartLine",
    "end_line": "EndLine",
    "dismiss_reason": "DismissReason",
    "confidence_level": "ConfidenceLevel",
}


def parse_findings_json(json_str: str) -> List[Dict[str, Any]]:
  """Parses `cm report --format json` output normalizing keys to PascalCase."""
  # Imported here, not at the top, so that importing this module for
  # `CmAdapter` never loads `utils` (see the module docstring).
  from utils import extract_json_from_output  # pylint: disable=g-import-not-at-top

  data = extract_json_from_output(json_str)
  if data is None:
    logger.error("No valid JSON array or object found in report.")
    return []

  if isinstance(data, dict):
    findings = data.get("findings", data.get("items", []))
  elif isinstance(data, list):
    findings = data
  else:
    findings = []

  cleaned_findings = []
  for item in findings:
    if not isinstance(item, dict):
      continue
    cleaned = {}
    for k, v in item.items():
      if v == "":
        cleaned[k] = None
      else:
        cleaned[k] = v
      # Mirror snake_case keys onto the canonical PascalCase name. The original
      # key is retained so downstream snake_case readers keep working, and an
      # explicit PascalCase key already present in the payload always wins.
      canonical = _FINDING_KEY_ALIASES.get(k)
      if canonical and canonical not in item:
        cleaned[canonical] = cleaned[k]
    cleaned_findings.append(cleaned)

  return cleaned_findings


def extract_session_id(find_stdout: str) -> Optional[str]:
  """Extracts the CodeMender session ID from 'cm find' output."""
  # Match UUID format session ID (e.g. Session: f7f7b492-3564-4dc0-bc8f-2020554ebe24)
  match = re.search(
      r"Session:\s*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})",
      find_stdout,
      re.IGNORECASE,
  )
  if match:
    return match.group(1)
  return None


def log_cm_version(
    cm_binary: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[str] = None,
) -> Optional[str]:
  """Runs `cm --version` and logs the CodeMender CLI binary version.

  Args:
    cm_binary: Path or name of the cm executable.
    env: Environment variables for the subprocess.
    cwd: Working directory for running the command.

  Returns:
    The output version string if successfully retrieved, or None.
  """
  # Imported here, not at the top, so that importing this module for
  # `CmAdapter` never loads `utils` (see the module docstring).
  from utils import run_command  # pylint: disable=g-import-not-at-top

  bin_path = cm_binary or shutil.which("cm") or "cm"
  try:
    res = run_command(
        [bin_path, "--version"],
        cwd=cwd,
        env=env,
        check=False,
        capture_stderr=True,
    )
    if res.returncode == 0:
      version_str = res.stdout.strip()
      if version_str:
        logger.info("CodeMender CLI version: %s", version_str)
        return version_str
      logger.warning("CodeMender CLI returned empty version output.")
    else:
      logger.warning(
          "Failed to retrieve CodeMender CLI version (exit code %d): %s",
          res.returncode,
          res.stderr.strip() if getattr(res, "stderr", None) else "",
      )
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.warning("Error checking CodeMender CLI version: %s", e)
  return None
