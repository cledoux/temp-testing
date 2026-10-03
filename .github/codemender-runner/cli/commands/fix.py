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

"""`cm-runner fix` -- patch one finding and print the patch (SPEC-FIX).

`main` has already checked that `cm` runs. `fix` then runs these steps in
order and stops at the first failure:

  1. Check the command line, then read the finding: a file, or stdin with
     `--finding -`. It must be a SARIF document holding exactly one result.
  2. Check the repository. It must be a Git working tree with no uncommitted
     work other than the files `cm` itself writes. `cm fix` starts with
     `git checkout HEAD -- . && git clean -fd`, which would otherwise throw
     that work away without warning.
  3. Import the finding into `cm`'s database and find the ID `cm` gave it.
  4. Run `cm fix` on that ID. This usually takes 10 minutes or more.
  5. Confirm the finding's status is `FIXED`. `cm fix` exits 0 whether or not
     it produced a patch.
  6. Collect the patch with Git, write it to `--out` if given, then write it
     to stdout.

stdout carries the patch as a unified diff, byte for byte as `git diff` wrote
it, and nothing else, so `cm-runner fix ... > fix.diff && git apply fix.diff`
works. On exit 2 or 3 nothing is written to stdout. The patch is left applied
in the repository and is not committed.

`cm` runs through `CmAdapter` with the runner's own environment (ADR-0003).
Git runs through `vcs/git.py`.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import logging
import os
from pathlib import Path
import sys
import tempfile
from typing import Optional, TextIO

from cli import exit_codes
from cli import sarif
from cli.events import EventEmitter
from codemender.cm import CmAdapter
from codemender.cm import Finding
from vcs import git

logger = logging.getLogger(__name__)

# `cm report` and `cm report import` only touch `cm`'s local database.
_CM_REPORT_TIMEOUT_SEC = 60.0

# A 10-line file took 8 to 9 minutes on `cm` 0.11.0, so real repositories need
# a generous limit.
_FIX_TIMEOUT_SEC = 1800.0

# Files `cm` writes into the repository it works on. They are not the caller's
# work, so they don't block a run, and they are never part of the patch.
_CM_OWN_PATHS = (".cm_project", ".exploit")

# The status `cm report --format json` shows once `cm fix` has patched a finding.
_FIXED = "FIXED"

# Name of the `--out` diff file when the finding came from stdin.
_STDIN_DIFF_NAME = "finding"


@dataclasses.dataclass(frozen=True)
class FixConfig:
  """Everything `fix` takes from the command line.

  Attributes:
    finding: The finding file, as an absolute path, or None to read the
      finding from stdin (`--finding -`).
    repo: The repository to fix, as an absolute path.
    out: Folder to write the diff file into, or None for no file.
  """

  finding: Optional[Path]
  repo: Path
  out: Optional[Path] = None

  def __post_init__(self) -> None:
    if self.finding is None or str(self.finding) == "-":
      object.__setattr__(self, "finding", None)
    else:
      object.__setattr__(
          self, "finding", Path(self.finding).expanduser().resolve()
      )
    object.__setattr__(self, "repo", Path(self.repo).expanduser().resolve())
    if self.out is not None:
      object.__setattr__(self, "out", Path(self.out).expanduser().resolve())

  def validate(self) -> int:
    """Checks the command-line input before anything is run.

    Returns:
      `exit_codes.OK`, or `exit_codes.USAGE` (with the reason logged) when
      `repo` is not a directory, `finding` is not a readable file, or `out`
      is an existing file.
    """
    if not self.repo.is_dir():
      logger.error("--repo %s is not a directory.", self.repo)
      return exit_codes.USAGE
    if self.finding is not None and not (
        self.finding.is_file() and os.access(self.finding, os.R_OK)
    ):
      logger.error("--finding %s is not a readable file.", self.finding)
      return exit_codes.USAGE
    if self.out is not None and self.out.exists() and not self.out.is_dir():
      logger.error("--out %s exists and is not a directory.", self.out)
      return exit_codes.USAGE
    return exit_codes.OK

  @property
  def diff_file_name(self) -> str:
    """Name of the `--out` diff file: the finding file's name, as `.diff`."""
    stem = self.finding.stem if self.finding is not None else _STDIN_DIFF_NAME
    return f"{stem}.diff"


def config_from_args(args: argparse.Namespace) -> FixConfig:
  """Builds a FixConfig from the parsed command line."""
  return FixConfig(finding=args.finding, repo=args.repo, out=args.out)


def run(
    cfg: FixConfig,
    adapter: CmAdapter,
    emitter: EventEmitter,
) -> int:
  """Fixes one finding and writes the patch to stdout.

  Args:
    cfg: What to fix.
    adapter: The cm found and checked by `main`.
    emitter: Holds the real stdout, which receives the patch.

  Returns:
    `exit_codes.OK` when the finding was fixed and the patch written,
    `exit_codes.USAGE` for a bad command line or finding, and
    `exit_codes.FAILED` for anything else.
  """
  err = cfg.validate()
  if err != exit_codes.OK:
    return err
  finding_text = _read_finding(cfg)
  if finding_text is None:
    return exit_codes.USAGE

  if not _check_repository(cfg.repo):
    return exit_codes.FAILED
  finding = _import(cfg, finding_text, adapter)
  if finding is None:
    return exit_codes.FAILED
  if not _run_fix(cfg.repo, finding.finding_id, adapter):
    return exit_codes.FAILED
  if not _confirm_fixed(finding.finding_id, adapter):
    return exit_codes.FAILED
  patch = _collect_patch(cfg.repo)
  if patch is None:
    return exit_codes.FAILED
  if cfg.out is not None and not _write_diff_file(cfg, patch):
    return exit_codes.FAILED

  _write_patch(emitter.stream, patch)
  logger.info(
      "Fixed finding %s; wrote a %d-byte patch.",
      finding.finding_id,
      len(patch),
  )
  return exit_codes.OK


def _read_finding(cfg: FixConfig) -> Optional[str]:
  """Reads the finding and checks that it is SARIF holding exactly one result.

  A file with several results is rejected rather than fixed in part, so one
  run always means one finding and one patch.

  Returns:
    The finding as text, or None with the reason logged.
  """
  source = "stdin" if cfg.finding is None else str(cfg.finding)
  try:
    if cfg.finding is not None:
      text = cfg.finding.read_text(encoding="utf-8")
    elif sys.stdin is not None:
      text = sys.stdin.read()
    else:
      text = ""
  except (OSError, UnicodeDecodeError) as exc:
    logger.error("Could not read the finding from %s: %s", source, exc)
    return None

  try:
    doc = sarif.SarifDocument.from_json(text)
  except sarif.SarifJsonError as exc:
    logger.error("The finding from %s is not valid JSON: %s", source, exc)
    return None
  except sarif.SarifSchemaError as exc:
    logger.error("The finding from %s is not a SARIF document: %s", source, exc)
    return None

  count = doc.result_count
  if count != 1:
    logger.error(
        "The finding from %s holds %d results; fix takes exactly one. Split a"
        " find-diff report into one file per finding first (see 'From"
        " find-diff to fix' in docs/guides/calling_cm_runner.md).",
        source,
        count,
    )
    return None
  return text


def _check_repository(repo: Path) -> bool:
  """Checks that `repo` is a Git working tree with no uncommitted work."""
  if not git.is_git_repository(repo.as_posix()):
    logger.error("--repo %s is not inside a Git working tree.", repo)
    return False
  uncommitted = git.list_uncommitted_paths(repo.as_posix(), exclude=_CM_OWN_PATHS)
  if uncommitted is None:
    logger.error("Could not check %s for uncommitted work.", repo)
    return False
  if uncommitted:
    logger.error(
        "--repo %s has uncommitted work. 'cm fix' would discard it, because it"
        " starts with 'git checkout HEAD -- . && git clean -fd'. Commit or"
        " stash these files first:\n  %s",
        repo,
        "\n  ".join(uncommitted),
    )
    return False
  return True


def _import(
    cfg: FixConfig, finding_text: str, adapter: CmAdapter
) -> Optional[Finding]:
  """Imports the finding into `cm` and returns the `Finding` `cm` created."""
  if cfg.finding is not None:
    return adapter.import_finding(
        cfg.finding.as_posix(),
        cfg.repo.as_posix(),
        timeout_sec=_CM_REPORT_TIMEOUT_SEC,
    )

  # `cm report import` only reads files, so a finding from stdin goes into a
  # temporary file first. It must sit outside the repository, or it would end
  # up in the patch.
  try:
    handle, path = tempfile.mkstemp(
        prefix="cm-runner-finding-", suffix=".sarif"
    )
  except OSError as exc:
    logger.error("Could not create a temporary file for the finding: %s", exc)
    return None
  try:
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
      stream.write(finding_text)
    if Path(path).resolve().is_relative_to(cfg.repo):
      logger.error(
          "The temporary folder %s is inside --repo %s. Set TMPDIR to a folder"
          " outside the repository.",
          Path(path).parent,
          cfg.repo,
      )
      return None
    return adapter.import_finding(
        path, cfg.repo.as_posix(), timeout_sec=_CM_REPORT_TIMEOUT_SEC
    )
  except OSError as exc:
    logger.error("Could not write the finding to %s: %s", path, exc)
    return None
  finally:
    with contextlib.suppress(OSError):
      os.unlink(path)


def _run_fix(repo: Path, finding_id: str, adapter: CmAdapter) -> bool:
  """Runs `cm fix` once on `finding_id`. Retrying is left to the caller."""
  logger.info(
      "Running 'cm fix' on finding %s. This usually takes 10 minutes or more;"
      " cm's output is logged when it finishes.",
      finding_id,
  )
  # `--bypass-warning` accepts `cm`'s responsibility warning on the caller's
  # behalf, as the existing pipeline does. There is no terminal to ask in CI.
  result = adapter.run(
      ["fix", "-y", "--bypass-warning", finding_id],
      cwd=repo.as_posix(),
      timeout_sec=_FIX_TIMEOUT_SEC,
  )
  logger.info("cm fix stdout:\n%s", result.stdout.rstrip())
  logger.info("cm fix stderr:\n%s", result.stderr.rstrip())
  if not result.ok:
    logger.error(
        "'cm fix %s' failed (exit %s, error %s).",
        finding_id,
        result.exit_code,
        result.error,
    )
    return False
  return True


def _confirm_fixed(finding_id: str, adapter: CmAdapter) -> bool:
  """Checks that `cm` marked the finding FIXED."""
  finding = adapter.get_finding(finding_id, timeout_sec=_CM_REPORT_TIMEOUT_SEC)
  if finding is None:
    return False
  if not finding.is_fixed:
    logger.error(
        "cm fix finished, but finding %s is %s, not %s. No patch was produced.",
        finding_id,
        finding.status or "without a status",
        _FIXED,
    )
    return False
  return True


def _collect_patch(repo: Path) -> Optional[bytes]:
  """Returns the patch `cm fix` left in the working tree, or None."""
  patch = git.diff_working_tree(repo.as_posix(), exclude=_CM_OWN_PATHS)
  if patch is None:
    logger.error("Could not collect the patch from %s with git.", repo)
    return None
  if not patch.strip():
    logger.error(
        "cm marked the finding %s, but the working tree has no changes.", _FIXED
    )
    return None
  return patch


def _write_diff_file(cfg: FixConfig, patch: bytes) -> bool:
  """Writes the patch to `--out`, before anything goes to stdout."""
  assert cfg.out is not None
  target = cfg.out / cfg.diff_file_name
  try:
    cfg.out.mkdir(parents=True, exist_ok=True)
    target.write_bytes(patch)
  except OSError as exc:
    logger.error("Could not write the patch to %s: %s", target, exc)
    return False
  logger.info("Wrote the patch to %s.", target)
  return True


def _write_patch(stream: TextIO, patch: bytes) -> None:
  """Writes the patch to `stream` byte for byte.

  Writing to the stream's underlying binary buffer keeps Windows line endings
  and bytes that are not valid UTF-8 exactly as Git wrote them. A stream with
  no buffer, such as a test's `StringIO`, gets the decoded text instead.
  """
  stream.flush()
  buffer = getattr(stream, "buffer", None)
  if buffer is not None:
    buffer.write(patch)
    buffer.flush()
  else:
    stream.write(patch.decode("utf-8", errors="replace"))
    stream.flush()
