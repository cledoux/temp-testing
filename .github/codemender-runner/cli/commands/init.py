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

"""`cm-runner init` -- set up `cm` for one repository and check the result.

`main` has already checked that `cm` is present and runs (`cm --version`)
before this command starts; if not, the run stops there. `init` then runs
four steps in order and stops at the first failure:

  1. Report which `cm` is in use, from the version `main` already read.
  2. Create `cm`'s workspace with `cm init`, but only when
     `~/.codemender/config.yaml` does not exist yet. With stdin closed (as in
     CI) `cm init` silently replaces an existing config with its stock
     default, which would throw away a config someone supplied on purpose.
  3. Write this repository's settings into the config with
     `config.inject_codemender_config`, then read the file back. That function
     only logs a failed write, so without the read-back a failure would look
     like success.
  4. Run `cm init --verify` and read its summary line (`Results: ...`) as
     one pass/fail `check` event. It exits 0 even when one of its checks
     fails, so its exit code cannot be trusted.

Each step emits one `check` event. Any failed check makes the exit code
`exit_codes.FAILED`; the reason is in the event and in the logs on stderr.

`cm` runs through `CmAdapter`, which captures its output and applies a
timeout. Outside `cli/` and `codemender.cm`, the only module imported is
`config.py`, so `init` needs nothing installed beyond PyYAML.
"""

from __future__ import annotations

import argparse
import dataclasses
import io
import logging
from pathlib import Path
import re
import sys
from typing import Optional

import yaml

from cli import exit_codes
from cli.events import EventEmitter
from codemender.cm import CmAdapter
import config

logger = logging.getLogger(__name__)

# How long any single `cm` call may take. Without a limit, a hung `cm` would
# hang the CI job.
CM_TIMEOUT_SEC = 60

# Check statuses, as they appear in the `check` event.
PASS = "pass"
FAIL = "fail"
# Something was missing and `init` fixed it.
RECOVERED = "recovered"


def cm_config_path() -> Path:
  """Returns the path of `cm`'s config file.

  Same location `config.inject_codemender_config` writes to.
  """
  return Path.home() / ".codemender" / "config.yaml"


@dataclasses.dataclass(frozen=True)
class InitConfig:
  """Everything `init` takes from the command line.

  Attributes:
    repo: The repository to set up, as an absolute path.
  """

  repo: Path

  def validate(self) -> int:
    """Checks the command-line input before anything is run.

    Returns:
      `exit_codes.OK`, or `exit_codes.USAGE` (with the reason logged) when
      `repo` is not a directory.
    """
    if not self.repo.is_dir():
      logger.error("--repo %s is not a directory.", self.repo)
      return exit_codes.USAGE
    return exit_codes.OK


def config_from_args(args: argparse.Namespace) -> InitConfig:
  """Builds an InitConfig from the parsed command line."""
  # `resolve()`, not `absolute()`: `absolute()` keeps `..` in the path, but
  # the config writer removes it, so the read-back in step 3 would not match.
  return InitConfig(repo=Path(args.repo).expanduser().resolve())


def run(
    cfg: InitConfig,
    adapter: CmAdapter,
    emitter: Optional[EventEmitter] = None,
) -> int:
  """Runs the setup steps in order, stopping at the first failure.

  Args:
    cfg: What to set up.
    adapter: The cm found and checked by `main`.
    emitter: Destination for `check` events, or None to log checks to stderr.

  Returns:
    `exit_codes.OK` when every check passed, `exit_codes.FAILED` when one
    failed, `exit_codes.USAGE` when `--repo` is not a directory.
  """
  err = cfg.validate()
  if err != exit_codes.OK:
    return err
  repo = cfg.repo

  _report_cm(adapter, emitter)

  # `cm` gets the runner's own environment. `init` never starts `cm`'s agent,
  # so there is no untrusted code to keep secrets away from.
  if not _run_init(repo, adapter, emitter):
    return exit_codes.FAILED
  if not _write_config(repo, emitter):
    return exit_codes.FAILED
  if not _verify_init(repo, adapter, emitter):
    return exit_codes.FAILED
  return exit_codes.OK


def _check(
    emitter: Optional[EventEmitter], name: str, status: str, message: str
) -> None:
  """Emits one `check` event, or logs the check outcome when emitter is None."""
  if emitter is not None:
    emitter.emit(
        "check",
        name=name,
        status=status,
        message=message,
    )
  else:
    logger.info("init check [%s] %s: %s", name, status, message)


def _report_cm(
    adapter: CmAdapter, emitter: Optional[EventEmitter] = None
) -> None:
  """Step 1: report which `cm` is in use.

  `main` has already checked that it runs, so this always passes. The
  version is the one `main` read; `cm` is not run again.
  """
  _check(
      emitter,
      "cm_binary",
      PASS,
      f"cm {adapter.version()} at {adapter.binary}",
  )


def _run_init(
    repo: Path, adapter: CmAdapter, emitter: Optional[EventEmitter] = None
) -> bool:
  """Step 2: create `cm`'s workspace with `cm init`, only when it is missing.

  See the module docstring for why an existing config is never touched.

  Returns:
    True if the config file exists afterwards.
  """
  config_path = cm_config_path()
  if config_path.is_file():
    _check(
        emitter,
        "cm_workspace",
        PASS,
        f"{config_path} already exists; kept as is",
    )
    return True
  result = adapter.run(["init"], cwd=str(repo), timeout_sec=CM_TIMEOUT_SEC)
  # `cm init` exits 0 in every case we have seen, so the file is the real
  # test of whether it worked.
  if not result.ok or not config_path.is_file():
    logger.error(
        "'cm init' did not create %s (exit %s, error %s). stderr:\n%s",
        config_path,
        result.exit_code,
        result.error,
        result.stderr,
    )
    _check(
        emitter, "cm_workspace", FAIL, f"'cm init' did not create {config_path}"
    )
    return False
  _check(
      emitter,
      "cm_workspace",
      RECOVERED,
      f"created {config_path} with 'cm init'",
  )
  return True


def _write_config(
    repo: Path, emitter: Optional[EventEmitter] = None
) -> bool:
  """Step 3: write this repo's settings into the config, then read it back.

  `inject_codemender_config` catches its own write errors and only logs them,
  so without the read-back a failed write would pass.

  The sandbox network setting is whatever `inject_codemender_config` writes:
  `permissive-open` unless CODEMENDER_SANDBOX_NETWORK_PROFILE says otherwise.
  Whether that is the right default is to be decided in the fix/verify work;
  `find` is unaffected, as its agent has no network tools.

  Returns:
    True if the config was rewritten and points at `repo`.
  """
  config_path = cm_config_path()
  before = _file_identity(config_path)
  # `inject_codemender_config` prompts on stdin when `sys.stdin.isatty()` is
  # true and no build command is configured; `init` must never prompt or hang.
  old_stdin = sys.stdin
  try:
    sys.stdin = io.StringIO()
    config.inject_codemender_config(str(repo))
  except Exception:  # pylint: disable=broad-exception-caught
    # Any other error is reported as a failed check, not a traceback.
    logger.exception("Writing %s failed.", config_path)
    _check(emitter, "cm_config", FAIL, f"could not write {config_path}")
    return False
  finally:
    sys.stdin = old_stdin
  settings = _read_back(config_path, before, repo)
  if settings is None:
    _check(
        emitter,
        "cm_config",
        FAIL,
        f"{config_path} was not updated for {repo}",
    )
    return False
  _check(emitter, "cm_config", PASS, _describe(repo, settings))
  return True


def _verify_init(
    repo: Path, adapter: CmAdapter, emitter: Optional[EventEmitter] = None
) -> bool:
  """Step 4: `cm`'s own check of the setup, `cm init --verify`.

  It exits 0 even when one of its checks fails, so the result is read from
  its summary line (`Results: 4 passed, 3 warnings, 1 failed`) and becomes
  one `cm_verify` check, pass or fail. The full report, including warnings
  such as an unset build command, goes to stderr.

  Warnings do not fail the check. In particular, `cm` 0.9.0 fails its server
  connectivity line only when it cannot find a GCP project ID. Once it has
  one, it reports that line as a warning ("Skipped") without contacting the
  server. So a passing `init` does not prove `cm` can reach the server or
  that credentials work; that shows up at the first model call.

  Returns:
    True if `cm` exited 0 and its summary line reports no failed checks.
  """
  result = adapter.run(
      ["init", "--verify"], cwd=str(repo), timeout_sec=CM_TIMEOUT_SEC
  )
  if result.error is not None:
    logger.error("'cm init --verify' did not finish: %s", result.error)
    _check(
        emitter,
        "cm_verify",
        FAIL,
        f"'cm init --verify' failed: {result.error}",
    )
    return False
  report = result.stdout.rstrip()

  summary = _verify_summary(result.stdout)
  if summary is None:
    # No summary line: `cm` stopped partway, or a later version reworded it.
    # Either way the result is unknown, which is never "nothing wrong".
    logger.error(
        "No 'Results:' line in the output of 'cm init --verify'.\n"
        "stdout:\n%s\nstderr:\n%s",
        report,
        result.stderr,
    )
    _check(
        emitter,
        "cm_verify",
        FAIL,
        "no summary line in the output of 'cm init --verify'",
    )
    return False
  if result.exit_code != 0:
    # Not seen on cm 0.9.0; treated as a failure in case a later version
    # starts using its exit code.
    logger.error(
        "'cm init --verify' exited %s.\nstdout:\n%s\nstderr:\n%s",
        result.exit_code,
        report,
        result.stderr,
    )
    _check(
        emitter,
        "cm_verify",
        FAIL,
        f"'cm init --verify' exited {result.exit_code}: {summary}",
    )
    return False
  if _failed_count(summary) > 0:
    logger.error("'cm init --verify' reported a failed check:\n%s", report)
    _check(emitter, "cm_verify", FAIL, summary)
    return False
  logger.info("'cm init --verify' report:\n%s", report)
  _check(emitter, "cm_verify", PASS, summary)
  return True


# The summary line of `cm init --verify`, e.g. "  Results: 4 passed, 4 warnings".
# `cm` 0.9.0 leaves out the failed count when it is zero.
_VERIFY_SUMMARY_RE = re.compile(r"^\s*Results:\s*(.*?)\s*$", re.MULTILINE)
_FAILED_COUNT_RE = re.compile(r"(\d+)\s+failed")


def _verify_summary(output: str) -> str | None:
  """Returns the counts from the `Results:` line, e.g. "4 passed, 4 warnings".

  None when there is no such line.
  """
  match = _VERIFY_SUMMARY_RE.search(output or "")
  return match.group(1) if match else None


def _failed_count(summary: str) -> int:
  """Returns the number of failed checks in a summary; 0 when not listed."""
  match = _FAILED_COUNT_RE.search(summary)
  return int(match.group(1)) if match else 0


def _file_identity(path: Path) -> tuple[int, int] | None:
  """Returns (inode, mtime in ns) for `path`, or None if it cannot be read.

  `inject_codemender_config` writes a new file and renames it into place, so a
  successful write always gives the path a new inode.
  """
  try:
    info = path.stat()
  except OSError:
    return None
  return (info.st_ino, info.st_mtime_ns)


def _read_back(
    path: Path, before: tuple[int, int] | None, repo: Path
) -> dict | None:
  """Confirms `path` was rewritten for `repo` and returns its contents.

  Args:
    path: The config file.
    before: `_file_identity(path)` from before the write.
    repo: The absolute repo path the settings must point at.

  Returns:
    The parsed config, or None (with the reason logged) if the file was not
    rewritten, cannot be parsed, or points the sandbox at another folder.
  """
  after = _file_identity(path)
  if after is None or after == before:
    logger.error("%s was not rewritten; see the error logged above.", path)
    return None
  try:
    with path.open(encoding="utf-8") as handle:
      data = yaml.safe_load(handle)
  except (OSError, yaml.YAMLError) as e:
    logger.error("Could not read back %s: %s", path, e)
    return None
  if not isinstance(data, dict):
    logger.error("%s does not hold a YAML mapping.", path)
    return None
  mounts = (data.get("sandbox") or {}).get("mounts") or {}
  target = mounts.get("target_dir")
  # The config stores the path as a string.
  if target != str(repo):
    logger.error(
        "%s has sandbox.mounts.target_dir=%r, expected %r.",
        path,
        target,
        str(repo),
    )
    return None
  return data


def _describe(repo: Path, settings: dict) -> str:
  """One-line summary of the settings that matter to a caller."""
  build = (settings.get("build") or {}).get("command") or "not set"
  network = ((settings.get("sandbox") or {}).get("network") or {}).get(
      "profile", "not set"
  )
  return (
      f"wrote settings for {repo}: build command {build}, "
      f"sandbox network {network}"
  )
