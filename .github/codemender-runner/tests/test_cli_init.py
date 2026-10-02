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

"""Tests for `cm-runner init`.

Like `test_cli.py`, these run the CLI in a subprocess. Each run gets:

  * an empty PATH, so a real `cm` on the developer's machine never leaks in;
  * a temporary HOME, so `~/.codemender` is never the developer's own;
  * stdin closed, so nothing can stop and wait for an answer;
  * no inherited `CODEMENDER_*` variables, so local settings cannot change
    the result.
"""

import argparse
import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli import exit_codes
from codemender.cm import CmAdapter

# Directory containing the `cli` package, used as cwd so `python -m cli` works.
_PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The repo's pre-existing fake cm. It rejects `--version`.
_FAKE_CM = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cm")

# Real `cm init --verify` output captured from cm 0.9.0.
_TESTDATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata")
_VERIFY_OK = os.path.join(_TESTDATA, "cm_0.9.0_init_verify_ok.txt")
_VERIFY_NO_PROJECT = os.path.join(
    _TESTDATA, "cm_0.9.0_init_verify_no_project.txt"
)
_VERIFY_NO_CONFIG = os.path.join(
    _TESTDATA, "cm_0.9.0_init_verify_no_config.txt"
)

# What the stub's `cm init` does by default: what the real one does, which
# is write a stock config.
_STUB_INIT_WRITES_CONFIG = (
    'mkdir -p "$HOME/.codemender" && '
    'echo "stock_default: true" > "$HOME/.codemender/config.yaml"'
)

# Stub cm. Every call appends one line to a log file:
#   <args> | cwd=<dir>
# so a test can see whether `cm init` ran, and where.
# `cm init --verify` prints a saved report and exits with a chosen code.
_STUB_CM_TEMPLATE = """#!/bin/bash
# The CLI runs with an empty PATH in these tests; the stub needs mkdir.
PATH=/usr/bin:/bin
echo "$* | cwd=$PWD" >> "{log}"
case "$*" in
  --version) echo "cm version 0.9.0" ;;
  "init --verify") cat "{verify_output}"; exit {verify_exit} ;;
  init) {init_body} ;;
esac
"""


class InitTestBase(unittest.TestCase):
  """Runs `python -m cli init` in a controlled environment."""

  def setUp(self):
    super().setUp()
    self.tmp = tempfile.mkdtemp(prefix="cm_runner_init_")
    self.addCleanup(shutil.rmtree, self.tmp, True)

    self.empty_path = os.path.join(self.tmp, "empty_path")
    self.home = os.path.join(self.tmp, "home")
    self.repo = os.path.join(self.tmp, "repo")
    for directory in (self.empty_path, self.home, self.repo):
      os.mkdir(directory)

    self.cm_log = os.path.join(self.tmp, "cm_calls.log")
    self.config_path = os.path.join(self.home, ".codemender", "config.yaml")

  def write_stub_cm(
      self,
      init_body=_STUB_INIT_WRITES_CONFIG,
      verify_output=_VERIFY_OK,
      verify_exit=0,
  ):
    """Creates the stub cm and returns its path.

    Args:
      init_body: Shell commands the stub runs for `cm init`.
      verify_output: File whose contents `cm init --verify` prints.
      verify_exit: Exit code of `cm init --verify`.
    """
    path = os.path.join(self.tmp, "cm")
    with open(path, "w", encoding="utf-8") as handle:
      handle.write(
          _STUB_CM_TEMPLATE.format(
              log=self.cm_log,
              init_body=init_body,
              verify_output=verify_output,
              verify_exit=verify_exit,
          )
      )
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP)
    return path

  def cm_calls(self):
    """Returns the stub's log lines, one per `cm` call."""
    if not os.path.exists(self.cm_log):
      return []
    with open(self.cm_log, encoding="utf-8") as handle:
      return handle.read().splitlines()

  def init_calls(self):
    """Returns the log lines for `cm init` calls only."""
    return [c for c in self.cm_calls() if c.split(" | ")[0] == "init"]

  def read_config(self):
    """Returns the parsed `~/.codemender/config.yaml` of the test HOME."""
    with open(self.config_path, encoding="utf-8") as handle:
      return yaml.safe_load(handle)

  def run_init(self, *args, extra_env=None, cwd=None):
    """Runs `init` with the given extra arguments.

    Args:
      *args: Arguments passed after `init`.
      extra_env: Variables added to the child's otherwise minimal environment.
      cwd: Folder to run from. Defaults to the package folder; any other
        folder is reached through PYTHONPATH.

    Returns:
      The completed process, with text-mode stdout and stderr.
    """
    env = {
        "PATH": self.empty_path,
        "HOME": self.home,
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if cwd is not None:
      env["PYTHONPATH"] = _PKG_DIR
    env.update(extra_env or {})
    return subprocess.run(
        [sys.executable, "-m", "cli", "init", *args],
        cwd=_PKG_DIR if cwd is None else cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

  def events(self, completed):
    """Parses stdout as NDJSON; every line must be a JSON object."""
    events = [json.loads(line) for line in completed.stdout.splitlines()]
    for event in events:
      self.assertIsInstance(event, dict)
    return events


class TestInitCmBinary(InitTestBase):
  """`cm` must be present and run; `main` checks this before `init` starts."""

  def assert_stopped_before_init(self, result):
    """Exit 3, nothing on stdout, and no `cm init` or config written."""
    self.assertEqual(result.returncode, exit_codes.FAILED, result.stderr)
    self.assertEqual(result.stdout, "")
    self.assertEqual(self.init_calls(), [])
    self.assertFalse(os.path.exists(self.config_path))

  def test_missing_cm_fails(self):
    """No cm on PATH: the run stops before `init`, reason on stderr."""
    result = self.run_init("--repo", self.repo)

    self.assert_stopped_before_init(result)
    self.assertIn("cm not found", result.stderr)

  def test_working_cm_passes(self):
    """A cm that reports its version: the first check is a pass.

    `cm --version` runs once in total: `main` checks it and `init` reports
    the version it read.
    """
    stub = self.write_stub_cm()

    result = self.run_init("--repo", self.repo, "--cm-binary", stub)

    self.assertEqual(result.returncode, exit_codes.OK, result.stderr)
    events = self.events(result)
    self.assertEqual(events[0]["name"], "cm_binary")
    self.assertEqual(events[0]["status"], "pass")
    self.assertIn("0.9.0", events[0]["message"])
    self.assertIn(stub, events[0]["message"])
    version_calls = [c for c in self.cm_calls() if c.startswith("--version ")]
    self.assertEqual(len(version_calls), 1, self.cm_calls())

  def test_cm_that_will_not_report_version_fails(self):
    """A cm that is present but fails `--version` stops the run."""
    result = self.run_init("--repo", self.repo, "--cm-binary", _FAKE_CM)

    self.assert_stopped_before_init(result)
    self.assertIn("did not run 'cm --version'", result.stderr)

  def test_cm_binary_path_that_does_not_exist_fails(self):
    """An explicit --cm-binary that does not exist stops the run."""
    missing = os.path.join(self.tmp, "no_such_cm")

    result = self.run_init("--repo", self.repo, "--cm-binary", missing)

    self.assert_stopped_before_init(result)


class TestInitWorkspace(InitTestBase):
  """Step 2 of `init`: run `cm init` only when the config is missing."""

  def test_fresh_home_runs_cm_init_once(self):
    """No config yet: `cm init` runs once and the check is `recovered`."""
    stub = self.write_stub_cm()

    result = self.run_init("--repo", self.repo, "--cm-binary", stub)

    self.assertEqual(result.returncode, exit_codes.OK, result.stderr)
    events = self.events(result)
    self.assertEqual(
        [(e["name"], e["status"]) for e in events[:3]],
        [
            ("cm_binary", "pass"),
            ("cm_workspace", "recovered"),
            ("cm_config", "pass"),
        ],
    )
    self.assertEqual(len(self.init_calls()), 1, self.cm_calls())
    self.assertTrue(os.path.isfile(self.config_path))

  def test_existing_config_is_kept_and_cm_init_not_run(self):
    """Config already there: `cm init` is not run, so its settings survive.

    This is the step 2 change. The real `cm init`, with stdin closed, would
    replace this file with its stock default. Step 3 then merges the repo's
    settings into the file, keeping what was there.
    """
    os.makedirs(os.path.dirname(self.config_path))
    with open(self.config_path, "w", encoding="utf-8") as handle:
      handle.write("team_id: customer-supplied\n")
    stub = self.write_stub_cm()

    result = self.run_init("--repo", self.repo, "--cm-binary", stub)

    self.assertEqual(result.returncode, exit_codes.OK, result.stderr)
    events = self.events(result)
    self.assertEqual(events[1]["name"], "cm_workspace")
    self.assertEqual(events[1]["status"], "pass")
    self.assertEqual(self.init_calls(), [])
    self.assertEqual(self.read_config()["team_id"], "customer-supplied")

  def test_cm_init_that_creates_nothing_fails(self):
    """`cm init` exits 0 but writes no config: fail, exit 3.

    The real `cm init` exits 0 in every case we have seen, so the exit code
    alone cannot be trusted.
    """
    stub = self.write_stub_cm(init_body="true")

    result = self.run_init("--repo", self.repo, "--cm-binary", stub)

    self.assertEqual(result.returncode, exit_codes.FAILED, result.stderr)
    events = self.events(result)
    self.assertEqual(events[-1]["name"], "cm_workspace")
    self.assertEqual(events[-1]["status"], "fail")

  def test_cm_init_that_exits_non_zero_fails(self):
    """`cm init` exits non-zero: fail, exit 3, even if it wrote a file."""
    stub = self.write_stub_cm(
        init_body=_STUB_INIT_WRITES_CONFIG + "; echo boom >&2; exit 1"
    )

    result = self.run_init("--repo", self.repo, "--cm-binary", stub)

    self.assertEqual(result.returncode, exit_codes.FAILED, result.stderr)
    self.assertEqual(self.events(result)[-1]["status"], "fail")
    # cm's own error text goes to stderr, never to stdout.
    self.assertIn("boom", result.stderr)
    self.assertNotIn("boom", result.stdout)

  def test_cm_init_runs_in_repo_and_leaves_no_cache_folder(self):
    """`cm init` runs from the repo, and no cache folder is created there."""
    stub = self.write_stub_cm()

    self.run_init("--repo", self.repo, "--cm-binary", stub)

    [call] = self.init_calls()
    self.assertIn(f"cwd={os.path.realpath(self.repo)}", call)
    self.assertFalse(
        os.path.exists(os.path.join(self.repo, ".codemender_cache"))
    )


class TestInitConfig(InitTestBase):
  """Step 3 of `init`: write the repo's settings, then read them back."""

  def config_event(self, result):
    """Returns the `cm_config` check, asserting there is exactly one."""
    [event] = [e for e in self.events(result) if e["name"] == "cm_config"]
    return event

  def test_settings_point_at_the_repo(self):
    """The written config points cm's sandbox and scope at the repo."""
    stub = self.write_stub_cm()

    result = self.run_init("--repo", self.repo, "--cm-binary", stub)

    self.assertEqual(result.returncode, exit_codes.OK, result.stderr)
    event = self.config_event(result)
    self.assertEqual(event["status"], "pass")
    self.assertIn(self.repo, event["message"])
    settings = self.read_config()
    self.assertEqual(settings["sandbox"]["mounts"]["target_dir"], self.repo)
    self.assertEqual(settings["project_paths"], [self.repo])
    self.assertEqual(settings["vcs"]["type"], "git")

  def test_legacy_sandbox_network_default_is_kept(self):
    """No override: the legacy default, `permissive-open`, is written."""
    stub = self.write_stub_cm()

    result = self.run_init("--repo", self.repo, "--cm-binary", stub)

    message = self.config_event(result)["message"]
    self.assertIn("sandbox network permissive-open", message)

  def test_build_command_is_guessed_from_the_repo(self):
    """A package.json with a test script gives `npm test`, as in legacy."""
    with open(os.path.join(self.repo, "package.json"), "w") as handle:
      json.dump({"scripts": {"test": "jest"}}, handle)
    stub = self.write_stub_cm()

    result = self.run_init("--repo", self.repo, "--cm-binary", stub)

    self.assertIn("build command npm test", self.config_event(result)["message"])
    self.assertEqual(self.read_config()["build"]["command"], "npm test")

  def test_build_command_from_environment_wins(self):
    """CODEMENDER_BUILD_COMMAND overrides the guess, as in legacy."""
    with open(os.path.join(self.repo, "package.json"), "w") as handle:
      json.dump({"scripts": {"test": "jest"}}, handle)
    stub = self.write_stub_cm()

    result = self.run_init(
        "--repo",
        self.repo,
        "--cm-binary",
        stub,
        extra_env={"CODEMENDER_BUILD_COMMAND": "make check"},
    )

    self.assertIn(
        "build command make check", self.config_event(result)["message"]
    )

  def test_no_build_command_is_reported_and_does_not_block(self):
    """Nothing to guess from: reported as `not set`; no prompt, no hang."""
    stub = self.write_stub_cm()

    result = self.run_init("--repo", self.repo, "--cm-binary", stub)

    self.assertEqual(result.returncode, exit_codes.OK, result.stderr)
    self.assertIn("build command not set", self.config_event(result)["message"])

  @unittest.skipIf(os.geteuid() == 0, "root ignores file permissions")
  def test_failed_write_is_caught(self):
    """The legacy writer only logs a failed write; `init` must fail.

    This is the step 3 change. The config folder is made read-only so the write
    cannot happen.
    """
    os.makedirs(os.path.dirname(self.config_path))
    with open(self.config_path, "w", encoding="utf-8") as handle:
      handle.write("team_id: customer-supplied\n")
    config_dir = os.path.dirname(self.config_path)
    os.chmod(config_dir, 0o555)
    self.addCleanup(os.chmod, config_dir, 0o755)
    stub = self.write_stub_cm()

    result = self.run_init("--repo", self.repo, "--cm-binary", stub)

    self.assertEqual(result.returncode, exit_codes.FAILED, result.stderr)
    event = self.config_event(result)
    self.assertEqual(event["status"], "fail")
    self.assertEqual(self.events(result)[-1], event)


class TestInitVerify(InitTestBase):
  """Step 4 of `init`: `cm init --verify`, read from its summary line."""

  def verify_events(self, result):
    """Returns the `cm_verify` checks, in order."""
    return [e for e in self.events(result) if e["name"] == "cm_verify"]

  def test_passing_report_is_one_pass_event(self):
    """Warnings only: one `cm_verify` pass carrying cm's counts."""
    stub = self.write_stub_cm(verify_output=_VERIFY_OK)

    result = self.run_init("--repo", self.repo, "--cm-binary", stub)

    self.assertEqual(result.returncode, exit_codes.OK, result.stderr)
    [event] = self.verify_events(result)
    self.assertEqual(event["status"], "pass")
    self.assertEqual(event["message"], "4 passed, 4 warnings")
    # The per-item detail, warnings included, is on stderr.
    self.assertIn("Build command", result.stderr)

  def test_failed_check_fails_the_run_although_cm_exits_0(self):
    """A failed count means exit 3, even though `cm` itself exits 0.

    Uses the real report for "no GCP project found". The full report,
    including cm's advice, goes to stderr.
    """
    stub = self.write_stub_cm(verify_output=_VERIFY_NO_PROJECT)

    result = self.run_init("--repo", self.repo, "--cm-binary", stub)

    self.assertEqual(result.returncode, exit_codes.FAILED, result.stderr)
    [event] = self.verify_events(result)
    self.assertEqual(event["status"], "fail")
    self.assertEqual(event["message"], "4 passed, 3 warnings, 1 failed")
    self.assertIn("GOOGLE_CLOUD_PROJECT", result.stderr)

  def test_missing_summary_line_fails(self):
    """No `Results:` line is "result unknown", never "nothing wrong"."""
    report = os.path.join(self.tmp, "no_summary.txt")
    with open(_VERIFY_OK, encoding="utf-8") as src, open(
        report, "w", encoding="utf-8"
    ) as dst:
      dst.writelines(l for l in src if "Results:" not in l)
    stub = self.write_stub_cm(verify_output=report)

    result = self.run_init("--repo", self.repo, "--cm-binary", stub)

    self.assertEqual(result.returncode, exit_codes.FAILED, result.stderr)
    [event] = self.verify_events(result)
    self.assertEqual(event["status"], "fail")
    self.assertIn("no summary line", event["message"])

  def test_empty_output_fails(self):
    """No output at all fails the same way."""
    stub = self.write_stub_cm(verify_output="/dev/null")

    result = self.run_init("--repo", self.repo, "--cm-binary", stub)

    self.assertEqual(result.returncode, exit_codes.FAILED, result.stderr)
    self.assertEqual(
        [(e["name"], e["status"]) for e in self.verify_events(result)],
        [("cm_verify", "fail")],
    )

  def test_non_zero_exit_fails_even_with_a_clean_report(self):
    """As in the legacy pipeline, a non-zero exit is a failure."""
    stub = self.write_stub_cm(verify_output=_VERIFY_OK, verify_exit=2)

    result = self.run_init("--repo", self.repo, "--cm-binary", stub)

    self.assertEqual(result.returncode, exit_codes.FAILED, result.stderr)
    [event] = self.verify_events(result)
    self.assertEqual(event["status"], "fail")
    self.assertIn("exited 2", event["message"])

  def test_stdout_carries_only_check_events(self):
    """Every stdout line is a `check` event; cm's own report is not echoed."""
    stub = self.write_stub_cm(verify_output=_VERIFY_NO_PROJECT)

    result = self.run_init("--repo", self.repo, "--cm-binary", stub)

    for event in self.events(result):
      self.assertEqual(event["event"], "check")
    self.assertNotIn("Results:", result.stdout)
    self.assertNotIn("GOOGLE_CLOUD_PROJECT", result.stdout)


class TestVerifySummary(unittest.TestCase):
  """Reading the summary line of real `cm init --verify` captures."""

  def setUp(self):
    super().setUp()
    from cli.commands import init as init_cmd

    # pylint: disable=protected-access
    self.summary = init_cmd._verify_summary
    self.failed_count = init_cmd._failed_count

  def test_real_captures(self):
    """Counts as cm 0.9.0 prints them; a zero failed count is left out."""
    cases = {
        _VERIFY_OK: ("4 passed, 4 warnings", 0),
        _VERIFY_NO_PROJECT: ("4 passed, 3 warnings, 1 failed", 1),
        _VERIFY_NO_CONFIG: ("3 passed, 3 warnings, 2 failed", 2),
    }
    for path, (summary, failed) in cases.items():
      with self.subTest(capture=os.path.basename(path)):
        with open(path, encoding="utf-8") as handle:
          found = self.summary(handle.read())
        self.assertEqual(found, summary)
        self.assertEqual(self.failed_count(found), failed)

  def test_explicit_zero_failed_is_not_a_failure(self):
    """In case a later cm prints "0 failed" instead of leaving it out."""
    self.assertEqual(self.failed_count("8 passed, 0 warnings, 0 failed"), 0)

  def test_no_summary_line(self):
    for output in ("", None, "Error: unknown flag: --verify\n"):
      with self.subTest(output=output):
        self.assertIsNone(self.summary(output))


class TestInitRepoFlag(InitTestBase):
  """`--repo` must name a directory."""

  def test_repo_defaults_to_the_current_folder(self):
    """With no --repo, the folder `init` runs from is set up."""
    stub = self.write_stub_cm()

    result = self.run_init("--cm-binary", stub, cwd=self.repo)

    self.assertEqual(result.returncode, exit_codes.OK, result.stderr)
    real_repo = os.path.realpath(self.repo)
    self.assertEqual(
        self.read_config()["sandbox"]["mounts"]["target_dir"], real_repo
    )

  def test_repo_with_dot_dot_is_set_up(self):
    """`..` in --repo is removed, so the config read-back still matches."""
    stub = self.write_stub_cm()

    result = self.run_init(
        "--repo", os.path.join("repo", "..", "repo"),
        "--cm-binary", stub,
        cwd=self.tmp,
    )

    self.assertEqual(result.returncode, exit_codes.OK, result.stderr)
    self.assertEqual(
        self.read_config()["sandbox"]["mounts"]["target_dir"],
        os.path.realpath(self.repo),
    )

  def test_repo_that_does_not_exist_is_a_usage_error(self):
    """A bad --repo exits 2 before any check runs, so stdout is empty.

    Only `main`'s `cm --version` check has run by then.
    """
    stub = self.write_stub_cm()

    result = self.run_init(
        "--repo", os.path.join(self.tmp, "nope"), "--cm-binary", stub
    )

    self.assertEqual(result.returncode, exit_codes.USAGE, result.stderr)
    self.assertEqual(result.stdout, "")
    self.assertIn("not a directory", result.stderr)
    self.assertEqual(
        [c.split(" | ")[0] for c in self.cm_calls()], ["--version"]
    )

  def test_repo_that_is_a_file_is_a_usage_error(self):
    """A file is not a repository."""
    stub = self.write_stub_cm()
    a_file = os.path.join(self.tmp, "a_file")
    open(a_file, "w", encoding="utf-8").close()

    result = self.run_init("--repo", a_file, "--cm-binary", stub)

    self.assertEqual(result.returncode, exit_codes.USAGE, result.stderr)
    self.assertEqual(result.stdout, "")

  def test_repo_with_tilde_is_expanded(self):
    """`~` in --repo is expanded via expanduser().resolve()."""
    from cli.commands import init as init_cmd

    home_repo = os.path.join(self.home, "subrepo")
    os.mkdir(home_repo)
    with mock.patch.dict(os.environ, {"HOME": self.home}):
      cfg = init_cmd.config_from_args(argparse.Namespace(repo="~/subrepo"))
    self.assertEqual(cfg.repo, Path(home_repo).resolve())


class TestInitSilentMode(InitTestBase):
  """`init.run` with `emitter=None` (or omitted) for stderr-only auto-init."""

  def setUp(self):
    super().setUp()
    from cli.commands import init as init_cmd

    self.init_cmd = init_cmd

  def test_passing_run_on_fresh_home_with_emitter_none(self):
    """When emitter=None on a fresh HOME, init succeeds, logs checks, and writes zero bytes to stdout."""
    stub = self.write_stub_cm()
    adapter = CmAdapter(stub)
    self.assertEqual(adapter.version(), "0.9.0")
    repo_path = Path(self.repo).resolve()
    cfg = self.init_cmd.InitConfig(repo=repo_path)

    stdout_buf = io.StringIO()
    with (
        mock.patch.dict(
            os.environ,
            {"HOME": self.home, "PATH": self.empty_path},
            clear=False,
        ),
        contextlib.redirect_stdout(stdout_buf),
        self.assertLogs("cli.commands.init", level="INFO") as logs,
    ):
      rc = self.init_cmd.run(cfg, adapter, emitter=None)

    self.assertEqual(rc, exit_codes.OK)
    self.assertEqual(stdout_buf.getvalue(), "")
    self.assertTrue(os.path.isfile(self.config_path))
    settings = self.read_config()
    self.assertEqual(
        settings["sandbox"]["mounts"]["target_dir"], str(repo_path)
    )
    joined_logs = "\n".join(logs.output)
    self.assertIn("init check [cm_binary] pass:", joined_logs)
    self.assertIn("init check [cm_workspace] recovered:", joined_logs)
    self.assertIn("init check [cm_config] pass:", joined_logs)
    self.assertIn("init check [cm_verify] pass:", joined_logs)

  def test_passing_run_on_existing_config_with_emitter_omitted(self):
    """When emitter is omitted on an existing config, init keeps config, updates repo, logs checks, and writes nothing to stdout."""
    os.makedirs(os.path.dirname(self.config_path))
    with open(self.config_path, "w", encoding="utf-8") as handle:
      handle.write("team_id: customer-supplied\n")
    stub = self.write_stub_cm()
    adapter = CmAdapter(stub)
    self.assertEqual(adapter.version(), "0.9.0")
    repo_path = Path(self.repo).resolve()
    cfg = self.init_cmd.InitConfig(repo=repo_path)

    stdout_buf = io.StringIO()
    with (
        mock.patch.dict(
            os.environ,
            {"HOME": self.home, "PATH": self.empty_path},
            clear=False,
        ),
        contextlib.redirect_stdout(stdout_buf),
        self.assertLogs("cli.commands.init", level="INFO") as logs,
    ):
      rc = self.init_cmd.run(cfg, adapter)

    self.assertEqual(rc, exit_codes.OK)
    self.assertEqual(stdout_buf.getvalue(), "")
    self.assertEqual(self.init_calls(), [])
    settings = self.read_config()
    self.assertEqual(settings["team_id"], "customer-supplied")
    self.assertEqual(
        settings["sandbox"]["mounts"]["target_dir"], str(repo_path)
    )
    joined_logs = "\n".join(logs.output)
    self.assertIn("init check [cm_binary] pass:", joined_logs)
    self.assertIn("init check [cm_workspace] pass:", joined_logs)
    self.assertIn("init check [cm_config] pass:", joined_logs)
    self.assertIn("init check [cm_verify] pass:", joined_logs)

  def test_failing_run_with_emitter_none(self):
    """When emitter=None on a failing run, init returns FAILED, logs the failed check, and writes zero bytes to stdout."""
    stub = self.write_stub_cm(verify_output=_VERIFY_NO_PROJECT)
    adapter = CmAdapter(stub)
    self.assertEqual(adapter.version(), "0.9.0")
    repo_path = Path(self.repo).resolve()
    cfg = self.init_cmd.InitConfig(repo=repo_path)

    stdout_buf = io.StringIO()
    with (
        mock.patch.dict(
            os.environ,
            {"HOME": self.home, "PATH": self.empty_path},
            clear=False,
        ),
        contextlib.redirect_stdout(stdout_buf),
        self.assertLogs("cli.commands.init", level="INFO") as logs,
    ):
      rc = self.init_cmd.run(cfg, adapter, emitter=None)

    self.assertEqual(rc, exit_codes.FAILED)
    self.assertEqual(stdout_buf.getvalue(), "")
    joined_logs = "\n".join(logs.output)
    self.assertIn(
        "init check [cm_verify] fail: 4 passed, 3 warnings, 1 failed",
        joined_logs,
    )


class TestInitConfigValidate(unittest.TestCase):
  """`InitConfig.validate()`, called directly."""

  def setUp(self):
    super().setUp()
    from cli.commands import init as init_cmd

    self.init_cmd = init_cmd
    self.tmp = tempfile.mkdtemp(prefix="cm_runner_validate_")
    self.addCleanup(shutil.rmtree, self.tmp, True)

  def validate(self, path):
    """Returns validate()'s exit code for --repo `path`."""
    return self.init_cmd.InitConfig(repo=Path(path)).validate()

  def test_directory_is_ok(self):
    self.assertEqual(self.validate(self.tmp), exit_codes.OK)

  def test_missing_path_is_a_usage_error(self):
    with self.assertLogs(level="ERROR") as logs:
      code = self.validate(os.path.join(self.tmp, "nope"))

    self.assertEqual(code, exit_codes.USAGE)
    self.assertIn("not a directory", logs.output[0])

  def test_file_is_a_usage_error(self):
    a_file = os.path.join(self.tmp, "a_file")
    open(a_file, "w", encoding="utf-8").close()

    with self.assertLogs(level="ERROR"):
      code = self.validate(a_file)

    self.assertEqual(code, exit_codes.USAGE)


class TestInitImports(unittest.TestCase):
  """`init` must not drag in the legacy pipeline."""

  def test_init_does_not_import_the_legacy_pipeline(self):
    """Importing the command loads none of main, utils, runners, requests."""
    code = (
        "import sys, cli.commands.init\n"
        "bad = [m for m in ('main', 'utils', 'runners', 'requests')\n"
        "       if m in sys.modules]\n"
        "print(','.join(bad))\n"
    )
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("PYTHONPATH", None)

    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=_PKG_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )

    self.assertEqual(result.stdout.strip(), "", result.stdout)


if __name__ == "__main__":
  unittest.main()
