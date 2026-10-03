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

"""Tests for `cm-runner fix` (SPEC-FIX)."""

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Callable, Dict, List, Optional, Sequence, Tuple
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli import __main__ as cli_main
from cli import exit_codes
from cli.commands import fix
from cli.events import EventEmitter
from codemender.cm import CmAdapter, CmResult, TokenUsage

_PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_APP_PY = (
    "import os\n"
    "import sys\n"
    "\n"
    "\n"
    "def ping(host):\n"
    '    return os.system("ping -c 1 " + host)\n'
)
_FIXED_APP_PY = _APP_PY.replace(
    'os.system("ping -c 1 " + host)', 'os.system("ping -c 1 " + shlex.quote(host))'
).replace("import os\n", "import os\nimport shlex\n")


def _sarif(result_count: int = 1) -> str:
  """Returns a find-diff style SARIF document holding `result_count` results."""
  result = {
      "ruleId": "CWE-78",
      "level": "error",
      "message": {"text": "OS Command Injection in ping()"},
      "locations": [{
          "physicalLocation": {
              "artifactLocation": {"uri": "app.py"},
              "region": {"startLine": 6, "endLine": 6},
          }
      }],
  }
  return json.dumps({
      "version": "2.1.0",
      "runs": [{
          "tool": {"driver": {"name": "CodeMender", "version": "dev"}},
          "results": [result] * result_count,
      }],
  })


def _ok(args: Sequence[str], stdout: str = "", stderr: str = "") -> CmResult:
  return CmResult(
      args=("/fake/bin/cm", *args),
      exit_code=0,
      stdout=stdout,
      stderr=stderr,
      tokens=TokenUsage(),
  )


def _failed(args: Sequence[str], stderr: str, exit_code: int = 1) -> CmResult:
  return CmResult(
      args=("/fake/bin/cm", *args),
      exit_code=exit_code,
      stdout="",
      stderr=stderr,
      tokens=TokenUsage(),
  )


def _apply_default_fix(repo: str) -> None:
  """What `cm fix` does to the repository in the tests, unless told otherwise."""
  Path(repo, "app.py").write_text(_FIXED_APP_PY, encoding="utf-8")
  Path(repo, ".cm_project").write_text("{}", encoding="utf-8")


class FakeCm(CmAdapter):
  """In-process `cm` with its own findings database.

  `report --format json` lists the database, `report import` adds findings,
  and `fix` edits the repository through `on_fix` and sets the finding's
  status. Every call is recorded. Any call can be overridden with a fixed
  result through `overrides`, keyed by the first two arguments.
  """

  def __init__(
      self,
      existing: Optional[Dict[str, str]] = None,
      import_adds: int = 1,
      fix_status: str = "FIXED",
      on_fix: Optional[Callable[[str], None]] = _apply_default_fix,
      overrides: Optional[Dict[Tuple[str, ...], CmResult]] = None,
  ):
    super().__init__(binary="/fake/bin/cm")
    self._version = "0.11.0"
    self.findings: Dict[str, str] = dict(existing or {})
    self.import_adds = import_adds
    self.fix_status = fix_status
    self.on_fix = on_fix
    self.overrides = overrides or {}
    self.calls: List[Dict[str, object]] = []
    # (path, whether it existed, its contents) for each `report import`.
    self.imported: List[Tuple[str, bool, str]] = []
    self._next_id = 1

  def run(
      self,
      args: Sequence[str],
      cwd: Optional[str] = None,
      env: Optional[Dict[str, str]] = None,
      timeout_sec: Optional[float] = None,
  ) -> CmResult:
    args = list(args)
    self.calls.append(
        {"args": args, "cwd": cwd, "env": env, "timeout_sec": timeout_sec}
    )
    key = tuple(args[:2])
    if key in self.overrides:
      return self.overrides[key]

    if args == ["report", "--format", "json"]:
      listing = [
          {"finding_id": fid, "status": status, "title": "CWE-78"}
          for fid, status in self.findings.items()
      ]
      return _ok(args, json.dumps(listing, indent=2), "[INFO] Session log: x\n")

    if args[:2] == ["report", "import"]:
      path = args[args.index("-f") + 1]
      exists = os.path.isfile(path)
      contents = Path(path).read_text(encoding="utf-8") if exists else ""
      self.imported.append((path, exists, contents))
      for _ in range(self.import_adds):
        self.findings[f"00000000-0000-0000-0000-{self._next_id:012d}"] = "OPEN"
        self._next_id += 1
      return _ok(args, f"Successfully imported {self.import_adds} findings.\n")

    if args[:1] == ["fix"]:
      finding_id = args[-1]
      if self.on_fix is not None:
        self.on_fix(cwd)
      self.findings[finding_id] = self.fix_status
      return _ok(args, "✨ Patch generated successfully!\n", "sandbox: denied\n")

    raise AssertionError(f"Unexpected cm call: {args!r}")

  def call_args(self) -> List[List[str]]:
    return [call["args"] for call in self.calls]


def _git(repo: str, *args: str) -> str:
  return subprocess.run(
      ["git", *args],
      cwd=repo,
      check=True,
      capture_output=True,
      text=True,
      timeout=30,
  ).stdout


class FixTestBase(unittest.TestCase):
  """A temporary folder holding a committed Git repository and a finding file."""

  def setUp(self):
    super().setUp()
    self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="cm_runner_fix_"))
    self.addCleanup(shutil.rmtree, self.tmp, True)
    self.repo = os.path.join(self.tmp, "repo")
    os.makedirs(self.repo)
    _git(self.repo, "init", "-q")
    _git(self.repo, "config", "user.name", "Test User")
    _git(self.repo, "config", "user.email", "test@example.com")
    Path(self.repo, "app.py").write_text(_APP_PY, encoding="utf-8")
    _git(self.repo, "add", "app.py")
    _git(self.repo, "commit", "-q", "-m", "init")

    self.finding = os.path.join(self.tmp, "cwe-78-app-py.sarif")
    Path(self.finding).write_text(_sarif(), encoding="utf-8")

  def cfg(self, **overrides) -> fix.FixConfig:
    values = {"finding": Path(self.finding), "repo": Path(self.repo), "out": None}
    values.update(overrides)
    return fix.FixConfig(**values)

  def execute(
      self, cfg: fix.FixConfig, adapter: CmAdapter, stdin: str = ""
  ) -> Tuple[int, str, str]:
    """Runs `fix.run` with the stream setup `cli/__main__.py` uses."""
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(
        stderr
    ), mock.patch.object(sys, "stdin", io.StringIO(stdin)):
      cli_main.configure_logging("debug")
      rc = fix.run(cfg, adapter, EventEmitter(stream=stdout))
    cli_main.configure_logging("info")
    return rc, stdout.getvalue(), stderr.getvalue()


class TestConfigFromArgs(FixTestBase):
  """REQ-0001: flags and path normalisation."""

  def test_defaults_repo_to_cwd_and_out_to_none(self):
    cfg = fix.config_from_args(
        argparse.Namespace(finding="f.sarif", repo=".", out=None)
    )
    self.assertEqual(cfg.repo, Path.cwd().resolve())
    self.assertEqual(cfg.finding, (Path.cwd() / "f.sarif").resolve())
    self.assertIsNone(cfg.out)

  def test_dash_means_stdin(self):
    cfg = fix.config_from_args(
        argparse.Namespace(finding="-", repo=".", out=None)
    )
    self.assertIsNone(cfg.finding)
    self.assertEqual(cfg.diff_file_name, "finding.diff")

  def test_expands_home_and_removes_dot_dot(self):
    with mock.patch.dict(os.environ, {"HOME": self.tmp}):
      cfg = fix.config_from_args(
          argparse.Namespace(
              finding="~/cwe-78-app-py.sarif", repo="~/repo/../repo", out="~/out"
          )
      )
    self.assertEqual(cfg.finding, Path(self.finding))
    self.assertEqual(cfg.repo, Path(self.repo))
    self.assertEqual(cfg.out, Path(self.tmp, "out"))
    self.assertEqual(cfg.diff_file_name, "cwe-78-app-py.diff")

  def test_direct_init_normalises_paths_and_dash(self):
    with mock.patch.dict(os.environ, {"HOME": self.tmp}):
      cfg = fix.FixConfig(
          finding="~/cwe-78-app-py.sarif", repo="~/repo/../repo", out="~/out"
      )
      stdin_cfg = fix.FixConfig(finding="-", repo=".")
    self.assertEqual(cfg.finding, Path(self.finding))
    self.assertEqual(cfg.repo, Path(self.repo))
    self.assertEqual(cfg.out, Path(self.tmp, "out"))
    self.assertIsNone(stdin_cfg.finding)
    self.assertEqual(stdin_cfg.repo, Path.cwd().resolve())

  def test_parser_registers_exactly_three_command_flags(self):
    args = cli_main.build_parser().parse_args(
        ["fix", "--finding", "f.sarif", "--repo", "r", "--out", "o"]
    )
    self.assertEqual((args.finding, args.repo, args.out), ("f.sarif", "r", "o"))
    for flag in ("--model", "--context", "--retries"):
      with self.subTest(flag=flag), contextlib.redirect_stderr(io.StringIO()):
        with self.assertRaises(SystemExit):
          cli_main.build_parser().parse_args(
              ["fix", "--finding", "f.sarif", flag, "x"]
          )


class TestInputValidation(FixTestBase):
  """REQ-0002: exit 2, nothing on stdout, nothing run."""

  def assert_usage_error(self, cfg, stdin="", expect_in_log=""):
    adapter = FakeCm()
    rc, stdout, stderr = self.execute(cfg, adapter, stdin)
    self.assertEqual(rc, exit_codes.USAGE, stderr)
    self.assertEqual(stdout, "")
    self.assertEqual(adapter.calls, [])
    self.assertIn(expect_in_log, stderr)
    return stderr

  def test_repo_not_a_directory(self):
    self.assert_usage_error(
        self.cfg(repo=Path(self.tmp, "missing")), expect_in_log="--repo"
    )

  def test_finding_not_a_file(self):
    self.assert_usage_error(
        self.cfg(finding=Path(self.tmp, "missing.sarif")),
        expect_in_log="--finding",
    )

  def test_out_is_an_existing_file(self):
    out = Path(self.tmp, "out")
    out.write_text("x", encoding="utf-8")
    self.assert_usage_error(self.cfg(out=out), expect_in_log="--out")

  def test_not_json(self):
    Path(self.finding).write_text("not json", encoding="utf-8")
    self.assert_usage_error(self.cfg(), expect_in_log="not valid JSON")

  def test_json_without_runs(self):
    Path(self.finding).write_text('{"findings": []}', encoding="utf-8")
    self.assert_usage_error(self.cfg(), expect_in_log="no 'runs' list")

  def test_two_results_rejected_with_split_hint(self):
    Path(self.finding).write_text(_sarif(2), encoding="utf-8")
    stderr = self.assert_usage_error(self.cfg(), expect_in_log="holds 2 results")
    self.assertIn("one file per finding", stderr)

  def test_zero_results_rejected(self):
    Path(self.finding).write_text(_sarif(0), encoding="utf-8")
    self.assert_usage_error(self.cfg(), expect_in_log="holds 0 results")

  def test_results_counted_across_runs(self):
    doc = json.loads(_sarif(1))
    doc["runs"].append(doc["runs"][0])
    Path(self.finding).write_text(json.dumps(doc), encoding="utf-8")
    self.assert_usage_error(self.cfg(), expect_in_log="holds 2 results")

  def test_empty_stdin(self):
    self.assert_usage_error(
        self.cfg(finding=None), stdin="", expect_in_log="stdin"
    )


class TestPreflight(FixTestBase):
  """REQ-0003: exit 3 before `cm` runs; uncommitted work is left alone."""

  def test_not_a_git_repository(self):
    plain = Path(self.tmp, "plain")
    plain.mkdir()
    adapter = FakeCm()
    rc, stdout, stderr = self.execute(self.cfg(repo=plain), adapter)
    self.assertEqual(rc, exit_codes.FAILED, stderr)
    self.assertEqual(stdout, "")
    self.assertEqual(adapter.calls, [])
    self.assertIn("not inside a Git working tree", stderr)

  def test_refuses_uncommitted_work_and_leaves_it_alone(self):
    Path(self.repo, "app.py").write_text(_APP_PY + "# my edit\n", encoding="utf-8")
    Path(self.repo, "notes.txt").write_text("keep me\n", encoding="utf-8")
    adapter = FakeCm()

    rc, stdout, stderr = self.execute(self.cfg(), adapter)

    self.assertEqual(rc, exit_codes.FAILED, stderr)
    self.assertEqual(stdout, "")
    self.assertEqual(adapter.calls, [])
    self.assertIn("app.py", stderr)
    self.assertIn("notes.txt", stderr)
    self.assertIn("# my edit", Path(self.repo, "app.py").read_text("utf-8"))
    self.assertTrue(Path(self.repo, "notes.txt").exists())

  def test_refuses_staged_work(self):
    Path(self.repo, "staged.py").write_text("x = 1\n", encoding="utf-8")
    _git(self.repo, "add", "staged.py")
    adapter = FakeCm()
    rc, _, stderr = self.execute(self.cfg(), adapter)
    self.assertEqual(rc, exit_codes.FAILED, stderr)
    self.assertIn("staged.py", stderr)
    self.assertEqual(adapter.calls, [])

  def test_cm_own_files_do_not_block(self):
    Path(self.repo, ".cm_project").write_text("{}", encoding="utf-8")
    Path(self.repo, ".exploit").mkdir()
    Path(self.repo, ".exploit", "poc.sh").write_text("#!/bin/sh\n", "utf-8")
    rc, stdout, stderr = self.execute(self.cfg(), FakeCm())
    self.assertEqual(rc, exit_codes.OK, stderr)
    self.assertIn("diff --git a/app.py b/app.py", stdout)

  def test_ignored_files_do_not_block(self):
    Path(self.repo, ".gitignore").write_text("*.log\n", encoding="utf-8")
    _git(self.repo, "add", ".gitignore")
    _git(self.repo, "commit", "-q", "-m", "ignore logs")
    Path(self.repo, "build.log").write_text("noise\n", encoding="utf-8")
    rc, stdout, stderr = self.execute(self.cfg(), FakeCm())
    self.assertEqual(rc, exit_codes.OK, stderr)
    self.assertNotIn("build.log", stdout)


class TestSuccessfulFix(FixTestBase):
  """REQ-0004 to REQ-0007 on the happy path."""

  def test_cm_calls_in_order_with_repo_cwd_and_no_env(self):
    adapter = FakeCm(existing={"old-finding": "OPEN"})

    rc, _, stderr = self.execute(self.cfg(), adapter)

    self.assertEqual(rc, exit_codes.OK, stderr)
    new_id = "00000000-0000-0000-0000-000000000001"
    self.assertEqual(
        adapter.call_args(),
        [
            ["report", "--format", "json"],
            ["report", "import", "-f", self.finding, "-p", self.repo],
            ["report", "--format", "json"],
            ["fix", "-y", "--bypass-warning", new_id],
            ["report", "--format", "json"],
        ],
    )
    for call in adapter.calls:
      self.assertIsNone(call["env"])
    self.assertEqual(adapter.calls[3]["cwd"], self.repo)
    self.assertEqual(adapter.calls[3]["timeout_sec"], 1800.0)
    self.assertEqual(adapter.calls[0]["timeout_sec"], 60.0)
    self.assertEqual(adapter.findings["old-finding"], "OPEN")

  def test_stdout_is_exactly_the_git_patch_without_cm_files(self):
    rc, stdout, stderr = self.execute(self.cfg(), FakeCm())

    self.assertEqual(rc, exit_codes.OK, stderr)
    self.assertTrue(stdout.startswith("diff --git a/app.py b/app.py\n"), stdout)
    self.assertIn("+import shlex\n", stdout)
    self.assertNotIn(".cm_project", stdout)
    # Progress text from `cm fix` goes to stderr, never stdout.
    self.assertNotIn("Patch generated", stdout)
    self.assertIn("Patch generated", stderr)

  def test_patch_applies_to_a_clean_checkout(self):
    rc, stdout, stderr = self.execute(self.cfg(), FakeCm())
    self.assertEqual(rc, exit_codes.OK, stderr)

    clone = os.path.join(self.tmp, "clone")
    _git(self.tmp, "clone", "-q", self.repo, clone)
    patch_file = Path(self.tmp, "fix.diff")
    patch_file.write_text(stdout, encoding="utf-8")
    _git(clone, "apply", str(patch_file))
    self.assertEqual(Path(clone, "app.py").read_text("utf-8"), _FIXED_APP_PY)

  def test_patch_includes_a_file_the_fix_created(self):
    def add_module(repo):
      _apply_default_fix(repo)
      Path(repo, "sanitize.py").write_text("def clean(s):\n  return s\n", "utf-8")

    rc, stdout, stderr = self.execute(self.cfg(), FakeCm(on_fix=add_module))

    self.assertEqual(rc, exit_codes.OK, stderr)
    self.assertIn("diff --git a/app.py b/app.py", stdout)
    self.assertIn("diff --git a/sanitize.py b/sanitize.py", stdout)
    self.assertIn("new file mode", stdout)

  def test_patch_left_applied_and_not_committed(self):
    head_before = _git(self.repo, "rev-parse", "HEAD")
    rc, _, stderr = self.execute(self.cfg(), FakeCm())
    self.assertEqual(rc, exit_codes.OK, stderr)
    self.assertEqual(_git(self.repo, "rev-parse", "HEAD"), head_before)
    self.assertEqual(Path(self.repo, "app.py").read_text("utf-8"), _FIXED_APP_PY)
    self.assertTrue(Path(self.repo, ".cm_project").exists())

  def test_out_file_named_after_finding_holds_stdout_bytes(self):
    out = Path(self.tmp, "patches", "nested")
    rc, stdout, stderr = self.execute(self.cfg(out=out), FakeCm())
    self.assertEqual(rc, exit_codes.OK, stderr)
    self.assertEqual(
        (out / "cwe-78-app-py.diff").read_bytes(), stdout.encode("utf-8")
    )
    self.assertEqual(os.listdir(out), ["cwe-78-app-py.diff"])

  def test_no_out_writes_no_files_outside_the_repo(self):
    before = sorted(os.listdir(self.tmp))
    rc, _, stderr = self.execute(self.cfg(), FakeCm())
    self.assertEqual(rc, exit_codes.OK, stderr)
    self.assertEqual(sorted(os.listdir(self.tmp)), before)

  def test_finding_from_stdin_goes_through_a_temp_file_outside_the_repo(self):
    adapter = FakeCm()
    out = Path(self.tmp, "out")

    rc, stdout, stderr = self.execute(
        self.cfg(finding=None, out=out), adapter, stdin=_sarif()
    )

    self.assertEqual(rc, exit_codes.OK, stderr)
    self.assertIn("diff --git a/app.py b/app.py", stdout)
    [(path, existed, contents)] = adapter.imported
    self.assertTrue(existed)
    self.assertEqual(contents, _sarif())
    self.assertFalse(Path(path).resolve().is_relative_to(Path(self.repo)))
    self.assertFalse(os.path.exists(path), "temporary finding file not deleted")
    self.assertTrue((out / "finding.diff").is_file())

  def test_stdin_temp_file_inside_repo_is_refused(self):
    adapter = FakeCm()
    with mock.patch.object(tempfile, "tempdir", self.repo):
      rc, stdout, stderr = self.execute(
          self.cfg(finding=None), adapter, stdin=_sarif()
      )
    self.assertEqual(rc, exit_codes.FAILED, stderr)
    self.assertEqual(stdout, "")
    self.assertIn("TMPDIR", stderr)
    self.assertNotIn(["report", "import"], [a[:2] for a in adapter.call_args()])
    self.assertEqual(
        [p for p in os.listdir(self.repo) if p.startswith("cm-runner-")], []
    )


class TestFailures(FixTestBase):
  """REQ-0004 and REQ-0007: every failure exits 3 with nothing on stdout."""

  def assert_failed(self, adapter, cfg=None, expect_in_log=""):
    rc, stdout, stderr = self.execute(cfg or self.cfg(), adapter)
    self.assertEqual(rc, exit_codes.FAILED, stderr)
    self.assertEqual(stdout, "")
    self.assertIn(expect_in_log, stderr)
    return stderr

  def test_cm_not_initialised(self):
    args = ["report", "--format", "json"]
    adapter = FakeCm(
        overrides={
            ("report", "--format"): _failed(
                args, "Error: CodeMender has not been initialized.\n"
            )
        }
    )
    self.assert_failed(adapter, expect_in_log="has not been initialized")
    self.assertEqual(adapter.call_args(), [args])

  def test_import_fails(self):
    adapter = FakeCm(
        overrides={
            ("report", "import"): _failed(
                ["report", "import"], "Error: no valid findings to import\n"
            )
        }
    )
    self.assert_failed(adapter, expect_in_log="no valid findings to import")
    self.assertNotIn("fix", [a[0] for a in adapter.call_args()])

  def test_import_adds_no_finding(self):
    adapter = FakeCm(import_adds=0)
    self.assert_failed(adapter, expect_in_log="added 0")
    self.assertNotIn("fix", [a[0] for a in adapter.call_args()])

  def test_import_adds_two_findings(self):
    adapter = FakeCm(import_adds=2)
    self.assert_failed(adapter, expect_in_log="added 2")
    self.assertNotIn("fix", [a[0] for a in adapter.call_args()])

  def test_report_prints_something_other_than_a_list(self):
    args = ["report", "--format", "json"]
    adapter = FakeCm(
        overrides={("report", "--format"): _ok(args, '{"findings": []}')}
    )
    self.assert_failed(adapter, expect_in_log="not a list of findings")

  def test_fix_finishes_without_fixing(self):
    adapter = FakeCm(fix_status="OPEN", on_fix=None)
    stderr = self.assert_failed(adapter, expect_in_log="is OPEN, not FIXED")
    self.assertIn("Patch generated", stderr)  # cm's output is still logged.

  def test_fix_times_out_and_status_is_not_read(self):
    args = ["fix"]
    timeout = CmResult(
        args=("/fake/bin/cm", *args),
        exit_code=None,
        stdout="partial progress\n",
        stderr="",
        tokens=TokenUsage(),
        error="timed out after 1800.0 s",
    )
    adapter = FakeCm(overrides={("fix", "-y"): timeout})
    self.assert_failed(adapter, expect_in_log="timed out after 1800.0 s")
    self.assertEqual(adapter.call_args()[-1][0], "fix")

  def test_fix_exits_non_zero(self):
    adapter = FakeCm(overrides={("fix", "-y"): _failed(["fix"], "boom\n")})
    self.assert_failed(adapter, expect_in_log="boom")

  def test_fixed_but_no_changes(self):
    adapter = FakeCm(on_fix=lambda repo: Path(repo, ".cm_project").write_text("{}"))
    self.assert_failed(adapter, expect_in_log="no changes")

  def test_out_write_failure(self):
    blocker = Path(self.tmp, "blocker")
    blocker.write_text("a file, not a folder", encoding="utf-8")
    self.assert_failed(
        FakeCm(), cfg=self.cfg(out=blocker / "out"), expect_in_log="Could not write"
    )

  def test_only_one_fix_attempt(self):
    adapter = FakeCm(fix_status="OPEN", on_fix=None)
    self.assert_failed(adapter)
    self.assertEqual([a[0] for a in adapter.call_args()].count("fix"), 1)


class TestWritePatch(unittest.TestCase):
  """REQ-0005: the patch reaches stdout byte for byte."""

  def test_binary_stream_gets_exact_bytes(self):
    patch = b"diff --git a/w.txt b/w.txt\r\n-a\r\n+b\r\n\xff\n"
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="utf-8")
    stream.write("")  # Text written earlier must not be reordered.
    fix._write_patch(stream, patch)
    self.assertEqual(raw.getvalue(), patch)


class TestFixThroughTheCli(unittest.TestCase):
  """The whole command, run as `python -m cli fix` against a fake `cm` binary."""

  _FAKE_CM = r'''
import json, os, sys
state = os.environ["FAKE_CM_STATE"]
def load():
    if not os.path.exists(state):
        return []
    with open(state) as handle:
        return json.load(handle)
def save(findings):
    with open(state, "w") as handle:
        json.dump(findings, handle)
args = sys.argv[1:]
if args == ["--version"]:
    print("cm version 0.11.0")
elif args == ["init"]:
    cfg_dir = os.path.join(os.environ["HOME"], ".codemender")
    os.makedirs(cfg_dir, exist_ok=True)
    with open(os.path.join(cfg_dir, "config.yaml"), "w") as handle:
        handle.write("stock_default: true\n")
elif args == ["init", "--verify"]:
    print("  Results: 4 passed, 4 warnings")
elif args == ["report", "--format", "json"]:
    print("[INFO] Session log: x", file=sys.stderr)
    print(json.dumps(load(), indent=2))
elif args[:2] == ["report", "import"]:
    findings = load()
    findings.append({"finding_id": "id-%d" % len(findings), "status": "OPEN"})
    save(findings)
    print("Successfully imported 1 findings.")
elif args[:1] == ["fix"]:
    with open("windows.txt", "wb") as handle:
        handle.write(b"line one\r\nline two fixed\r\n")
    with open(".cm_project", "w") as handle:
        handle.write("{}")
    print("progress banner that must not reach stdout")
    findings = load()
    for finding in findings:
        if finding["finding_id"] == args[-1]:
            finding["status"] = "FIXED"
    save(findings)
else:
    sys.exit(1)
'''

  def setUp(self):
    super().setUp()
    self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="cm_runner_fix_cli_"))
    self.addCleanup(shutil.rmtree, self.tmp, True)
    self.home = os.path.join(self.tmp, "home")
    os.makedirs(self.home, exist_ok=True)
    self.cm = os.path.join(self.tmp, "cm")
    with open(self.cm, "w", encoding="utf-8") as handle:
      handle.write(f"#!{sys.executable}\n{self._FAKE_CM}")
    os.chmod(self.cm, 0o755)

    self.repo = os.path.join(self.tmp, "repo")
    os.makedirs(self.repo)
    _git(self.repo, "init", "-q")
    _git(self.repo, "config", "user.name", "Test User")
    _git(self.repo, "config", "user.email", "test@example.com")
    _git(self.repo, "config", "core.autocrlf", "false")
    Path(self.repo, "windows.txt").write_bytes(b"line one\r\nline two\r\n")
    _git(self.repo, "add", "windows.txt")
    _git(self.repo, "commit", "-q", "-m", "init")
    self.finding = os.path.join(self.tmp, "f.sarif")
    Path(self.finding).write_text(_sarif(), encoding="utf-8")

  def run_fix(self, *args, stdin=None):
    env = dict(os.environ)
    env["HOME"] = self.home
    env["FAKE_CM_STATE"] = os.path.join(self.tmp, "state.json")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("PYTHONPATH", None)
    return subprocess.run(
        [sys.executable, "-m", "cli", "fix", "--cm-binary", self.cm, *args],
        cwd=_PKG_DIR,
        env=env,
        input=stdin,
        capture_output=True,
        timeout=60,
        check=False,
    )

  def test_stdout_is_a_patch_that_applies_byte_for_byte(self):
    result = self.run_fix("--repo", self.repo, "--finding", self.finding)

    self.assertEqual(result.returncode, exit_codes.OK, result.stderr.decode())
    self.assertTrue(result.stdout.startswith(b"diff --git a/windows.txt"))
    self.assertIn(b"+line two fixed\r\n", result.stdout)
    self.assertNotIn(b"progress banner", result.stdout)
    self.assertIn(b"progress banner", result.stderr)

    clone = os.path.join(self.tmp, "clone")
    _git(self.tmp, "clone", "-q", "-c", "core.autocrlf=false", self.repo, clone)
    Path(self.tmp, "fix.diff").write_bytes(result.stdout)
    _git(clone, "apply", os.path.join(self.tmp, "fix.diff"))
    self.assertEqual(
        Path(clone, "windows.txt").read_bytes(),
        Path(self.repo, "windows.txt").read_bytes(),
    )

  def test_finding_from_stdin(self):
    result = self.run_fix(
        "--repo", self.repo, "--finding", "-", stdin=_sarif().encode()
    )
    self.assertEqual(result.returncode, exit_codes.OK, result.stderr.decode())
    self.assertIn(b"+line two fixed\r\n", result.stdout)

  def test_bad_finding_exits_two_with_empty_stdout(self):
    Path(self.finding).write_text(_sarif(2), encoding="utf-8")
    result = self.run_fix("--repo", self.repo, "--finding", self.finding)
    self.assertEqual(result.returncode, exit_codes.USAGE)
    self.assertEqual(result.stdout, b"")

  def test_dirty_repo_exits_three_with_empty_stdout(self):
    Path(self.repo, "notes.txt").write_text("mine\n", encoding="utf-8")
    result = self.run_fix("--repo", self.repo, "--finding", self.finding)
    self.assertEqual(result.returncode, exit_codes.FAILED)
    self.assertEqual(result.stdout, b"")
    self.assertIn(b"notes.txt", result.stderr)


if __name__ == "__main__":
  unittest.main()
