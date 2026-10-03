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

"""Hermetic unit tests for `cm-runner find-diff` (`cli/commands/find_diff.py`)."""

import argparse
import contextlib
from io import StringIO
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional, Sequence, Tuple
import unittest

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli import __main__ as cli_main
from cli import exit_codes
from cli.commands import find_diff
from cli.events import EventEmitter
from codemender.cm import CmAdapter, CmResult, TokenUsage
from tests.test_cli import CLIContractTestBase, _write_stub_cm

_PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_PRETTY_SARIF_TWO_FINDINGS = json.dumps(
    {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "CodeMender", "version": "0.9.0"}},
                "results": [
                    {
                        "ruleId": "CWE-78",
                        "level": "error",
                        "message": {
                            "text": (
                                "OS Command Injection in archive extractor: "
                                "Untrusted filename user_archive is passed "
                                "directly to os.system('/bin/sh -c')."
                            )
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "src/archive/unpack.py"
                                    },
                                    "region": {"startLine": 18, "endLine": 19},
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "CWE-89",
                        "level": "error",
                        "message": {
                            "text": (
                                "SQL Injection in user lookup query: "
                                "User-supplied user_id is interpolated "
                                "directly into the SQL query string."
                            )
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "src/db/users.py"
                                    },
                                    "region": {"startLine": 42, "endLine": 45},
                                }
                            }
                        ],
                    },
                ],
            }
        ],
    },
    indent=2,
)

_PRETTY_SARIF_ZERO_FINDINGS = json.dumps(
    {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "CodeMender", "version": "0.9.0"}},
                "results": [],
            }
        ],
    },
    indent=2,
)

_SAMPLE_MARKDOWN_REPORT = (
    "# CodeMender Security Report\n\n"
    "## Findings\n\n"
    "- **CWE-78**: OS Command Injection in `src/archive/unpack.py`\n"
    "- **CWE-89**: SQL Injection in `src/db/users.py`\n"
)


class RecordingCmAdapter(CmAdapter):
  """In-process double for `CmAdapter` that records every `run()` call."""

  def __init__(self, responses: Optional[Dict[Tuple[str, ...], CmResult]] = None):
    super().__init__(binary="/fake/bin/cm")
    self._version = "0.9.0"
    self.calls: List[Dict[str, object]] = []
    self.responses = responses or {}

  def run(
      self,
      args: Sequence[str],
      cwd: Optional[str] = None,
      env: Optional[Dict[str, str]] = None,
      timeout_sec: Optional[float] = None,
  ) -> CmResult:
    key = tuple(args)
    self.calls.append(
        {
            "args": list(args),
            "cwd": cwd,
            "env": env,
            "timeout_sec": timeout_sec,
        }
    )
    if key in self.responses:
      return self.responses[key]
    if args and args[0] == "find":
      return CmResult(
          args=(self.binary, *args),
          exit_code=0,
          stdout="Impact-Aware PR Delta Scan: 2 files in scope\n",
          stderr="Session: 11111111-2222-3333-4444-555555555555\n",
          tokens=TokenUsage(1000, 200, 1200),
      )
    if list(args) == ["report", "--format", "sarif"]:
      return CmResult(
          args=(self.binary, *args),
          exit_code=0,
          stdout=_PRETTY_SARIF_TWO_FINDINGS + "\n",
          stderr="Loaded session 11111111-2222-3333-4444-555555555555\n",
          tokens=TokenUsage(),
      )
    if list(args) == ["report", "--format", "md"]:
      return CmResult(
          args=(self.binary, *args),
          exit_code=0,
          stdout=_SAMPLE_MARKDOWN_REPORT,
          stderr="Rendered markdown report\n",
          tokens=TokenUsage(),
      )
    raise AssertionError(f"Unexpected CmAdapter.run call: {args!r}")


class FindDiffTestBase(unittest.TestCase):
  """Sets up an isolated temp workspace with a real Git repository."""

  def setUp(self):
    super().setUp()
    self.tmp = tempfile.mkdtemp(prefix="cm_runner_find_diff_")
    self.addCleanup(shutil.rmtree, self.tmp, True)

    self.home = os.path.join(self.tmp, "home")
    self.repo = os.path.join(self.tmp, "repo")
    os.makedirs(self.home, exist_ok=True)
    os.makedirs(self.repo, exist_ok=True)

    self._init_git_repo(self.repo)

  def _init_git_repo(self, repo_dir: str) -> None:
    """Initializes a Git repository with an initial commit and `origin/main` ref."""
    subprocess.run(
        ["git", "init"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        timeout=30,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        timeout=30,
    )
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        timeout=30,
    )
    readme = os.path.join(repo_dir, "README.md")
    with open(readme, "w", encoding="utf-8") as handle:
      handle.write("# Sample Repo\n")
    subprocess.run(
        ["git", "add", "README.md"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        timeout=30,
    )
    subprocess.run(
        ["git", "commit", "-m", "Initial commit"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        timeout=30,
    )
    # Create simulated remote-tracking ref `refs/remotes/origin/main`
    subprocess.run(
        ["git", "update-ref", "refs/remotes/origin/main", "HEAD"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        timeout=30,
    )

  def execute_find_diff(
      self,
      cfg: find_diff.FindDiffConfig,
      adapter: CmAdapter,
      log_level: str = "info",
  ) -> Tuple[int, str, str]:
    """Runs `find_diff.run` with stdout/stderr isolation matching `cli/__main__.py`."""
    stdout_buf = StringIO()
    stderr_buf = StringIO()
    emitter = EventEmitter(stream=stdout_buf)
    with contextlib.redirect_stderr(stderr_buf), contextlib.redirect_stdout(
        stderr_buf
    ):
      cli_main.configure_logging(log_level)
      rc = find_diff.run(cfg, adapter, emitter)
    # Restore default stderr handler after capture so logging doesn't hold closed StringIO
    cli_main.configure_logging("info")
    return rc, stdout_buf.getvalue(), stderr_buf.getvalue()


class TestFindDiffConfigFromArgs(FindDiffTestBase):
  """Tests for `config_from_args` (`REQ-0001`)."""

  def test_defaults_repo_to_cwd_base_to_head_and_out_to_none(self):
    args = argparse.Namespace()
    cfg = find_diff.config_from_args(args)

    self.assertEqual(cfg.repo, Path(".").expanduser().resolve())
    self.assertEqual(cfg.base, "HEAD")
    self.assertIsNone(cfg.out)

  def test_strips_surrounding_whitespace_on_base(self):
    args = argparse.Namespace(repo=self.repo, base="  origin/main \n", out=None)
    cfg = find_diff.config_from_args(args)
    self.assertEqual(cfg.base, "origin/main")

  def test_tilde_expansion_on_repo_and_out(self):
    old_home = os.environ.get("HOME")
    os.environ["HOME"] = self.home
    try:
      args = argparse.Namespace(
          repo="~/my_project",
          base="origin/main",
          out="~/my_artifacts",
      )
      cfg = find_diff.config_from_args(args)
    finally:
      if old_home is None:
        os.environ.pop("HOME", None)
      else:
        os.environ["HOME"] = old_home

    self.assertEqual(cfg.repo, (Path(self.home) / "my_project").resolve())
    self.assertEqual(cfg.base, "origin/main")
    self.assertEqual(cfg.out, (Path(self.home) / "my_artifacts").resolve())

  def test_dot_dot_segments_are_resolved(self):
    rel_repo = os.path.join(self.tmp, "repo", "..", "repo")
    rel_out = os.path.join(self.tmp, "repo", "..", "out_dir")
    args = argparse.Namespace(repo=rel_repo, base="HEAD", out=rel_out)

    cfg = find_diff.config_from_args(args)

    self.assertEqual(cfg.repo, Path(self.repo).resolve())
    self.assertEqual(cfg.out, (Path(self.tmp) / "out_dir").resolve())


class TestFindDiffValidate(FindDiffTestBase):
  """Tests for `FindDiffConfig.validate()` (`REQ-0002`, Exit Code 2)."""

  def test_valid_config_returns_ok(self):
    cfg = find_diff.FindDiffConfig(
        repo=Path(self.repo),
        base="origin/main",
        out=Path(self.tmp) / "artifacts",
    )
    self.assertEqual(cfg.validate(), exit_codes.OK)

  def test_nonexistent_repo_exits_usage_with_empty_stdout(self):
    adapter = RecordingCmAdapter()
    cfg = find_diff.FindDiffConfig(repo=Path(self.tmp) / "does_not_exist")

    rc, stdout, stderr = self.execute_find_diff(cfg, adapter)

    self.assertEqual(rc, exit_codes.USAGE)
    self.assertEqual(stdout, "")
    self.assertIn("not a directory", stderr)
    self.assertEqual(adapter.calls, [])

  def test_regular_file_repo_exits_usage_with_empty_stdout(self):
    file_path = Path(self.tmp) / "regular_file.txt"
    file_path.write_text("hello", encoding="utf-8")
    adapter = RecordingCmAdapter()
    cfg = find_diff.FindDiffConfig(repo=file_path)

    rc, stdout, stderr = self.execute_find_diff(cfg, adapter)

    self.assertEqual(rc, exit_codes.USAGE)
    self.assertEqual(stdout, "")
    self.assertIn("not a directory", stderr)
    self.assertEqual(adapter.calls, [])

  def test_empty_or_whitespace_base_exits_usage_with_empty_stdout(self):
    for bad_base in ("", "   ", "\t\n"):
      with self.subTest(base=bad_base):
        adapter = RecordingCmAdapter()
        cfg = find_diff.FindDiffConfig(repo=Path(self.repo), base=bad_base)

        rc, stdout, stderr = self.execute_find_diff(cfg, adapter)

        self.assertEqual(rc, exit_codes.USAGE)
        self.assertEqual(stdout, "")
        self.assertIn("--base", stderr)
        self.assertEqual(adapter.calls, [])

  def test_out_pointing_to_existing_regular_file_exits_usage(self):
    out_file = Path(self.tmp) / "existing_file.txt"
    out_file.write_text("not a dir", encoding="utf-8")
    adapter = RecordingCmAdapter()
    cfg = find_diff.FindDiffConfig(
        repo=Path(self.repo), base="HEAD", out=out_file
    )

    rc, stdout, stderr = self.execute_find_diff(cfg, adapter)

    self.assertEqual(rc, exit_codes.USAGE)
    self.assertEqual(stdout, "")
    self.assertIn("not a directory", stderr)
    self.assertEqual(adapter.calls, [])


class TestFindDiffGitPreflight(FindDiffTestBase):
  """Tests for Git repository and `--base` ref pre-flight checks in `validate()` (`REQ-0002`, Exit Code 3)."""

  def test_non_git_directory_exits_failed_before_calling_cm(self):
    non_git_dir = Path(self.tmp) / "plain_dir"
    non_git_dir.mkdir()
    adapter = RecordingCmAdapter()
    cfg = find_diff.FindDiffConfig(repo=non_git_dir, base="HEAD")

    self.assertEqual(cfg.validate(), exit_codes.FAILED)
    rc, stdout, stderr = self.execute_find_diff(cfg, adapter)

    self.assertEqual(rc, exit_codes.FAILED)
    self.assertEqual(stdout, "")
    self.assertIn("not inside a Git working tree", stderr)
    self.assertEqual(adapter.calls, [])

  def test_nonexistent_base_ref_exits_failed_before_calling_cm(self):
    adapter = RecordingCmAdapter()
    cfg = find_diff.FindDiffConfig(
        repo=Path(self.repo), base="origin/nonexistent"
    )

    self.assertEqual(cfg.validate(), exit_codes.FAILED)
    rc, stdout, stderr = self.execute_find_diff(cfg, adapter)

    self.assertEqual(rc, exit_codes.FAILED)
    self.assertEqual(stdout, "")
    self.assertIn("origin/nonexistent", stderr)
    self.assertEqual(adapter.calls, [])

  def test_invalidly_formatted_base_ref_exits_failed_before_calling_cm(self):
    adapter = RecordingCmAdapter()
    cfg = find_diff.FindDiffConfig(
        repo=Path(self.repo), base="origin/..bad..ref"
    )

    self.assertEqual(cfg.validate(), exit_codes.FAILED)
    rc, stdout, stderr = self.execute_find_diff(cfg, adapter)

    self.assertEqual(rc, exit_codes.FAILED)
    self.assertEqual(stdout, "")
    self.assertIn("origin/..bad..ref", stderr)
    self.assertEqual(adapter.calls, [])


class TestFindDiffAdapterExecutionAndSarifOutput(FindDiffTestBase):
  """Tests for two-step `CmAdapter` execution (`REQ-0003`, `REQ-0004`) and SARIF output (`REQ-0005`)."""

  def test_two_step_cm_adapter_execution_and_single_line_sarif_stdout(self):
    adapter = RecordingCmAdapter()
    repo_path = Path(self.repo).resolve()
    cfg = find_diff.FindDiffConfig(repo=repo_path, base="origin/main")

    rc, stdout, stderr = self.execute_find_diff(
        cfg, adapter, log_level="debug"
    )

    self.assertEqual(rc, exit_codes.OK, stderr)
    self.assertEqual(
        adapter.calls,
        [
            {
                "args": [
                    "find",
                    repo_path.as_posix(),
                    "-y",
                    "--diff=origin/main",
                    "--diff-workers=16",
                    "--fail-on",
                    "NONE",
                ],
                "cwd": repo_path.as_posix(),
                "env": None,
                "timeout_sec": 360.0,
            },
            {
                "args": ["report", "--format", "sarif"],
                "cwd": repo_path.as_posix(),
                "env": None,
                "timeout_sec": 60.0,
            },
        ],
    )

    # REQ-0004: No `.codemender_cache` directory created in the repository
    self.assertFalse((repo_path / ".codemender_cache").exists())

    # REQ-0003: Progress output from `cm find --diff` and `cm report` stderr
    # are forwarded to stderr, never stdout
    self.assertIn("Impact-Aware PR Delta Scan", stderr)
    self.assertIn("Session: 11111111-2222-3333-4444-555555555555", stderr)
    self.assertIn("Loaded session 11111111-2222-3333-4444-555555555555", stderr)
    self.assertIn("2 finding(s)", stderr)

    # REQ-0005: stdout contains exactly 1 compact SARIF 2.1.0 JSON line
    lines = stdout.splitlines()
    self.assertEqual(len(lines), 1, f"Expected 1 line on stdout, got: {stdout!r}")
    self.assertTrue(stdout.endswith("\n"))
    sarif_doc = json.loads(lines[0])
    self.assertEqual(sarif_doc["version"], "2.1.0")
    results = sarif_doc["runs"][0]["results"]
    self.assertEqual(len(results), 2)
    self.assertEqual(results[0]["ruleId"], "CWE-78")
    self.assertEqual(results[1]["ruleId"], "CWE-89")

  def test_clean_diff_with_zero_findings_emits_compact_sarif_and_exits_zero(self):
    repo_path = Path(self.repo).resolve()
    adapter = RecordingCmAdapter(
        responses={
            ("report", "--format", "sarif"): CmResult(
                args=("/fake/bin/cm", "report", "--format", "sarif"),
                exit_code=0,
                stdout=_PRETTY_SARIF_ZERO_FINDINGS + "\n",
                stderr="",
                tokens=TokenUsage(),
            ),
        }
    )
    cfg = find_diff.FindDiffConfig(repo=repo_path, base="HEAD")

    rc, stdout, stderr = self.execute_find_diff(cfg, adapter)

    self.assertEqual(rc, exit_codes.OK, stderr)
    lines = stdout.splitlines()
    self.assertEqual(len(lines), 1)
    sarif_doc = json.loads(lines[0])
    self.assertEqual(sarif_doc["runs"][0]["results"], [])
    self.assertIn("0 findings", stderr)

  def test_end_to_end_with_stub_cm_binary_via_real_cm_adapter(self):
    """Exercises `find_diff.run` with a real `CmAdapter` executing a shell stub `cm`."""
    stub_cm = Path(self.tmp) / "cm"
    sarif_file = Path(self.tmp) / "stub_sarif.json"
    sarif_file.write_text(_PRETTY_SARIF_TWO_FINDINGS, encoding="utf-8")

    stub_script = f"""#!/bin/bash
case "$*" in
  --version)
    echo "cm version 0.9.0"
    ;;
  "find {os.path.realpath(self.repo)} -y --diff=origin/main --diff-workers=16 --fail-on NONE")
    echo "Impact-Aware PR Delta Scan"
    echo "Scanning diff..." >&2
    exit 0
    ;;
  "report --format sarif")
    cat "{sarif_file}"
    exit 0
    ;;
  *)
    echo "Unexpected args: $*" >&2
    exit 99
    ;;
esac
"""
    stub_cm.write_text(stub_script, encoding="utf-8")
    stub_cm.chmod(stub_cm.stat().st_mode | stat.S_IEXEC)

    adapter = CmAdapter(str(stub_cm))
    cfg = find_diff.FindDiffConfig(
        repo=Path(self.repo).resolve(), base="origin/main"
    )

    rc, stdout, stderr = self.execute_find_diff(cfg, adapter)

    self.assertEqual(rc, exit_codes.OK, stderr)
    self.assertIn("Impact-Aware PR Delta Scan", stderr)
    lines = stdout.splitlines()
    self.assertEqual(len(lines), 1)
    self.assertEqual(len(json.loads(lines[0])["runs"][0]["results"]), 2)


class TestFindDiffOutArtifacts(FindDiffTestBase):
  """Tests for `--out` report artifact generation (`REQ-0006`)."""

  def test_out_writes_report_sarif_and_report_md_and_keeps_repo_clean(self):
    repo_path = Path(self.repo).resolve()
    out_dir = Path(self.tmp) / "nested" / "cm-artifacts"
    adapter = RecordingCmAdapter()
    cfg = find_diff.FindDiffConfig(
        repo=repo_path, base="origin/main", out=out_dir
    )

    rc, stdout, stderr = self.execute_find_diff(cfg, adapter)

    self.assertEqual(rc, exit_codes.OK, stderr)
    self.assertEqual(
        [c["args"] for c in adapter.calls],
        [
            [
                "find",
                str(repo_path),
                "-y",
                "--diff=origin/main",
                "--diff-workers=16",
                "--fail-on",
                "NONE",
            ],
            ["report", "--format", "sarif"],
            ["report", "--format", "md"],
        ],
    )
    self.assertEqual(adapter.calls[2]["timeout_sec"], 60.0)
    self.assertIsNone(adapter.calls[2]["env"])

    sarif_artifact = out_dir / "report.sarif"
    md_artifact = out_dir / "report.md"
    self.assertTrue(sarif_artifact.is_file())
    self.assertTrue(md_artifact.is_file())

    written_sarif = json.loads(sarif_artifact.read_text(encoding="utf-8"))
    self.assertEqual(len(written_sarif["runs"][0]["results"]), 2)
    self.assertEqual(
        md_artifact.read_text(encoding="utf-8"), _SAMPLE_MARKDOWN_REPORT
    )

    # Repository working tree must remain completely clean
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=self.repo,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    self.assertEqual(status.stdout.strip(), "")

    # stdout still receives the 1-line compact SARIF JSON
    self.assertEqual(len(stdout.splitlines()), 1)


class TestFindDiffFailureAtomicity(FindDiffTestBase):
  """Tests for coarse exit codes and failure atomicity (`REQ-0007`)."""

  def test_cm_find_timeout_skips_report_and_emits_zero_stdout_bytes(self):
    repo_path = Path(self.repo).resolve()
    find_key = (
        "find",
        str(repo_path),
        "-y",
        "--diff=HEAD",
        "--diff-workers=16",
        "--fail-on",
        "NONE",
    )
    adapter = RecordingCmAdapter(
        responses={
            find_key: CmResult(
                args=("/fake/bin/cm", *find_key),
                exit_code=None,
                stdout="Partial scan progress...\n",
                stderr="",
                tokens=TokenUsage(),
                error="timed out after 360.0 s",
            ),
        }
    )
    cfg = find_diff.FindDiffConfig(repo=repo_path, base="HEAD")

    rc, stdout, stderr = self.execute_find_diff(cfg, adapter)

    self.assertEqual(rc, exit_codes.FAILED)
    self.assertEqual(stdout, "")
    self.assertIn("timed out after 360.0 s", stderr)
    self.assertEqual(len(adapter.calls), 1)

  def test_cm_find_non_zero_exit_skips_report_and_emits_zero_stdout_bytes(self):
    repo_path = Path(self.repo).resolve()
    find_key = (
        "find",
        str(repo_path),
        "-y",
        "--diff=HEAD",
        "--diff-workers=16",
        "--fail-on",
        "NONE",
    )
    adapter = RecordingCmAdapter(
        responses={
            find_key: CmResult(
                args=("/fake/bin/cm", *find_key),
                exit_code=1,
                stdout="",
                stderr="rpc error: code = Unavailable desc = backend unreachable\n",
                tokens=TokenUsage(),
            ),
        }
    )
    cfg = find_diff.FindDiffConfig(repo=repo_path, base="HEAD")

    rc, stdout, stderr = self.execute_find_diff(cfg, adapter)

    self.assertEqual(rc, exit_codes.FAILED)
    self.assertEqual(stdout, "")
    self.assertIn("backend unreachable", stderr)
    self.assertEqual(len(adapter.calls), 1)

  def test_cm_report_sarif_failure_emits_zero_stdout_bytes(self):
    repo_path = Path(self.repo).resolve()
    adapter = RecordingCmAdapter(
        responses={
            ("report", "--format", "sarif"): CmResult(
                args=("/fake/bin/cm", "report", "--format", "sarif"),
                exit_code=1,
                stdout="",
                stderr="failed to open state.db\n",
                tokens=TokenUsage(),
            ),
        }
    )
    cfg = find_diff.FindDiffConfig(repo=repo_path, base="HEAD")

    rc, stdout, stderr = self.execute_find_diff(cfg, adapter)

    self.assertEqual(rc, exit_codes.FAILED)
    self.assertEqual(stdout, "")
    self.assertIn("failed to open state.db", stderr)

  def test_cm_report_sarif_malformed_or_invalid_json_emits_zero_stdout_bytes(
      self,
  ):
    repo_path = Path(self.repo).resolve()
    bad_payloads = [
        "",
        "{truncated json",
        "[]",
        '{"version": "2.1.0"}',
        '{"version": "2.1.0", "runs": "not-a-list"}',
    ]
    for payload in bad_payloads:
      with self.subTest(payload=payload):
        adapter = RecordingCmAdapter(
            responses={
                ("report", "--format", "sarif"): CmResult(
                    args=("/fake/bin/cm", "report", "--format", "sarif"),
                    exit_code=0,
                    stdout=payload,
                    stderr="",
                    tokens=TokenUsage(),
                ),
            }
        )
        cfg = find_diff.FindDiffConfig(repo=repo_path, base="HEAD")

        rc, stdout, stderr = self.execute_find_diff(cfg, adapter)

        self.assertEqual(rc, exit_codes.FAILED)
        self.assertEqual(stdout, "")
        self.assertNotEqual(stderr.strip(), "")

  def test_cm_report_md_failure_aborts_before_stdout_emission(self):
    repo_path = Path(self.repo).resolve()
    out_dir = Path(self.tmp) / "out"
    adapter = RecordingCmAdapter(
        responses={
            ("report", "--format", "md"): CmResult(
                args=("/fake/bin/cm", "report", "--format", "md"),
                exit_code=1,
                stdout="",
                stderr="markdown export failed\n",
                tokens=TokenUsage(),
            ),
        }
    )
    cfg = find_diff.FindDiffConfig(repo=repo_path, base="HEAD", out=out_dir)

    rc, stdout, stderr = self.execute_find_diff(cfg, adapter)

    self.assertEqual(rc, exit_codes.FAILED)
    self.assertEqual(stdout, "")
    self.assertIn("markdown export failed", stderr)
    self.assertFalse(out_dir.exists())

  def test_unwritable_out_path_aborts_before_stdout_emission(self):
    repo_path = Path(self.repo).resolve()
    adapter = RecordingCmAdapter()
    # `/dev/null/invalid` cannot be created as a directory on POSIX systems
    cfg = find_diff.FindDiffConfig(
        repo=repo_path,
        base="HEAD",
        out=Path("/dev/null/invalid"),
    )

    rc, stdout, stderr = self.execute_find_diff(cfg, adapter)

    self.assertEqual(rc, exit_codes.FAILED)
    self.assertEqual(stdout, "")
    self.assertIn("Could not write report artifacts", stderr)


class TestFindDiffImports(unittest.TestCase):
  """`find_diff` must not pull in `main.py`, `runners`, or `vcs.github`."""

  def test_find_diff_does_not_import_legacy_main_or_github(self):
    code = (
        "import sys, cli.commands.find_diff\n"
        "bad = [m for m in ('main', 'runners', 'vcs.github')\n"
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


class TestFindDiffCLIContract(CLIContractTestBase):
  """End-to-end subprocess CLI contract tests for `python -m cli find-diff`."""

  def setUp(self):
    super().setUp()
    self.tmp = tempfile.mkdtemp(prefix="cm_runner_find_diff_cli_")
    self.addCleanup(shutil.rmtree, self.tmp, True)

    self.home = os.path.join(self.tmp, "home")
    os.makedirs(self.home, exist_ok=True)
    self.cm_log = os.path.join(self.tmp, "cm.log")

    self.repo = os.path.join(self.tmp, "repo")
    os.makedirs(self.repo, exist_ok=True)
    self._init_git_repo(self.repo)

    self.sarif_file = os.path.join(self.tmp, "stub_sarif.json")
    with open(self.sarif_file, "w", encoding="utf-8") as handle:
      handle.write(_PRETTY_SARIF_TWO_FINDINGS)

    self.md_file = os.path.join(self.tmp, "stub_report.md")
    with open(self.md_file, "w", encoding="utf-8") as handle:
      handle.write(_SAMPLE_MARKDOWN_REPORT)

    self._install_stub_cm(find_exit=0)
    self._cli_path = f"{self._stub_dir}:/usr/bin:/bin"

  def run_cli(self, *args, path=None):
    """Invokes `python -m cli` with an isolated HOME directory."""
    env = dict(os.environ)
    env["PATH"] = self._stub_dir if path is None else path
    env["HOME"] = self.home
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("PYTHONPATH", None)

    return subprocess.run(
        [sys.executable, "-m", "cli", *args],
        cwd=_PKG_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

  def _cm_calls(self) -> List[str]:
    if not os.path.exists(self.cm_log):
      return []
    with open(self.cm_log, encoding="utf-8") as handle:
      return handle.read().splitlines()

  def _init_git_repo(self, repo_dir: str) -> None:
    subprocess.run(
        ["git", "init"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        timeout=30,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        timeout=30,
    )
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        timeout=30,
    )
    readme = os.path.join(repo_dir, "README.md")
    with open(readme, "w", encoding="utf-8") as handle:
      handle.write("# Sample Repo\n")
    subprocess.run(
        ["git", "add", "README.md"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        timeout=30,
    )
    subprocess.run(
        ["git", "commit", "-m", "Initial commit"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        timeout=30,
    )

  def _install_stub_cm(
      self,
      find_exit: int = 0,
      verify_summary: str = "Results: 4 passed, 4 warnings",
      verify_exit: int = 0,
  ) -> None:
    body = f"""#!/bin/bash
PATH=/usr/bin:/bin
echo "$*" >> "{self.cm_log}"
case "$*" in
  --version)
    echo "cm version 0.9.0"
    ;;
  init)
    mkdir -p "$HOME/.codemender" && echo "stock_default: true" > "$HOME/.codemender/config.yaml"
    ;;
  "init --verify")
    echo "{verify_summary}"
    exit {verify_exit}
    ;;
  find\\ *)
    echo "Impact-Aware PR Delta Scan: 2 files in scope"
    echo "Scanning diff..." >&2
    exit {find_exit}
    ;;
  "report --format sarif")
    cat "{self.sarif_file}"
    exit 0
    ;;
  "report --format md")
    cat "{self.md_file}"
    exit 0
    ;;
  *)
    echo "Unexpected cm args: $*" >&2
    exit 99
    ;;
esac
"""
    _write_stub_cm(self._stub_dir, body=body)

  def test_happy_path_emits_one_sarif_json_line_and_keeps_chatter_on_stderr(
      self,
  ):
    res = self.run_cli(
        "find-diff",
        "--repo",
        self.repo,
        "--base",
        "HEAD",
        path=self._cli_path,
    )

    self.assertEqual(res.returncode, exit_codes.OK, res.stderr)
    payload = self.assert_stdout_is_one_json_object(res)
    self.assertEqual(payload["version"], "2.1.0")
    self.assertEqual(len(payload["runs"][0]["results"]), 2)

    config_path = os.path.join(self.home, ".codemender", "config.yaml")
    self.assertTrue(os.path.isfile(config_path))
    with open(config_path, encoding="utf-8") as handle:
      cfg_data = yaml.safe_load(handle)
    self.assertEqual(
        cfg_data["sandbox"]["mounts"]["target_dir"],
        os.path.realpath(self.repo),
    )

    self.assertIn("init check [cm_binary] pass:", res.stderr)
    self.assertIn("init check [cm_workspace] recovered:", res.stderr)
    self.assertIn("init check [cm_config] pass:", res.stderr)
    self.assertIn("init check [cm_verify] pass:", res.stderr)
    self.assertIn("Impact-Aware PR Delta Scan", res.stderr)
    self.assertIn("Scanning diff...", res.stderr)
    self.assertNotIn("Impact-Aware PR Delta Scan", res.stdout)

  def test_no_init_flag_skips_automatic_init_before_and_after_subcommand(self):
    orderings = {
        "before subcommand": [
            "--no-init",
            "find-diff",
            "--repo",
            self.repo,
            "--base",
            "HEAD",
        ],
        "after subcommand": [
            "find-diff",
            "--no-init",
            "--repo",
            self.repo,
            "--base",
            "HEAD",
        ],
    }
    config_path = os.path.join(self.home, ".codemender", "config.yaml")

    for label, argv in orderings.items():
      with self.subTest(ordering=label):
        if os.path.exists(self.cm_log):
          os.remove(self.cm_log)

        res = self.run_cli(*argv, path=self._cli_path)

        self.assertEqual(res.returncode, exit_codes.OK, res.stderr)
        payload = self.assert_stdout_is_one_json_object(res)
        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(len(payload["runs"][0]["results"]), 2)
        self.assertFalse(os.path.exists(config_path))
        calls = self._cm_calls()
        self.assertNotIn("init", calls)
        self.assertNotIn("init --verify", calls)
        self.assertNotIn("init check [", res.stderr)

  def test_failed_automatic_init_stops_before_find_diff_and_leaves_stdout_empty(
      self,
  ):
    self._install_stub_cm(
        verify_summary="Results: 4 passed, 3 warnings, 1 failed"
    )

    res = self.run_cli(
        "find-diff",
        "--repo",
        self.repo,
        "--base",
        "HEAD",
        path=self._cli_path,
    )

    self.assertEqual(res.returncode, exit_codes.FAILED, res.stderr)
    self.assertEqual(res.stdout, "")
    self.assertIn("1 failed", res.stderr)
    calls = self._cm_calls()
    self.assertFalse(
        any(c.startswith("find ") for c in calls),
        f"cm find must not run when automatic init fails; calls={calls}",
    )

  def test_out_flag_writes_report_sarif_and_report_md_and_emits_one_sarif_line(
      self,
  ):
    out_dir = os.path.join(self.tmp, "artifacts")
    res = self.run_cli(
        "find-diff",
        "--repo",
        self.repo,
        "--base",
        "HEAD",
        "--out",
        out_dir,
        path=self._cli_path,
    )

    self.assertEqual(res.returncode, exit_codes.OK, res.stderr)
    payload = self.assert_stdout_is_one_json_object(res)
    self.assertEqual(len(payload["runs"][0]["results"]), 2)

    sarif_path = Path(out_dir) / "report.sarif"
    md_path = Path(out_dir) / "report.md"
    self.assertTrue(sarif_path.is_file())
    self.assertTrue(md_path.is_file())
    self.assertEqual(
        len(json.loads(sarif_path.read_text(encoding="utf-8"))["runs"][0]["results"]),
        2,
    )
    self.assertEqual(
        md_path.read_text(encoding="utf-8"), _SAMPLE_MARKDOWN_REPORT
    )

  def test_usage_errors_exit_two_with_empty_stdout(self):
    cases = {
        "nonexistent repo": [
            "find-diff",
            "--repo",
            os.path.join(self.tmp, "nonexistent"),
        ],
        "empty base": ["find-diff", "--repo", self.repo, "--base", ""],
        "unknown flag --staged": ["find-diff", "--staged"],
    }
    for label, argv in cases.items():
      with self.subTest(case=label):
        res = self.run_cli(*argv, path=self._cli_path)

        self.assertEqual(res.returncode, exit_codes.USAGE, res.stderr)
        self.assertEqual(res.stdout, "")
        self.assertNotEqual(res.stderr.strip(), "")

  def test_failures_exit_three_with_empty_stdout(self):
    non_git = os.path.join(self.tmp, "plain_dir")
    os.makedirs(non_git, exist_ok=True)

    with self.subTest(case="non-git repo"):
      res = self.run_cli(
          "find-diff", "--repo", non_git, "--base", "HEAD", path=self._cli_path
      )
      self.assertEqual(res.returncode, exit_codes.FAILED, res.stderr)
      self.assertEqual(res.stdout, "")
      self.assertIn("not inside a Git working tree", res.stderr)

    with self.subTest(case="missing base ref"):
      res = self.run_cli(
          "find-diff",
          "--repo",
          self.repo,
          "--base",
          "origin/no-such-branch",
          path=self._cli_path,
      )
      self.assertEqual(res.returncode, exit_codes.FAILED, res.stderr)
      self.assertEqual(res.stdout, "")
      self.assertIn("origin/no-such-branch", res.stderr)

    with self.subTest(case="cm find returns exit 1"):
      self._install_stub_cm(find_exit=1)
      res = self.run_cli(
          "find-diff",
          "--repo",
          self.repo,
          "--base",
          "HEAD",
          path=self._cli_path,
      )
      self.assertEqual(res.returncode, exit_codes.FAILED, res.stderr)
      self.assertEqual(res.stdout, "")


if __name__ == "__main__":
  unittest.main()
