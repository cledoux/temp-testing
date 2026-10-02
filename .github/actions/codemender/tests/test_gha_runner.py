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

"""Unit tests for the gha_runner entry point (M1 init + find-diff flow)."""

import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, call, patch

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

import gha_runner  # pylint: disable=g-import-not-at-top
from launcher.base import LauncherError, RunResult  # pylint: disable=g-import-not-at-top

_VERSION_EVENT = {
    "event": "version",
    "orchestrator": "0.1.0",
    "cm": {"found": True, "version": "0.9.0", "path": "/usr/local/bin/cm"},
    "contract": "cm-0.9.x",
}

_INIT_OK_EVENTS = [
    {"event": "check", "name": "cm_binary", "status": "pass", "message": "ok"},
    {"event": "check", "name": "cm_workspace", "status": "recovered", "message": "created"},
    {"event": "check", "name": "cm_config", "status": "pass", "message": "ok"},
    {"event": "check", "name": "cm_verify", "status": "pass", "message": "ok"},
]

_SARIF_CLEAN = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "CodeMender"}}, "results": []}],
}

_SARIF_WITH_FINDINGS = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "CodeMender"}},
            "results": [
                {
                    "ruleId": "CWE-78",
                    "level": "error",
                    "message": {
                        "text": (
                            "OS Command Injection in archive extractor:"
                            " Untrusted filename user_archive is passed"
                            " directly to os.system('/bin/sh -c')."
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
                    "level": "warning",
                    "message": {
                        "text": (
                            "SQL Injection in user lookup query:"
                            " User-supplied user_id is interpolated directly."
                        )
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/db/users.py"},
                                "region": {"startLine": 42, "endLine": 42},
                            }
                        }
                    ],
                },
            ],
        }
    ],
}

_ENV = {
    "GITHUB_EVENT_NAME": "pull_request",
    "GITHUB_REPOSITORY": "o/r",
    "GITHUB_TOKEN": "tok",
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_RUN_ID": "123",
    "CODEMENDER_RUNNER_IMAGE": "img:sha",
    "GOOGLE_CLOUD_PROJECT": "my-gcp-project",
    "GOOGLE_GHA_CREDS_PATH": "/tmp/adc.json",
}


def _pr_event(
    head_repo="o/r",
    base_repo="o/r",
    number=7,
    base_sha="1111222233334444",
    head_sha="aaaabbbbccccdddd",
):
  return {
      "pull_request": {
          "number": number,
          "head": {"sha": head_sha, "repo": {"full_name": head_repo}},
          "base": {"sha": base_sha, "repo": {"full_name": base_repo}},
      }
  }


def _launcher(init_result=None, scan_result=None, error=None):
  launcher = MagicMock()
  if error:
    launcher.run.side_effect = error
    return launcher
  init_res = (
      init_result
      if init_result is not None
      else RunResult(0, list(_INIT_OK_EVENTS))
  )
  scan_res = (
      scan_result
      if scan_result is not None
      else RunResult(0, [dict(_SARIF_CLEAN)])
  )
  launcher.run.side_effect = [init_res, scan_res]
  return launcher


@patch.object(gha_runner, "post_or_update_sticky_comment", return_value="https://c")
class TestRunPr(unittest.TestCase):

  def test_clean_scan_posts_no_vulnerabilities_comment(self, mock_post):
    launcher = _launcher()

    self.assertEqual(gha_runner.run_pr(_pr_event(), _ENV, launcher), 0)

    self.assertEqual(
        launcher.run.call_args_list,
        [
            call("init", ["--repo", "/workspace"]),
            call(
                "find-diff",
                [
                    "--repo",
                    "/workspace",
                    "--base",
                    "1111222233334444",
                    "--out",
                    "/out",
                ],
            ),
        ],
    )
    token, repo, pr, body = mock_post.call_args.args
    self.assertEqual((token, repo, pr), ("tok", "o/r", 7))
    self.assertIn("✅ **No vulnerabilities found**", body)
    self.assertIn("`111122223333`", body)
    self.assertIn("https://github.com/o/r/actions/runs/123", body)

  def test_findings_posts_summary_table_and_details(self, mock_post):
    launcher = _launcher(scan_result=RunResult(0, [_SARIF_WITH_FINDINGS]))

    self.assertEqual(gha_runner.run_pr(_pr_event(), _ENV, launcher), 0)

    body = mock_post.call_args.args[3]
    self.assertIn("⚠️ **Found 2 vulnerabilities**", body)
    self.assertIn("`CWE-78`", body)
    self.assertIn("`CWE-89`", body)
    self.assertIn("🔴 High / Critical", body)
    self.assertIn("🟠 Medium", body)
    self.assertIn(
        "[`src/archive/unpack.py:18-19`](https://github.com/o/r/blob/aaaabbbbccccdddd/src/archive/unpack.py#L18-L19)",
        body,
    )
    self.assertIn(
        "[`src/db/users.py:42`](https://github.com/o/r/blob/aaaabbbbccccdddd/src/db/users.py#L42)",
        body,
    )
    self.assertIn("<details>", body)
    self.assertIn("Untrusted filename user_archive", body)

  def test_fork_pr_runs_and_posts(self, mock_post):
    launcher = _launcher()

    rc = gha_runner.run_pr(_pr_event(head_repo="fork/r"), _ENV, launcher)

    self.assertEqual(rc, 0)
    self.assertEqual(launcher.run.call_count, 2)
    mock_post.assert_called_once()

  def test_fork_pr_comment_failure_prints_settings_guidance(self, mock_post):
    mock_post.return_value = None
    launcher = _launcher()

    with patch("builtins.print") as mock_print:
      rc = gha_runner.run_pr(_pr_event(head_repo="fork/r"), _ENV, launcher)

    self.assertEqual(rc, 1)
    printed = " ".join(str(c.args[0]) for c in mock_print.call_args_list)
    self.assertIn("Send write tokens to workflows from pull requests", printed)

  def test_init_failure_skips_find_diff_and_posts_error(self, mock_post):
    failed_init = RunResult(
        3,
        [
            {
                "event": "check",
                "name": "cm_verify",
                "status": "fail",
                "message": "missing GOOGLE_CLOUD_PROJECT",
            }
        ],
    )
    launcher = _launcher(init_result=failed_init)

    self.assertEqual(gha_runner.run_pr(_pr_event(), _ENV, launcher), 1)
    launcher.run.assert_called_once_with("init", ["--repo", "/workspace"])
    body = mock_post.call_args.args[3]
    self.assertIn("❌ **CodeMender scan failed.**", body)
    self.assertIn("`cm_verify`", body)
    self.assertIn("missing GOOGLE_CLOUD_PROJECT", body)

  def test_find_diff_failure_posts_failure_and_exits_1(self, mock_post):
    launcher = _launcher(scan_result=RunResult(3, []))

    self.assertEqual(gha_runner.run_pr(_pr_event(), _ENV, launcher), 1)
    body = mock_post.call_args.args[3]
    self.assertIn("❌ **CodeMender scan failed.**", body)
    self.assertIn("`3`", body)

  def test_launcher_error_posts_reason_and_exits_1(self, mock_post):
    launcher = _launcher(error=LauncherError("docker not found"))

    self.assertEqual(gha_runner.run_pr(_pr_event(), _ENV, launcher), 1)
    self.assertIn("docker not found", mock_post.call_args.args[3])

  def test_invalid_sarif_event_is_failure(self, mock_post):
    launcher = _launcher(scan_result=RunResult(0, [{"event": "other"}]))

    self.assertEqual(gha_runner.run_pr(_pr_event(), _ENV, launcher), 1)
    self.assertIn(
        "did not emit a valid SARIF 2.1.0 document", mock_post.call_args.args[3]
    )

  def test_comment_failure_exits_1(self, mock_post):
    mock_post.return_value = None
    launcher = _launcher()

    self.assertEqual(gha_runner.run_pr(_pr_event(), _ENV, launcher), 1)


class TestFormatting(unittest.TestCase):

  def test_untrusted_values_cannot_break_out_of_code_span(self):
    event = dict(_VERSION_EVENT, orchestrator="1`\n## injected")
    body = gha_runner.format_version_comment(
        RunResult(0, [event]), "img", "https://run"
    )
    self.assertNotIn("\n## injected", body)
    self.assertIn("`1' ## injected`", body)

  def test_untrusted_sarif_text_cannot_break_details_or_fences(self):
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "CWE-79|`bad",
                        "level": "error",
                        "message": {
                            "text": (
                                "XSS|Title: Body with ```fence``` and"
                                " </details><script>alert(1)</script>"
                            )
                        },
                        "locations": [],
                    }
                ]
            }
        ],
    }
    body = gha_runner.format_find_diff_comment(
        RunResult(0, [sarif]),
        image="img:sha",
        run_url="https://run",
        base_sha="1234567890ab",
    )
    self.assertNotIn("```", body)
    self.assertNotIn("</details><script>", body)
    self.assertIn("&lt;/details&gt;&lt;script&gt;", body)

  def test_cm_not_found_is_flagged(self):
    event = dict(_VERSION_EVENT, cm={"found": False})
    body = gha_runner.format_version_comment(
        RunResult(0, [event]), "img", "https://run"
    )
    self.assertIn("⚠️", body)


class TestMain(unittest.TestCase):

  def setUp(self):
    super().setUp()
    self._temp_dir = tempfile.mkdtemp(prefix="gha-test-")
    self._workspace = os.path.join(self._temp_dir, "src-repo")
    os.makedirs(os.path.join(self._workspace, ".git"))
    with open(
        os.path.join(self._workspace, "app.py"), "w", encoding="utf-8"
    ) as f:
      f.write("print('hi')\n")
    self._event_file = os.path.join(self._temp_dir, "event.json")
    with open(self._event_file, "w", encoding="utf-8") as f:
      json.dump(_pr_event(), f)

  def tearDown(self):
    shutil.rmtree(self._temp_dir, ignore_errors=True)
    super().tearDown()

  def _env(self, **overrides):
    base = dict(
        _ENV,
        GITHUB_EVENT_PATH=self._event_file,
        GITHUB_WORKSPACE=self._workspace,
        RUNNER_TEMP=self._temp_dir,
    )
    base.update(overrides)
    return base

  def test_non_pr_event_is_skipped(self):
    self.assertEqual(gha_runner.main(self._env(GITHUB_EVENT_NAME="push")), 0)

  def test_missing_required_env_fails(self):
    env = self._env()
    del env["CODEMENDER_RUNNER_IMAGE"]
    self.assertEqual(gha_runner.main(env), 1)

  def test_missing_gcp_creds_fails(self):
    env = self._env(GOOGLE_GHA_CREDS_PATH="", GOOGLE_APPLICATION_CREDENTIALS="")
    self.assertEqual(gha_runner.main(env), 1)

  @patch.object(gha_runner, "run_pr", return_value=0)
  def test_stages_workspace_and_builds_docker_launcher(self, mock_run_pr):
    observed = {}

    def _capture(event, env, launcher):
      observed["workspace_exists"] = os.path.isfile(
          os.path.join(launcher.workspace_dir, "app.py")
      )
      observed["git_exists"] = os.path.isdir(
          os.path.join(launcher.workspace_dir, ".git")
      )
      observed["cm_home_exists"] = os.path.isdir(launcher.cm_home_dir)
      observed["out_exists"] = os.path.isdir(launcher.out_dir)
      return 0

    mock_run_pr.side_effect = _capture
    out_dir = os.path.join(self._temp_dir, "custom-out")
    rc = gha_runner.main(
        self._env(CODEMENDER_LOG_LEVEL="debug", CODEMENDER_OUT_DIR=out_dir)
    )
    self.assertEqual(rc, 0)

    event, _, launcher = mock_run_pr.call_args.args
    self.assertEqual(event["pull_request"]["number"], 7)
    self.assertEqual(launcher.image, "img:sha")
    self.assertEqual(launcher.log_level, "debug")
    self.assertEqual(launcher.runtime, "runsc")
    self.assertEqual(launcher.gcp_project, "my-gcp-project")
    self.assertEqual(launcher.gcp_credentials_file, "/tmp/adc.json")
    self.assertEqual(launcher.out_dir, out_dir)
    self.assertTrue(observed["workspace_exists"])
    self.assertTrue(observed["git_exists"])
    self.assertTrue(observed["cm_home_exists"])
    self.assertTrue(observed["out_exists"])
    # Staging root is cleaned up after `main` returns, while custom out_dir
    # stays on disk for the artifact upload step.
    self.assertFalse(os.path.exists(launcher.workspace_dir))
    self.assertTrue(os.path.isdir(out_dir))

  @patch.object(gha_runner, "run_pr", return_value=0)
  def test_runc_is_an_explicit_opt_out(self, mock_run_pr):
    self.assertEqual(
        gha_runner.main(self._env(CODEMENDER_CONTAINER_RUNTIME="runc")), 0
    )
    self.assertEqual(mock_run_pr.call_args.args[2].runtime, "runc")

  @patch.object(gha_runner, "run_pr", return_value=0)
  def test_empty_runtime_falls_back_to_gvisor(self, mock_run_pr):
    self.assertEqual(
        gha_runner.main(self._env(CODEMENDER_CONTAINER_RUNTIME="")), 0
    )
    self.assertEqual(mock_run_pr.call_args.args[2].runtime, "runsc")

  @patch.object(gha_runner, "run_pr")
  def test_unknown_runtime_fails_before_running(self, mock_run_pr):
    self.assertEqual(
        gha_runner.main(self._env(CODEMENDER_CONTAINER_RUNTIME="kata")), 1
    )
    mock_run_pr.assert_not_called()


if __name__ == "__main__":
  unittest.main()
