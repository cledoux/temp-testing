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

"""Unit tests for the gha_runner entry point (M0 flow)."""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

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

_ENV = {
    "GITHUB_EVENT_NAME": "pull_request",
    "GITHUB_REPOSITORY": "o/r",
    "GITHUB_TOKEN": "tok",
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_RUN_ID": "123",
    "CODEMENDER_RUNNER_IMAGE": "img:sha",
}


def _pr_event(head_repo="o/r", base_repo="o/r", number=7):
  return {
      "pull_request": {
          "number": number,
          "head": {"repo": {"full_name": head_repo}},
          "base": {"repo": {"full_name": base_repo}},
      }
  }


def _launcher(result=None, error=None):
  launcher = MagicMock()
  if error:
    launcher.run.side_effect = error
  else:
    launcher.run.return_value = result
  return launcher


@patch.object(gha_runner, "post_or_update_sticky_comment", return_value="https://c")
class TestRunPr(unittest.TestCase):

  def test_success_posts_version_comment(self, mock_post):
    launcher = _launcher(RunResult(0, [_VERSION_EVENT]))

    self.assertEqual(gha_runner.run_pr(_pr_event(), _ENV, launcher), 0)

    launcher.run.assert_called_once_with("version")
    token, repo, pr, body = mock_post.call_args.args
    self.assertEqual((token, repo, pr), ("tok", "o/r", 7))
    self.assertIn("✅", body)
    self.assertIn("`0.9.0`", body)
    self.assertIn("https://github.com/o/r/actions/runs/123", body)

  def test_fork_pr_runs_and_posts(self, mock_post):
    launcher = _launcher(RunResult(0, [_VERSION_EVENT]))

    rc = gha_runner.run_pr(_pr_event(head_repo="fork/r"), _ENV, launcher)

    self.assertEqual(rc, 0)
    launcher.run.assert_called_once_with("version")
    mock_post.assert_called_once()

  def test_fork_pr_comment_failure_prints_settings_guidance(self, mock_post):
    mock_post.return_value = None
    launcher = _launcher(RunResult(0, [_VERSION_EVENT]))

    with patch("builtins.print") as mock_print:
      rc = gha_runner.run_pr(_pr_event(head_repo="fork/r"), _ENV, launcher)

    self.assertEqual(rc, 1)
    printed = " ".join(str(c.args[0]) for c in mock_print.call_args_list)
    self.assertIn("Send write tokens to workflows from pull requests", printed)

  def test_runner_failure_posts_failure_and_exits_1(self, mock_post):
    launcher = _launcher(RunResult(3, []))

    self.assertEqual(gha_runner.run_pr(_pr_event(), _ENV, launcher), 1)
    body = mock_post.call_args.args[3]
    self.assertIn("❌", body)
    self.assertIn("`3`", body)

  def test_launcher_error_posts_reason_and_exits_1(self, mock_post):
    launcher = _launcher(error=LauncherError("docker not found"))

    self.assertEqual(gha_runner.run_pr(_pr_event(), _ENV, launcher), 1)
    self.assertIn("docker not found", mock_post.call_args.args[3])

  def test_missing_version_event_is_failure(self, mock_post):
    launcher = _launcher(RunResult(0, [{"event": "other"}]))

    self.assertEqual(gha_runner.run_pr(_pr_event(), _ENV, launcher), 1)
    self.assertIn("did not emit", mock_post.call_args.args[3])

  def test_comment_failure_exits_1(self, mock_post):
    mock_post.return_value = None
    launcher = _launcher(RunResult(0, [_VERSION_EVENT]))

    self.assertEqual(gha_runner.run_pr(_pr_event(), _ENV, launcher), 1)


class TestFormatting(unittest.TestCase):

  def test_untrusted_values_cannot_break_out_of_code_span(self):
    event = dict(_VERSION_EVENT, orchestrator="1`\n## injected")
    body = gha_runner.format_version_comment(
        RunResult(0, [event]), "img", "https://run"
    )
    self.assertNotIn("\n## injected", body)
    self.assertIn("`1' ## injected`", body)

  def test_cm_not_found_is_flagged(self):
    event = dict(_VERSION_EVENT, cm={"found": False})
    body = gha_runner.format_version_comment(
        RunResult(0, [event]), "img", "https://run"
    )
    self.assertIn("⚠️", body)


class TestMain(unittest.TestCase):

  def test_non_pr_event_is_skipped(self):
    env = dict(_ENV, GITHUB_EVENT_NAME="push")
    self.assertEqual(gha_runner.main(env), 0)

  def test_missing_required_env_fails(self):
    env = dict(_ENV)
    del env["CODEMENDER_RUNNER_IMAGE"]
    env["GITHUB_EVENT_PATH"] = "/nonexistent"
    self.assertEqual(gha_runner.main(env), 1)

  @patch.object(gha_runner, "run_pr", return_value=0)
  def test_reads_event_and_builds_docker_launcher(self, mock_run_pr):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
      json.dump(_pr_event(), f)
    try:
      env = dict(_ENV, GITHUB_EVENT_PATH=f.name, CODEMENDER_LOG_LEVEL="debug")
      self.assertEqual(gha_runner.main(env), 0)
    finally:
      os.unlink(f.name)

    event, _, launcher = mock_run_pr.call_args.args
    self.assertEqual(event["pull_request"]["number"], 7)
    self.assertEqual(launcher.image, "img:sha")
    self.assertEqual(launcher.log_level, "debug")


if __name__ == "__main__":
  unittest.main()
