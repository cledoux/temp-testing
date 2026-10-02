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

"""Unit tests for the launcher interface and LocalDockerLauncher."""

import os
import subprocess
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from launcher.base import LauncherError, RunResult, parse_ndjson  # pylint: disable=g-import-not-at-top
from launcher.local_docker import LocalDockerLauncher  # pylint: disable=g-import-not-at-top

_VERSION_LINE = (
    '{"ts": "2026-09-25T00:43:23Z", "event": "version", "orchestrator":'
    ' "0.1.0", "cm": {"found": true, "version": "0.9.0", "path":'
    ' "/usr/local/bin/cm"}, "contract": "cm-0.9.x"}'
)


class TestParseNdjson(unittest.TestCase):

  def test_parses_one_object_per_line_and_skips_blanks(self):
    events = parse_ndjson(f"{_VERSION_LINE}\n\n{{\"event\": \"x\"}}\n")
    self.assertEqual([e["event"] for e in events], ["version", "x"])

  def test_non_json_line_is_contract_violation(self):
    with self.assertRaises(LauncherError):
      parse_ndjson("Starting up...\n")

  def test_non_object_json_is_contract_violation(self):
    with self.assertRaises(LauncherError):
      parse_ndjson("[1, 2]\n")

  def test_find_event(self):
    result = RunResult(0, parse_ndjson(_VERSION_LINE))
    self.assertEqual(result.find_event("version")["orchestrator"], "0.1.0")
    self.assertIsNone(result.find_event("finding"))


class TestLocalDockerLauncher(unittest.TestCase):

  def test_requires_image(self):
    with self.assertRaises(ValueError):
      LocalDockerLauncher(image="")

  def test_build_command_passes_no_environment(self):
    launcher = LocalDockerLauncher(image="img:sha", log_level="debug")
    argv = launcher.build_command("version")

    self.assertEqual(
        argv,
        ["docker", "run", "--rm", "img:sha",
         "--output", "json", "--log-level", "debug", "version"],
    )
    # Security boundary: nothing from the host env (e.g. GITHUB_TOKEN) is
    # forwarded into the container.
    self.assertNotIn("-e", argv)
    self.assertNotIn("--env", argv)
    self.assertNotIn("--env-file", argv)
    self.assertFalse(any("TOKEN" in a for a in argv))

  @patch("launcher.local_docker.subprocess.run")
  def test_run_returns_exit_code_and_events(self, mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout=_VERSION_LINE + "\n")

    result = LocalDockerLauncher(image="img:sha").run("version")

    self.assertTrue(result.ok)
    self.assertEqual(result.find_event("version")["cm"]["version"], "0.9.0")
    kwargs = mock_run.call_args.kwargs
    self.assertEqual(kwargs["stdout"], subprocess.PIPE)
    self.assertIsNone(kwargs["stderr"])  # logs stream to the job log
    self.assertNotIn("env", kwargs)

  @patch("launcher.local_docker.subprocess.run")
  def test_run_propagates_failure_exit_code(self, mock_run):
    mock_run.return_value = MagicMock(returncode=3, stdout="")

    result = LocalDockerLauncher(image="img:sha").run("version")

    self.assertFalse(result.ok)
    self.assertEqual(result.exit_code, 3)
    self.assertEqual(result.events, [])

  @patch("launcher.local_docker.subprocess.run", side_effect=FileNotFoundError)
  def test_missing_docker_raises_launcher_error(self, _):
    with self.assertRaises(LauncherError):
      LocalDockerLauncher(image="img:sha").run("version")

  @patch(
      "launcher.local_docker.subprocess.run",
      side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=1),
  )
  def test_timeout_raises_launcher_error(self, _):
    with self.assertRaises(LauncherError):
      LocalDockerLauncher(image="img:sha", timeout_seconds=1).run("version")


if __name__ == "__main__":
  unittest.main()
