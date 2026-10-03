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

  _ALLOWED_ENV_KEYS = frozenset({
      "GIT_CONFIG_COUNT",
      "GIT_CONFIG_KEY_0",
      "GIT_CONFIG_VALUE_0",
      "GOOGLE_APPLICATION_CREDENTIALS",
      "GOOGLE_CLOUD_PROJECT",
  })

  def assert_no_host_env_or_escalation(self, argv):
    # Security boundary (ADR-0003): no bare `-e KEY` (host env passthrough),
    # no `--env-file`, and no repository-host token (`GITHUB_TOKEN`, etc.).
    self.assertNotIn("--env", argv)
    self.assertNotIn("--env-file", argv)
    self.assertFalse(any("TOKEN" in a for a in argv))
    for i, token in enumerate(argv):
      if token == "-e":
        self.assertLess(i + 1, len(argv))
        kv = argv[i + 1]
        self.assertIn("=", kv, "Every -e flag must be explicit KEY=VALUE")
        key, _ = kv.split("=", 1)
        self.assertIn(key, self._ALLOWED_ENV_KEYS)
    # Never weaken the real kernel's confinement.
    self.assertFalse(any(a.startswith("--privileged") for a in argv))
    self.assertFalse(any(a.startswith("--security-opt") for a in argv))
    self.assertFalse(any("unconfined" in a for a in argv))

  def test_requires_image(self):
    with self.assertRaises(ValueError):
      LocalDockerLauncher(image="")

  def test_default_runtime_is_gvisor(self):
    self.assertEqual(LocalDockerLauncher(image="img:sha").runtime, "runsc")

  def test_build_command_runsc_adds_gvisor_and_sys_admin_only(self):
    launcher = LocalDockerLauncher(
        image="img:sha", log_level="debug", runtime="runsc"
    )
    argv = launcher.build_command("version")

    self.assertEqual(
        argv,
        ["docker", "run", "--rm", "--runtime=runsc", "--cap-add", "SYS_ADMIN",
         "img:sha", "--log-level", "debug", "version"],
    )
    self.assertNotIn("-e", argv)
    self.assert_no_host_env_or_escalation(argv)

  def test_build_command_runc_adds_no_runtime_flags(self):
    launcher = LocalDockerLauncher(
        image="img:sha", log_level="debug", runtime="runc"
    )
    argv = launcher.build_command("version")

    self.assertEqual(
        argv,
        ["docker", "run", "--rm", "img:sha",
         "--log-level", "debug", "version"],
    )
    # SYS_ADMIN on runc would be granted by the real kernel: never add it.
    self.assertNotIn("--cap-add", argv)
    self.assertNotIn("SYS_ADMIN", argv)
    self.assertNotIn("-e", argv)
    self.assert_no_host_env_or_escalation(argv)

  def test_build_command_with_mounts_and_gcp_auth(self):
    launcher = LocalDockerLauncher(
        image="img:sha",
        log_level="info",
        runtime="runsc",
        workspace_dir="/tmp/work/workspace",
        cm_home_dir="/tmp/work/cm-home",
        out_dir="/tmp/work/out",
        gcp_credentials_file="/tmp/creds/adc.json",
        gcp_project="my-gcp-proj",
    )
    argv = launcher.build_command(
        "find-diff",
        ["--repo", "/workspace", "--base", "abc1234", "--out", "/out"],
    )

    self.assertEqual(
        argv,
        [
            "docker",
            "run",
            "--rm",
            "--runtime=runsc",
            "--cap-add",
            "SYS_ADMIN",
            "-v",
            "/tmp/work/workspace:/workspace",
            "-e",
            "GIT_CONFIG_COUNT=1",
            "-e",
            "GIT_CONFIG_KEY_0=safe.directory",
            "-e",
            "GIT_CONFIG_VALUE_0=/workspace",
            "-v",
            "/tmp/work/cm-home:/root/.codemender",
            "-v",
            "/tmp/work/out:/out",
            "-v",
            "/tmp/creds/adc.json:/creds/adc.json:ro",
            "-e",
            "GOOGLE_APPLICATION_CREDENTIALS=/creds/adc.json",
            "-e",
            "GOOGLE_CLOUD_PROJECT=my-gcp-proj",
            "img:sha",
            "--log-level",
            "info",
            "find-diff",
            "--repo",
            "/workspace",
            "--base",
            "abc1234",
            "--out",
            "/out",
        ],
    )
    image_at = argv.index("img:sha")
    for idx, tok in enumerate(argv):
      if tok in ("-v", "-e"):
        self.assertLess(idx, image_at)
    self.assert_no_host_env_or_escalation(argv)

  def test_unknown_runtime_is_rejected(self):
    for runtime in ("", "kata", "RUNSC", "runsc --privileged"):
      with self.subTest(runtime=runtime):
        with self.assertRaises(ValueError):
          LocalDockerLauncher(image="img:sha", runtime=runtime)

  def test_runtime_flags_come_before_image(self):
    # Anything after the image is passed to cm-runner, not to docker.
    argv = LocalDockerLauncher(image="img:sha").build_command("version")
    image_at = argv.index("img:sha")
    self.assertLess(argv.index("--runtime=runsc"), image_at)
    self.assertLess(argv.index("SYS_ADMIN"), image_at)

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
