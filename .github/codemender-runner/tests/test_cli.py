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

"""Unit tests for the cm-runner command-line interface.

Most of these tests assert the *output contract* rather than any particular
command's behaviour:

  1. stdout carries NDJSON and nothing else.
  2. Everything human-readable goes to stderr.
  3. Exit codes are 0 / 2 / 3.

The contract is the part other workstreams depend on, and it is the part most
easily broken by an innocent-looking change elsewhere in the repo -- see
`test_importing_cli_does_not_import_main` for the specific hazard.

The contract tests run the CLI in a subprocess rather than calling `main()`
in-process. That is deliberate: an in-process test cannot see output written
by a child process or by a C-level write to fd 1, and both of those are
exactly how the contract has been broken before.
"""

import ast
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli import exit_codes
from cli.events import EventEmitter

# Directory containing the `cli` package, used as cwd so `python -m cli` works.
_PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# A stub cm that only answers `--version`, which is all `main` needs from it.
_WORKING_CM_BODY = '#!/bin/sh\necho "cm version 0.9.0"\n'


def _write_stub_cm(directory, body=_WORKING_CM_BODY):
  """Writes an executable `cm` stub into `directory` and returns its path."""
  path = os.path.join(directory, "cm")
  with open(path, "w", encoding="utf-8") as handle:
    handle.write(body)
  os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP)
  return path


def _temp_dir(test):
  """Makes a temporary folder that is removed when `test` finishes."""
  directory = tempfile.mkdtemp(prefix="cm_runner_test_")
  test.addCleanup(shutil.rmtree, directory, True)
  return directory


class CLIContractTestBase(unittest.TestCase):
  """Runs the CLI in a subprocess with a controlled PATH."""

  def setUp(self):
    super().setUp()
    # PATH only ever holds folders made here, so a real `cm` installed on the
    # developer's machine can never leak into a test result. Without this,
    # these tests would pass or fail depending on whose laptop they run on.
    self._empty_dir = tempfile.mkdtemp(prefix="cm_runner_test_")
    self.addCleanup(shutil.rmtree, self._empty_dir, True)
    # Every command needs a `cm` that runs, so by default PATH holds a stub.
    self._stub_dir = tempfile.mkdtemp(prefix="cm_runner_stub_")
    self.addCleanup(shutil.rmtree, self._stub_dir, True)
    _write_stub_cm(self._stub_dir)

  def run_cli(self, *args, path=None):
    """Invokes `python -m cli` and captures both streams separately.

    Args:
      *args: Arguments passed after `-m cli`.
      path: Value for PATH in the child. Defaults to a folder holding only a
        working stub `cm`.

    Returns:
      The completed process, with text-mode stdout and stderr.
    """
    env = dict(os.environ)
    env["PATH"] = self._stub_dir if path is None else path
    # Keep the child from writing .pyc files into the source tree, and stop
    # any inherited PYTHONPATH from changing what `cli` resolves to.
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

  def assert_stdout_is_one_json_object(self, completed):
    """Asserts stdout is exactly one line and that line is a JSON object."""
    lines = completed.stdout.splitlines()
    self.assertEqual(
        len(lines),
        1,
        f"stdout must be exactly one line, got {len(lines)}:\n"
        f"{completed.stdout}",
    )
    payload = json.loads(lines[0])
    self.assertIsInstance(payload, dict)
    return payload


class TestStdoutPurity(CLIContractTestBase):
  """The output contract: stdout is machine-readable and nothing else."""

  def test_version_emits_exactly_one_json_object(self):
    """The happy path writes one NDJSON line and exits 0."""
    result = self.run_cli("version")

    self.assertEqual(result.returncode, exit_codes.OK, result.stderr)
    payload = self.assert_stdout_is_one_json_object(result)
    self.assertEqual(payload["event"], "version")
    self.assertIn("ts", payload)
    self.assertIn("contract", payload)

  def test_missing_cm_fails_with_empty_stdout(self):
    """With no cm, main exits 3 before any command runs; stdout stays empty.

    The reason goes to stderr, so a failed run never leaves a line on stdout
    that a caller could mistake for a result.
    """
    commands = (
        ["version"],
        ["init"],
        ["find-diff"],
        ["fix", "--finding", "f.sarif"],
    )
    for command in commands:
      with self.subTest(command=command[0]):
        result = self.run_cli(*command, path=self._empty_dir)

        self.assertEqual(result.returncode, exit_codes.FAILED, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn("cm not found", result.stderr)

  def test_usage_error_exits_two_and_leaves_stdout_empty(self):
    """argparse must never write to stdout, on any error path."""
    cases = {
        "no subcommand": [],
        "unknown subcommand": ["nonsuch"],
        "unknown flag": ["version", "--nonsuch"],
        "invalid flag value": ["version", "--log-level", "loud"],
        # Removed: stdout is always JSON.
        "--output flag": ["version", "--output", "text"],
    }

    for label, argv in cases.items():
      with self.subTest(case=label):
        result = self.run_cli(*argv)

        self.assertEqual(result.returncode, exit_codes.USAGE)
        self.assertEqual(
            result.stdout,
            "",
            f"{label}: stdout must stay empty, got: {result.stdout!r}",
        )
        self.assertNotEqual(result.stderr.strip(), "")

  def test_debug_logging_goes_to_stderr_not_stdout(self):
    """Raising log verbosity must not add anything to stdout.

    This is the regression test for the hazard described in
    `cli/__main__.configure_logging`: a stdout log handler installed anywhere
    in the process would surface here.
    """
    result = self.run_cli("--log-level", "debug", "version")

    self.assertEqual(result.returncode, exit_codes.OK, result.stderr)
    self.assert_stdout_is_one_json_object(result)

  def test_global_flags_accepted_before_and_after_subcommand(self):
    """Both orderings must behave identically.

    argparse silently ignores the pre-subcommand form unless the shared flags
    use SUPPRESS, which is a failure mode that looks like success.
    """
    stub = _write_stub_cm(
        _temp_dir(self), '#!/bin/sh\necho "cm version 7.7.7"\n'
    )

    before = self.run_cli("--cm-binary", stub, "version")
    after = self.run_cli("version", "--cm-binary", stub)

    for result in (before, after):
      self.assertEqual(result.returncode, exit_codes.OK, result.stderr)
      payload = self.assert_stdout_is_one_json_object(result)
      self.assertEqual(payload["cm"]["version"], "7.7.7")

  def test_no_init_sets_auto_init_false_before_and_after_subcommand(self):
    """`--no-init` populates `args.auto_init = False` in both positions; default is True."""
    from cli import __main__ as cli_main

    parser = cli_main.build_parser()
    default_args = cli_main._apply_defaults(parser.parse_args(["find-diff"]))
    self.assertTrue(default_args.auto_init)

    before_args = cli_main._apply_defaults(
        parser.parse_args(["--no-init", "find-diff"])
    )
    self.assertFalse(before_args.auto_init)

    after_args = cli_main._apply_defaults(
        parser.parse_args(["find-diff", "--no-init"])
    )
    self.assertFalse(after_args.auto_init)


class TestCmDetection(CLIContractTestBase):
  """Locating cm and reading its version."""

  def _write_fake_cm(self, body):
    """Creates an executable stub and returns its path."""
    directory = tempfile.mkdtemp(prefix="cm_runner_fake_")
    self.addCleanup(shutil.rmtree, directory, True)

    path = os.path.join(directory, "cm")
    with open(path, "w", encoding="utf-8") as handle:
      handle.write(body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP)
    return path

  def test_reports_version_from_explicit_binary(self):
    """`--cm-binary` is honoured and the bare version is extracted."""
    fake = self._write_fake_cm('#!/bin/bash\necho "cm version 1.2.3"\n')

    result = self.run_cli("version", "--cm-binary", fake)

    payload = self.assert_stdout_is_one_json_object(result)
    self.assertTrue(payload["cm"]["found"])
    self.assertEqual(payload["cm"]["version"], "1.2.3")
    self.assertEqual(payload["cm"]["path"], fake)

  def test_finds_cm_on_path(self):
    """With no explicit path, cm is discovered via PATH."""
    fake = self._write_fake_cm('#!/bin/bash\necho "cm version 4.5.6"\n')

    result = self.run_cli("version", path=os.path.dirname(fake))

    payload = self.assert_stdout_is_one_json_object(result)
    self.assertTrue(payload["cm"]["found"])
    self.assertEqual(payload["cm"]["version"], "4.5.6")

  def test_binary_present_but_version_unreadable_fails(self):
    """A cm that fails `--version` is found but does not run: exit 3.

    Uses an inline stub cm that rejects `--version`. Stdout
    stays empty, and the child's error text does not leak onto it.
    """
    fake = self._write_fake_cm(
        "#!/bin/sh\necho 'unrecognized option' >&2\nexit 1\n"
    )
    result = self.run_cli("version", "--cm-binary", fake)

    self.assertEqual(result.returncode, exit_codes.FAILED, result.stderr)
    self.assertEqual(result.stdout, "")
    self.assertIn("did not run 'cm --version'", result.stderr)

  def test_cm_binary_that_does_not_exist_fails(self):
    """`locate` accepts any --cm-binary path; running it is what fails."""
    missing = os.path.join(self._empty_dir, "no_such_cm")

    result = self.run_cli("version", "--cm-binary", missing)

    self.assertEqual(result.returncode, exit_codes.FAILED, result.stderr)
    self.assertEqual(result.stdout, "")

  def test_noisy_cm_cannot_pollute_stdout(self):
    """Child process chatter is captured, never forwarded to our stdout.

    This is the failure that `detect_cm` exists to avoid: the first
    implementation reused a helper that streams child output to sys.stdout,
    producing six lines where the contract allows one.
    """
    fake = self._write_fake_cm(
        "#!/bin/bash\n"
        'echo "banner line one"\n'
        'echo "banner line two"\n'
        'echo "cm version 9.9.9"\n'
    )

    result = self.run_cli("version", "--cm-binary", fake)

    payload = self.assert_stdout_is_one_json_object(result)
    self.assertEqual(payload["cm"]["version"], "9.9.9")


class TestImportIsolation(unittest.TestCase):
  """The cli package must stay independent of the env-var pipeline."""

  def test_importing_cli_does_not_import_main(self):
    """Importing cli must not pull in main.py.

    `main.py` calls logging.basicConfig() with a StreamHandler(sys.stdout) at
    module scope, so merely importing it attaches a log handler to the event
    stream. Nothing in cli/ imports it today; this test makes sure a future
    refactor cannot quietly change that.
    """
    probe = (
        "import sys;"
        "import cli, cli.__main__, cli.events, cli.exit_codes,"
        " cli.commands.version, cli.commands.find_diff, cli.commands.fix;"
        "print('main' in sys.modules)"
    )
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    result = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=_PKG_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertEqual(
        result.stdout.strip(),
        "False",
        "cli must not import main.py; it configures logging on stdout at "
        "import time.",
    )

  def test_version_command_needs_no_utils_or_third_party_packages(self):
    """`cli.commands.version` must not load legacy `utils` or any package from requirements.txt."""
    probe = (
        "import sys;"
        "before = set(sys.modules);"
        "import cli, cli.events, cli.exit_codes, cli.commands.version;"
        "loaded = set(sys.modules) - before;"
        "print(sorted(m for m in loaded"
        " if m.split('.')[0] in ('utils', 'requests', 'yaml', 'google')))"
    )
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    result = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=_PKG_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertEqual(result.stdout.strip(), "[]")


class TestEventEmitter(unittest.TestCase):
  """The emitter itself, exercised in-process against a StringIO."""

  def test_emit_writes_one_json_line_per_event(self):
    """Each event is a single self-contained line of JSON."""
    stream = StringIO()
    emitter = EventEmitter(stream=stream)

    emitter.emit("first", value=1)
    emitter.emit("second", value=2)

    lines = stream.getvalue().splitlines()
    self.assertEqual(len(lines), 2)
    self.assertEqual(json.loads(lines[0])["event"], "first")
    self.assertEqual(json.loads(lines[1])["value"], 2)

  def test_emit_returns_payload_including_timestamp(self):
    """The returned payload is what was written, so callers can inspect it."""
    emitter = EventEmitter(stream=StringIO())

    payload = emitter.emit("version", orchestrator="0.1.0")

    self.assertEqual(payload["event"], "version")
    self.assertEqual(payload["orchestrator"], "0.1.0")
    self.assertRegex(payload["ts"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class TestExitCodes(unittest.TestCase):
  """The exit codes are a published contract; pin their values."""

  def test_values_are_stable(self):
    """These may be added to, but never changed: CI configs depend on them."""
    self.assertEqual(exit_codes.OK, 0)
    self.assertEqual(exit_codes.USAGE, 2)
    self.assertEqual(exit_codes.FAILED, 3)


class TestCmRunnerScript(unittest.TestCase):
  """Tests for the bin/cm-runner wrapper script."""

  def setUp(self):
    super().setUp()
    self._script = os.path.join(_PKG_DIR, "bin", "cm-runner")

  def test_script_exists_and_is_executable(self):
    self.assertTrue(os.path.isfile(self._script))
    self.assertTrue(os.access(self._script, os.X_OK))

  def test_script_runs_version(self):
    stub = _write_stub_cm(_temp_dir(self))
    result = subprocess.run(
        [self._script, "version", "--cm-binary", stub],
        cwd=_PKG_DIR,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    self.assertEqual(result.returncode, exit_codes.OK, result.stderr)
    payload = json.loads(result.stdout.strip())
    self.assertEqual(payload["event"], "version")

  @unittest.skipUnless(
      os.path.exists(os.path.join(_PKG_DIR, "main.py")),
      "requires legacy main.py",
  )
  def test_script_runs_legacy(self):
    # Running legacy invokes main.py. Without env vars it exits with code 1.
    result = subprocess.run(
        [self._script, "legacy"],
        cwd=_PKG_DIR,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    self.assertEqual(result.returncode, 1)
    self.assertIn("GITHUB_REPO_URL is required", result.stderr)

  def test_script_exit_code_propagation(self):
    result = subprocess.run(
        [self._script, "--nonexistent-option"],
        cwd=_PKG_DIR,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    self.assertEqual(result.returncode, exit_codes.USAGE)

  def test_script_respects_cm_runner_python(self):
    env = dict(os.environ)
    env["CM_RUNNER_PYTHON"] = os.path.join(_temp_dir(self), "custom", "python")
    result = subprocess.run(
        [self._script, "version"],
        cwd=_PKG_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    self.assertEqual(result.returncode, 127)


class TestPackageDirectoryExecution(unittest.TestCase):
  """Tests for running the codemender-runner package directory directly via python3."""

  def test_package_directory_runs_version(self):
    stub = _write_stub_cm(_temp_dir(self))
    result = subprocess.run(
        [sys.executable, _PKG_DIR, "version", "--cm-binary", stub],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    self.assertEqual(result.returncode, exit_codes.OK, result.stderr)
    payload = json.loads(result.stdout.strip())
    self.assertEqual(payload["event"], "version")

  @unittest.skipUnless(
      os.path.exists(os.path.join(_PKG_DIR, "main.py")),
      "requires legacy main.py",
  )
  def test_package_directory_runs_legacy(self):
    result = subprocess.run(
        [sys.executable, _PKG_DIR, "legacy"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    self.assertEqual(result.returncode, 1)
    self.assertIn("GITHUB_REPO_URL is required", result.stderr)

  def test_package_directory_usage_on_missing_command(self):
    result = subprocess.run(
        [sys.executable, _PKG_DIR],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    self.assertEqual(result.returncode, exit_codes.USAGE)


class TestCliArchitectureRules(unittest.TestCase):
  """ADR-0002 Confirmation: architectural boundary enforcement via AST inspection."""

  def _get_cli_python_files(self):
    cli_dir = os.path.join(_PKG_DIR, "cli")
    py_files = []
    for root, _, files in os.walk(cli_dir):
      for f in files:
        if f.endswith(".py"):
          py_files.append(os.path.join(root, f))
    return py_files

  def _get_codemender_python_files(self):
    codemender_dir = os.path.join(_PKG_DIR, "codemender")
    py_files = []
    for root, _, files in os.walk(codemender_dir):
      for f in files:
        if f.endswith(".py"):
          py_files.append(os.path.join(root, f))
    return py_files

  def _assert_no_env_scrubbing_in_tree(self, tree, source_label):
    banned_symbols = {"get_scrubbed_env", "SENSITIVE_ENV_VARS"}
    for node in ast.walk(tree):
      if isinstance(node, ast.ImportFrom):
        for alias in node.names:
          self.assertNotIn(
              alias.name,
              banned_symbols,
              f"{source_label}:{node.lineno} imports banned symbol"
              f" '{alias.name}'",
          )
      elif isinstance(node, ast.Attribute):
        self.assertNotIn(
            node.attr,
            banned_symbols,
            f"{source_label}:{node.lineno} accesses banned attribute"
            f" '{node.attr}'",
        )
      elif isinstance(node, ast.Name):
        self.assertNotIn(
            node.id,
            banned_symbols,
            f"{source_label}:{node.lineno} references banned symbol"
            f" '{node.id}'",
        )

  def test_cli_and_codemender_do_not_reference_env_scrubbing(self):
    """ADR-0003 Confirmation: cli/ and codemender/ must never reference get_scrubbed_env or SENSITIVE_ENV_VARS."""
    target_files = (
        self._get_cli_python_files() + self._get_codemender_python_files()
    )
    self.assertGreater(len(target_files), 0)
    for py_file in target_files:
      with self.subTest(file=os.path.relpath(py_file, _PKG_DIR)):
        with open(py_file, "r", encoding="utf-8") as handle:
          tree = ast.parse(handle.read(), filename=py_file)
        self._assert_no_env_scrubbing_in_tree(tree, py_file)

    synthetic_violations = {
        "import_from": (
            "from config import get_scrubbed_env, SENSITIVE_ENV_VARS\n"
        ),
        "attribute_access": "config.get_scrubbed_env(repo)\n",
        "name_reference": " _ = SENSITIVE_ENV_VARS\n".lstrip(),
    }
    for label, snippet in synthetic_violations.items():
      with self.subTest(synthetic=label):
        with self.assertRaises(AssertionError):
          self._assert_no_env_scrubbing_in_tree(
              ast.parse(snippet, filename="<synthetic>"), "<synthetic>"
          )

  def test_cli_modules_do_not_import_subprocess(self):
    """CLI modules must never import subprocess directly; cm runs through codemender.cm.CmAdapter, git through vcs/git.py."""
    for py_file in self._get_cli_python_files():
      with self.subTest(file=os.path.relpath(py_file, _PKG_DIR)):
        with open(py_file, "r", encoding="utf-8") as handle:
          tree = ast.parse(handle.read(), filename=py_file)
        for node in ast.walk(tree):
          if isinstance(node, ast.Import):
            for alias in node.names:
              self.assertNotEqual(
                  alias.name,
                  "subprocess",
                  f"{py_file}:{node.lineno} imports banned module 'subprocess'",
              )
          elif isinstance(node, ast.ImportFrom):
            self.assertNotEqual(
                node.module,
                "subprocess",
                f"{py_file}:{node.lineno} imports from banned module 'subprocess'",
            )

  def test_cli_modules_do_not_import_vcs_github(self):
    """CLI modules must never import vcs.github; posting to repo hosts belongs to the CI job."""
    for py_file in self._get_cli_python_files():
      with self.subTest(file=os.path.relpath(py_file, _PKG_DIR)):
        with open(py_file, "r", encoding="utf-8") as handle:
          tree = ast.parse(handle.read(), filename=py_file)
        for node in ast.walk(tree):
          if isinstance(node, ast.Import):
            for alias in node.names:
              self.assertNotIn(
                  "vcs.github",
                  alias.name,
                  f"{py_file}:{node.lineno} imports banned module 'vcs.github'",
              )
          elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            self.assertFalse(
                mod == "vcs.github" or mod.startswith("vcs.github"),
                f"{py_file}:{node.lineno} imports from banned module 'vcs.github'",
            )
            if mod == "vcs":
              for alias in node.names:
                self.assertNotEqual(
                    alias.name,
                    "github",
                    f"{py_file}:{node.lineno} imports 'github' from 'vcs'",
                )

  def test_cli_modules_do_not_import_utils(self):
    """CLI modules must never import legacy utils (go/no-utils); it is left untouched for the legacy pipeline."""
    for py_file in self._get_cli_python_files():
      with self.subTest(file=os.path.relpath(py_file, _PKG_DIR)):
        with open(py_file, "r", encoding="utf-8") as handle:
          tree = ast.parse(handle.read(), filename=py_file)
        for node in ast.walk(tree):
          if isinstance(node, ast.Import):
            for alias in node.names:
              self.assertNotEqual(
                  alias.name,
                  "utils",
                  f"{py_file}:{node.lineno} imports banned legacy module 'utils'",
              )
          elif isinstance(node, ast.ImportFrom):
            self.assertNotEqual(
                node.module,
                "utils",
                f"{py_file}:{node.lineno} imports from banned legacy module 'utils'",
            )

  def test_cli_modules_do_not_call_banned_functions_directly(self):
    """CLI modules must not directly call run_command, build_cm_command, or push_branch_to_remote."""
    banned_calls = {"run_command", "build_cm_command", "push_branch_to_remote"}
    for py_file in self._get_cli_python_files():
      with self.subTest(file=os.path.relpath(py_file, _PKG_DIR)):
        with open(py_file, "r", encoding="utf-8") as handle:
          tree = ast.parse(handle.read(), filename=py_file)
        for node in ast.walk(tree):
          if isinstance(node, ast.Call):
            func_name = None
            if isinstance(node.func, ast.Name):
              func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
              func_name = node.func.attr
            self.assertNotIn(
                func_name,
                banned_calls,
                f"{py_file}:{node.lineno} directly calls banned function '{func_name}'",
            )


class TestStdoutRedirectDuringCommand(unittest.TestCase):
  """ADR-0002 Confirmation: while a command runs, stray stdout writes land on stderr."""

  @unittest.skipUnless(
      os.path.exists(os.path.join(_PKG_DIR, "utils.py")),
      "requires legacy utils.py",
  )
  def test_git_helper_inside_command_leaves_stdout_clean(self):
    """A vcs/git.py helper and a bare print() inside a command reach stderr only.

    The probe goes through the real `cli.__main__.main`, with the `version`
    command's `detect_cm` swapped for one that calls a git helper against a
    noisy fake `git` (the legacy `utils.run_command` echoes child output to
    `sys.stdout`) and then prints. This fails if `main` ever stops sending
    stray stdout writes to stderr, or leaves them redirected after it returns.
    """
    temp_dir = tempfile.mkdtemp(prefix="fake_git_")
    self.addCleanup(shutil.rmtree, temp_dir, True)

    fake_git = os.path.join(temp_dir, "git")
    with open(fake_git, "w", encoding="utf-8") as f:
      f.write('#!/bin/sh\necho "fatal: not a git repo"\nexit 128\n')
    os.chmod(fake_git, 0o755)
    # `main` checks cm before the command runs, so a working stub sits next
    # to the fake git.
    _write_stub_cm(temp_dir)

    probe = (
        "import sys\n"
        "import cli.commands.version as version_cmd\n"
        "from cli.__main__ import main\n"
        "from vcs.git import clean_workspace\n"
        "def noisy_detect_cm(adapter):\n"
        f"  clean_workspace({temp_dir!r})\n"
        "  print('stray print from a helper')\n"
        "  return {'found': True, 'version': '0.9.0', 'path': adapter.binary}\n"
        "version_cmd.detect_cm = noisy_detect_cm\n"
        "rc = main(['version'])\n"
        "sys.stderr.write(f'restored={sys.stdout is sys.__stdout__}\\n')\n"
        "sys.exit(rc)\n"
    )

    env = dict(os.environ)
    # Only the fake git and the stub cm are reachable: no real cm or git can
    # leak in.
    env["PATH"] = temp_dir
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("PYTHONPATH", None)

    res = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=_PKG_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    self.assertEqual(res.returncode, exit_codes.OK, res.stderr)
    lines = res.stdout.splitlines()
    self.assertEqual(
        len(lines), 1, f"stdout must hold only the version event, got:\n{res.stdout}"
    )
    self.assertEqual(json.loads(lines[0])["event"], "version")
    # The noisy git output, subprocess delimiters and the print went to stderr.
    self.assertIn(">>> [SUBPROCESS START]", res.stderr)
    self.assertIn("fatal: not a git repo", res.stderr)
    self.assertIn("<<< [SUBPROCESS END]", res.stderr)
    self.assertIn("stray print from a helper", res.stderr)
    self.assertIn("restored=True", res.stderr)


if __name__ == "__main__":
  unittest.main()
