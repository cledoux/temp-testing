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

"""Unit tests for codemender.cm module."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from codemender.cm import (
    CmAdapter,
    CmResult,
    Finding,
    TokenUsage,
    _normalise_version,
    detect_cm,
    extract_session_id,
    log_cm_version,
    parse_findings_json,
    parse_token_usage,
)


class TestCodeMenderCm(unittest.TestCase):

  def test_extract_session_id(self):
    """Verify regex extraction of Session UUID from cm find stdout."""
    find_output = """
        🚀 Starting FIND session (mode: SCAN)...
        Server: codemender_prod
        Session: 63198618-4ce9-41fa-b973-436e1451a3d0
        Operation: sessions/63198618-4ce9-41fa-b973-436e1451a3d0/operations/aeabc910
    """
    session_id = extract_session_id(find_output)
    self.assertEqual(session_id, "63198618-4ce9-41fa-b973-436e1451a3d0")

  @unittest.skipUnless(os.path.exists(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "utils.py")), "legacy utils.py excluded in distribution")
  def test_parse_findings_json_valid(self):
    """Verify parsing valid JSON findings output."""
    raw_json = """[
      {
        "FindingID": "f123",
        "VulnType": "SQL Injection",
        "FilePath": "app.py",
        "Status": "NEW"
      }
    ]"""
    findings = parse_findings_json(raw_json)
    self.assertEqual(len(findings), 1)
    self.assertEqual(findings[0]["FindingID"], "f123")
    self.assertEqual(findings[0]["VulnType"], "SQL Injection")

  @unittest.skipUnless(os.path.exists(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "utils.py")), "legacy utils.py excluded in distribution")
  def test_parse_findings_json_cm_070_snake_case(self):
    """Verify cm 0.7.0 snake_case output normalizes to canonical PascalCase."""
    # Verbatim `cm report --format json` payload emitted by cm version 0.7.0,
    # which switched to snake_case struct tags in cl/974628022.
    raw_json = """[
      {
        "finding_id": "a722cea6-dced-56fc-8b96-393c12834278",
        "session_id": "ChA5ODRmOWZiNDBhMTRmNDU0EAgaATAqBG1haW4",
        "title": "SQL Injection in User Authentication",
        "file_path": "/__w/juice-shop-local/juice-shop-local/juice-shop-local/routes/login.ts",
        "severity": "CRITICAL",
        "confidence": 100,
        "analysis": "### Data Flow Analysis\\n- **Source**: `req.body.email`",
        "snippet": "models.sequelize.query(...)",
        "vuln_type": "SQL Injection",
        "vuln_id": "CWE-89",
        "status": "OPEN",
        "start_line": 34,
        "end_line": 35
      },
      {
        "finding_id": "c0b70aa9-78b8-59f5-940a-6f3d9d3b6b6e",
        "session_id": "ChA5ODRmOWZiNDBhMTRmNDU0EAgaATAqBG1haW4",
        "title": "UNION SQL Injection in Product Search",
        "file_path": "/__w/juice-shop-local/juice-shop-local/juice-shop-local/routes/search.ts",
        "severity": "CRITICAL",
        "confidence": 100,
        "analysis": "### Data Flow Analysis\\n- **Source**: `req.query.q`",
        "snippet": "let criteria: any = req.query.q",
        "vuln_type": "SQL Injection",
        "vuln_id": "CWE-89",
        "status": "OPEN",
        "start_line": 21,
        "end_line": 24
      }
    ]"""
    findings = parse_findings_json(raw_json)
    self.assertEqual(len(findings), 2)
    first = findings[0]
    self.assertEqual(first["FindingID"], "a722cea6-dced-56fc-8b96-393c12834278")
    self.assertEqual(
        first["SessionID"], "ChA5ODRmOWZiNDBhMTRmNDU0EAgaATAqBG1haW4"
    )
    self.assertEqual(first["Title"], "SQL Injection in User Authentication")
    self.assertEqual(
        first["FilePath"],
        "/__w/juice-shop-local/juice-shop-local/juice-shop-local/routes/login.ts",
    )
    self.assertEqual(first["Severity"], "CRITICAL")
    self.assertEqual(first["Confidence"], 100)
    self.assertEqual(first["VulnType"], "SQL Injection")
    self.assertEqual(first["VulnID"], "CWE-89")
    self.assertEqual(first["Status"], "OPEN")
    self.assertEqual(first["StartLine"], 34)
    self.assertEqual(first["EndLine"], 35)
    # Original snake_case keys are retained for snake_case-aware consumers
    self.assertEqual(first["finding_id"], first["FindingID"])
    self.assertEqual(
        findings[1]["FindingID"], "c0b70aa9-78b8-59f5-940a-6f3d9d3b6b6e"
    )

  @unittest.skipUnless(os.path.exists(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "utils.py")), "legacy utils.py excluded in distribution")
  def test_parse_findings_json_pascal_case_wins_on_conflict(self):
    """Verify an explicit PascalCase key is never clobbered by its alias."""
    raw_json = """[
      {"FindingID": "pascal-wins", "finding_id": "snake-loses"}
    ]"""
    findings = parse_findings_json(raw_json)
    self.assertEqual(findings[0]["FindingID"], "pascal-wins")
    self.assertEqual(findings[0]["finding_id"], "snake-loses")

  @unittest.skipUnless(os.path.exists(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "utils.py")), "legacy utils.py excluded in distribution")
  @patch("utils.run_command")
  def test_log_cm_version_success(self, mock_run_cmd):
    """Verify log_cm_version logs and returns version string on success."""
    mock_run_cmd.return_value = MagicMock(
        returncode=0,
        stdout="cm version v0.1.0-20260515-vMvg-916238397\n",
        stderr="",
    )
    version = log_cm_version("cm")
    self.assertEqual(version, "cm version v0.1.0-20260515-vMvg-916238397")
    mock_run_cmd.assert_called_once_with(
        ["cm", "--version"],
        cwd=None,
        env=None,
        check=False,
        capture_stderr=True,
    )

  @unittest.skipUnless(os.path.exists(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "utils.py")), "legacy utils.py excluded in distribution")
  @patch("utils.run_command")
  def test_log_cm_version_failure(self, mock_run_cmd):
    """Verify log_cm_version handles command error gracefully."""
    mock_run_cmd.return_value = MagicMock(
        returncode=1,
        stdout="",
        stderr="command not found",
    )
    version = log_cm_version("cm")
    self.assertIsNone(version)

  @unittest.skipUnless(os.path.exists(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "utils.py")), "legacy utils.py excluded in distribution")
  @patch("utils.run_command")
  def test_log_cm_version_exception(self, mock_run_cmd):
    """Verify log_cm_version handles execution exceptions gracefully."""
    mock_run_cmd.side_effect = RuntimeError("Execution failed")
    version = log_cm_version("cm")
    self.assertIsNone(version)

  @patch("codemender.cm.subprocess.run")
  def test_detect_cm_success(self, mock_run):
    """Verify detect_cm extracts bare version string from a bounded call."""
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="cm version 0.9.0\n",
        stderr="",
    )
    res = detect_cm(CmAdapter("/usr/local/bin/cm"))
    self.assertEqual(res, {
        "found": True,
        "version": "0.9.0",
        "path": "/usr/local/bin/cm",
    })
    mock_run.assert_called_once_with(
        ["/usr/local/bin/cm", "--version"],
        cwd=None,
        env=None,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

  @patch("codemender.cm.subprocess.run")
  def test_detect_cm_command_error(self, mock_run):
    """Verify detect_cm returns found=True, version=None when command fails."""
    mock_run.return_value = MagicMock(
        returncode=1,
        stdout="",
        stderr="error: unknown option",
    )
    res = detect_cm(CmAdapter("/usr/local/bin/cm"))
    self.assertEqual(res, {
        "found": True,
        "version": None,
        "path": "/usr/local/bin/cm",
    })

  @patch("codemender.cm.subprocess.run")
  def test_detect_cm_exception(self, mock_run):
    """Verify detect_cm catches OS errors gracefully."""
    mock_run.side_effect = OSError("Permission denied")
    res = detect_cm(CmAdapter("/usr/local/bin/cm"))
    self.assertEqual(res, {
        "found": True,
        "version": None,
        "path": "/usr/local/bin/cm",
    })

  @patch("codemender.cm.subprocess.run")
  def test_version_is_read_once_and_kept(self, mock_run):
    """A version read once is returned again without running cm."""
    mock_run.return_value = MagicMock(
        returncode=0, stdout="cm version 0.9.0\n", stderr=""
    )
    adapter = CmAdapter("/usr/local/bin/cm")

    self.assertEqual(adapter.version(), "0.9.0")
    self.assertEqual(adapter.version(), "0.9.0")
    mock_run.assert_called_once()

  @patch("codemender.cm.subprocess.run")
  def test_failed_version_read_is_not_kept(self, mock_run):
    """After a failed read, the next call runs cm again."""
    mock_run.side_effect = [
        MagicMock(returncode=1, stdout="", stderr="boom"),
        MagicMock(returncode=0, stdout="cm version 0.9.0\n", stderr=""),
    ]
    adapter = CmAdapter("/usr/local/bin/cm")

    self.assertIsNone(adapter.version())
    self.assertEqual(adapter.version(), "0.9.0")
    self.assertEqual(mock_run.call_count, 2)


class TestVersionParsing(unittest.TestCase):
  """Parsing the version string out of `cm --version` output."""

  def test_strips_the_cm_version_prefix(self):
    self.assertEqual(_normalise_version("cm version 0.9.0"), "0.9.0")

  def test_tolerates_surrounding_whitespace(self):
    self.assertEqual(_normalise_version("  cm version 0.9.0 \n"), "0.9.0")

  def test_bare_version_passes_through(self):
    self.assertEqual(_normalise_version("0.9.0"), "0.9.0")

  def test_multiline_version_output(self):
    self.assertEqual(
        _normalise_version("cm version 0.9.0\nbuilt by Jim Meyering\n"),
        "0.9.0",
    )

  def test_empty_and_none_yield_none(self):
    self.assertIsNone(_normalise_version(""))
    self.assertIsNone(_normalise_version("   "))
    self.assertIsNone(_normalise_version(None))


class TestDetectCmWithStubBinary(unittest.TestCase):
  """detect_cm against real stub executables rather than mocks.

  A mock cannot notice a lost timeout or a change in which stream is parsed;
  a real child process can.
  """

  def _write_stub(self, body):
    """Writes an executable stub named `cm` and returns its path."""
    directory = tempfile.mkdtemp(prefix="cm_stub_")
    self.addCleanup(shutil.rmtree, directory, True)
    path = os.path.join(directory, "cm")
    with open(path, "w", encoding="utf-8") as handle:
      handle.write(body)
    os.chmod(path, 0o755)
    return path

  def test_detect_cm_gives_up_on_hung_binary(self):
    """Verify a cm that never answers is reported without a version, in time."""
    stub = self._write_stub("#!/bin/sh\nexec sleep 30\n")

    start = time.monotonic()
    with self.assertLogs("codemender-orchestrator", level="WARNING") as logs:
      res = detect_cm(CmAdapter(stub), timeout_sec=1)
    elapsed = time.monotonic() - start

    self.assertLess(elapsed, 10, "timeout_sec was not honoured")
    self.assertEqual(res, {"found": True, "version": None, "path": stub})
    self.assertIn("Could not read cm version", logs.output[0])

  def test_detect_cm_parses_stdout_only(self):
    """Verify a notice cm prints on stderr is not mistaken for the version."""
    stub = self._write_stub(
        "#!/bin/sh\n"
        'echo "notice: a newer version 1.1.0 is available" >&2\n'
        'echo "cm version 1.0.0"\n'
    )

    res = detect_cm(CmAdapter(stub))

    self.assertEqual(res["version"], "1.0.0")


class TestParseTokenUsage(unittest.TestCase):
  """Token counts are always parsed; every current cm release prints them."""

  def test_sums_every_tokens_line_and_expands_suffixes(self):
    output = (
        "Tokens: 41.5k in / 1.2k out / 42.7k total\n"
        "some progress line\n"
        "Tokens: 561 in / 39 out / 600 total\n"
    )
    self.assertEqual(
        parse_token_usage(output), TokenUsage(42061, 1239, 43300)
    )

  def test_millions_and_billions(self):
    self.assertEqual(
        parse_token_usage("Tokens: 1.2M in / 1G out / 2.2G total"),
        TokenUsage(1_200_000, 1_000_000_000, 2_200_000_000),
    )

  def test_no_tokens_lines_yield_zero(self):
    self.assertEqual(parse_token_usage("nothing here"), TokenUsage())
    self.assertEqual(parse_token_usage(""), TokenUsage())

  def test_unparseable_line_is_skipped(self):
    output = (
        "Tokens: 1.2.3k in / 1 out / 1 total\n"
        "Tokens: 10 in / 20 out / 30 total\n"
    )
    self.assertEqual(parse_token_usage(output), TokenUsage(10, 20, 30))


class TestCmResult(unittest.TestCase):

  def test_ok_needs_exit_zero_and_no_error(self):
    def result(exit_code, error=None):
      return CmResult(("cm",), exit_code, "", "", TokenUsage(), error)

    self.assertTrue(result(0).ok)
    self.assertFalse(result(1).ok)
    self.assertFalse(result(None, "timed out after 1 s").ok)


class TestCmAdapter(unittest.TestCase):
  """CmAdapter against real stub executables rather than mocks."""

  def _write_stub(self, body):
    """Writes an executable stub named `cm` and returns its path."""
    directory = tempfile.mkdtemp(prefix="cm_stub_")
    self.addCleanup(shutil.rmtree, directory, True)
    path = os.path.join(directory, "cm")
    with open(path, "w", encoding="utf-8") as handle:
      handle.write(body)
    os.chmod(path, 0o755)
    return path

  def test_run_returns_processed_result(self):
    """Streams stay separate and token counts are parsed from the output."""
    stub = self._write_stub(
        "#!/bin/sh\n"
        'echo "args: $*"\n'
        'echo "Tokens: 2k in / 1k out / 3k total"\n'
        'echo "a warning" >&2\n'
    )

    result = CmAdapter(stub).run(["find", "."])

    self.assertTrue(result.ok)
    self.assertEqual(result.args, (stub, "find", "."))
    self.assertEqual(result.exit_code, 0)
    self.assertIn("args: find .", result.stdout)
    self.assertNotIn("a warning", result.stdout)
    self.assertEqual(result.stderr.strip(), "a warning")
    self.assertEqual(result.tokens, TokenUsage(2000, 1000, 3000))
    self.assertIsNone(result.error)

  def test_run_reports_non_zero_exit_without_raising(self):
    stub = self._write_stub("#!/bin/sh\necho boom >&2\nexit 3\n")

    result = CmAdapter(stub).run(["fix", "some-id"])

    self.assertFalse(result.ok)
    self.assertEqual(result.exit_code, 3)
    self.assertEqual(result.stderr.strip(), "boom")
    self.assertIsNone(result.error)

  def test_run_stops_a_hung_cm_and_keeps_partial_output(self):
    stub = self._write_stub('#!/bin/sh\necho "started"\nexec sleep 30\n')

    start = time.monotonic()
    result = CmAdapter(stub).run(["find", "."], timeout_sec=1)
    elapsed = time.monotonic() - start

    self.assertLess(elapsed, 10, "timeout_sec was not honoured")
    self.assertFalse(result.ok)
    self.assertIsNone(result.exit_code)
    self.assertIn("timed out", result.error)
    self.assertIsInstance(result.stdout, str)

  def test_run_reports_a_binary_that_cannot_start(self):
    result = CmAdapter("/nonexistent/cm").run(["--version"])

    self.assertFalse(result.ok)
    self.assertIsNone(result.exit_code)
    self.assertIn("could not run", result.error)

  def test_run_closes_stdin(self):
    """cm must never read the runner's own input.

    The adapter runs inside a child Python whose stdin holds a line, so a
    `cm` that inherited stdin would read it.
    """
    stub = self._write_stub(
        '#!/bin/sh\nif read line; then echo "read: $line"; fi\necho done\n'
    )
    probe = (
        "from codemender.cm import CmAdapter;"
        f"print(CmAdapter({stub!r}).run([], timeout_sec=10).stdout, end='')"
    )
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    result = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        env=env,
        input="runner input\n",
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertEqual(result.stdout.strip(), "done")

  @patch("codemender.cm.shutil.which")
  def test_locate_returns_none_when_cm_is_missing(self, mock_which):
    mock_which.return_value = None
    self.assertIsNone(CmAdapter.locate())

  def test_locate_prefers_the_explicit_path(self):
    self.assertEqual(CmAdapter.locate("/opt/cm").binary, "/opt/cm")

  def test_importing_the_adapter_does_not_load_utils(self):
    """Legacy helpers reach utils lazily, so new commands never load it."""
    probe = (
        "import sys;"
        "import codemender.cm;"
        "print(sorted(m for m in sys.modules"
        " if m.split('.')[0] in ('utils', 'requests')))"
    )
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    result = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertEqual(result.stdout.strip(), "[]")



class _ScriptedCm(CmAdapter):
  """Returns queued results in order and records the arguments of each call."""

  def __init__(self, *results):
    super().__init__("/fake/bin/cm")
    self.results = list(results)
    self.calls = []

  def run(self, args, cwd=None, env=None, timeout_sec=None):
    self.calls.append(list(args))
    return self.results.pop(0)


def _result(stdout="", exit_code=0, stderr="", error=None):
  return CmResult(
      args=("/fake/bin/cm",),
      exit_code=exit_code,
      stdout=stdout,
      stderr=stderr,
      tokens=TokenUsage(),
      error=error,
  )


def _listing(*pairs):
  return _result(
      json.dumps([{"finding_id": fid, "status": status} for fid, status in pairs])
  )


class TestListFindings(unittest.TestCase):
  """`cm report --format json`, as `cm` 0.11.0 prints it."""

  def test_maps_ids_to_findings(self):
    adapter = _ScriptedCm(_listing(("a", "OPEN"), ("b", "FIXED")))
    self.assertEqual(
        adapter.list_findings(),
        {
            "a": Finding(finding_id="a", status="OPEN"),
            "b": Finding(finding_id="b", status="FIXED"),
        },
    )
    self.assertEqual(adapter.calls, [["report", "--format", "json"]])

  def test_empty_database(self):
    adapter = _ScriptedCm(_result("[]\n"))
    self.assertEqual(adapter.list_findings(), {})

  def test_failures_return_none(self):
    cases = {
        "not initialised": _result(exit_code=1, stderr="Error: not initialized"),
        "timed out": _result(exit_code=None, error="timed out after 60.0 s"),
        "not json": _result("No findings."),
        "not a list": _result('{"findings": []}'),
    }
    for label, result in cases.items():
      with self.subTest(case=label), self.assertLogs(
          "codemender-orchestrator", level="ERROR"
      ):
        self.assertIsNone(_ScriptedCm(result).list_findings())


class TestImportFinding(unittest.TestCase):
  """The before/after comparison that finds the ID `cm report import` assigned."""

  def test_returns_the_one_new_finding_among_old_ones(self):
    adapter = _ScriptedCm(
        _listing(("old", "FIXED")),
        _result("Successfully imported 1 findings.\n"),
        _listing(("old", "FIXED"), ("new", "OPEN")),
    )
    self.assertEqual(
        adapter.import_finding("/tmp/f.sarif", "/repo"),
        Finding(finding_id="new", status="OPEN"),
    )
    self.assertEqual(
        adapter.calls[1],
        ["report", "import", "-f", "/tmp/f.sarif", "-p", "/repo"],
    )

  def test_zero_or_two_new_ids_is_a_failure(self):
    afters = (
        [("old", "OPEN")],
        [("old", "OPEN"), ("n1", "OPEN"), ("n2", "OPEN")],
    )
    for after in afters:
      with self.subTest(after=after), self.assertLogs(
          "codemender-orchestrator", level="ERROR"
      ):
        adapter = _ScriptedCm(
            _listing(("old", "OPEN")), _result("ok"), _listing(*after)
        )
        self.assertIsNone(adapter.import_finding("f.sarif", "/repo"))

  def test_failed_import_stops_before_listing_again(self):
    adapter = _ScriptedCm(
        _listing(), _result(exit_code=1, stderr="Error: no valid findings")
    )
    with self.assertLogs("codemender-orchestrator", level="ERROR") as logs:
      self.assertIsNone(adapter.import_finding("f.sarif", "/repo"))
    self.assertEqual(len(adapter.calls), 2)
    self.assertIn("no valid findings", "\n".join(logs.output))


class TestGetFinding(unittest.TestCase):
  """Reading one finding after `cm fix` or `cm verify`."""

  def test_reads_one_finding(self):
    adapter = _ScriptedCm(_listing(("a", "OPEN"), ("b", "FIXED")))
    finding = adapter.get_finding("b")
    self.assertEqual(finding, Finding(finding_id="b", status="FIXED"))
    self.assertTrue(finding.is_fixed)
    self.assertFalse(Finding(finding_id="a", status="OPEN").is_fixed)

  def test_unknown_id(self):
    with self.assertLogs("codemender-orchestrator", level="ERROR"):
      self.assertIsNone(_ScriptedCm(_listing()).get_finding("zz"))


if __name__ == "__main__":
  unittest.main()
