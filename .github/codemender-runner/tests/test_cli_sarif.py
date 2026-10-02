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

"""Unit tests for `cli/sarif.py`."""

import json
import unittest

from cli import sarif


class TestSarifDocument(unittest.TestCase):
  """Tests for `SarifDocument` parsing, inspection, and serialization."""

  def test_from_json_valid_sarif(self) -> None:
    payload = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "cm"}},
                "results": [
                    {"ruleId": "CWE-787", "message": {"text": "oob write"}},
                ],
            }
        ],
    }
    doc = sarif.SarifDocument.from_json(json.dumps(payload, indent=2))
    self.assertEqual(doc.result_count, 1)
    self.assertEqual(len(doc.runs), 1)
    self.assertEqual(len(doc.results), 1)
    self.assertEqual(doc.results[0]["ruleId"], "CWE-787")

  def test_from_json_multiple_runs_and_empty_results(self) -> None:
    payload = {
        "version": "2.1.0",
        "runs": [
            {"results": [{"ruleId": "R1"}, {"ruleId": "R2"}]},
            {"results": []},
            {"tool": {"driver": {"name": "no-results-key"}}},
            "ignore-non-dict-run",
            {"results": [{"ruleId": "R3"}, "ignore-non-dict-result"]},
        ],
    }
    doc = sarif.SarifDocument.from_dict(payload)
    # `result_count` counts total entries in `results` lists (including non-dict
    # items if any), whereas `.results` filters to dict items.
    self.assertEqual(doc.result_count, 4)
    self.assertEqual([r["ruleId"] for r in doc.results], ["R1", "R2", "R3"])

  def test_from_json_invalid_json_raises_sarif_json_error(self) -> None:
    with self.assertRaises(sarif.SarifJsonError) as ctx:
      sarif.SarifDocument.from_json("{not valid json")
    self.assertIsInstance(ctx.exception, sarif.SarifError)

  def test_from_json_non_dict_or_missing_runs_raises_schema_error(self) -> None:
    for invalid in ["[]", '{"version": "2.1.0"}', '{"runs": "not-a-list"}']:
      with self.subTest(invalid=invalid):
        with self.assertRaises(sarif.SarifSchemaError) as ctx:
          sarif.SarifDocument.from_json(invalid)
        self.assertIsInstance(ctx.exception, sarif.SarifError)
        self.assertIn("runs", str(ctx.exception))

  def test_to_json_is_single_line_by_default(self) -> None:
    doc = sarif.SarifDocument.from_dict({"version": "2.1.0", "runs": []})
    serialized = doc.to_json()
    self.assertNotIn("\n", serialized)
    self.assertEqual(json.loads(serialized), {"version": "2.1.0", "runs": []})


if __name__ == "__main__":
  unittest.main()
