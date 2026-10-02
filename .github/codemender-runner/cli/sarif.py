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

"""SARIF 2.1.0 document abstraction for `cm-runner` CLI commands."""

from __future__ import annotations

import dataclasses
import json
from typing import Any, Dict, List, Optional


class SarifError(ValueError):
  """Base error for invalid SARIF input."""


class SarifJsonError(SarifError):
  """Raised when SARIF text is not valid JSON."""


class SarifSchemaError(SarifError):
  """Raised when parsed JSON does not match the expected SARIF structure."""


@dataclasses.dataclass(frozen=True)
class SarifDocument:
  """Wraps a parsed OASIS SARIF 2.1.0 JSON document.

  Provides a single abstraction layer for validating, inspecting, and
  serializing SARIF reports across `find-diff`, `fix`, and `verify` without
  coupling command modules to raw dictionary traversal.

  Attributes:
    data: The underlying SARIF JSON object (`dict`).
  """

  data: Dict[str, Any]

  @classmethod
  def from_json(cls, text: str) -> "SarifDocument":
    """Parses and validates a SARIF document from a JSON string.

    Args:
      text: Raw JSON string.

    Returns:
      A validated `SarifDocument`.

    Raises:
      SarifJsonError: If `text` is not valid JSON.
      SarifSchemaError: If the parsed JSON is not a dict with a `'runs'` list.
    """
    try:
      raw = json.loads(text)
    except (json.JSONDecodeError, TypeError) as exc:
      raise SarifJsonError(str(exc)) from exc
    return cls.from_dict(raw)

  @classmethod
  def from_dict(cls, raw: Any) -> "SarifDocument":
    """Validates an already-parsed JSON value as a `SarifDocument`.

    Args:
      raw: Parsed JSON value.

    Returns:
      A validated `SarifDocument`.

    Raises:
      SarifSchemaError: If `raw` is not a dict with a `'runs'` list.
    """
    if not isinstance(raw, dict) or not isinstance(raw.get("runs"), list):
      raise SarifSchemaError(
          "expected a JSON object with a 'runs' list (no 'runs' list found)."
      )
    return cls(data=raw)

  @property
  def runs(self) -> List[Dict[str, Any]]:
    """Returns all dict entries in the top-level `'runs'` list."""
    return [
        run_entry
        for run_entry in self.data.get("runs", [])
        if isinstance(run_entry, dict)
    ]

  @property
  def results(self) -> List[Dict[str, Any]]:
    """Returns all finding result objects across all `runs`."""
    items: List[Dict[str, Any]] = []
    for run_entry in self.runs:
      run_results = run_entry.get("results")
      if isinstance(run_results, list):
        items.extend(r for r in run_results if isinstance(r, dict))
    return items

  @property
  def result_count(self) -> int:
    """Returns the total number of finding entries across all `runs`."""
    return sum(
        len(run_entry["results"])
        for run_entry in self.runs
        if isinstance(run_entry.get("results"), list)
    )

  def to_json(self, indent: Optional[int] = None) -> str:
    """Serializes the SARIF document to JSON (compact 1-line by default)."""
    return json.dumps(self.data, indent=indent)
