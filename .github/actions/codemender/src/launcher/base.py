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

"""Launcher interface and the cm-runner output contract (ADR-0001)."""

import abc
from dataclasses import dataclass, field
import json
from typing import Any, Dict, List, Optional, Sequence

# cm-runner exit codes (ADR-0001). Frozen by the contract.
EXIT_OK = 0
EXIT_USAGE_ERROR = 2
EXIT_EXECUTION_FAILURE = 3


class LauncherError(Exception):
  """cm-runner could not be started, or broke the output contract."""


@dataclass
class RunResult:
  """Outcome of one cm-runner command.

  Attributes:
    exit_code: cm-runner's exit code (0 ok, 2 usage error, 3 failure).
    events: Parsed NDJSON events from stdout, one dict per line.
  """

  exit_code: int
  events: List[Dict[str, Any]] = field(default_factory=list)

  @property
  def ok(self) -> bool:
    return self.exit_code == EXIT_OK

  def find_event(self, event_type: str) -> Optional[Dict[str, Any]]:
    """Returns the first stdout event whose `event` field is `event_type`."""
    for event in self.events:
      if event.get("event") == event_type:
        return event
    return None


def parse_ndjson(stdout: str) -> List[Dict[str, Any]]:
  """Parses cm-runner stdout: one JSON object per line (ADR-0001).

  Blank lines are ignored. Anything else that is not a JSON object is a
  contract violation, because consumers fan out over every line.

  Raises:
    LauncherError: if a non-blank line is not a JSON object.
  """
  events = []
  for line_no, line in enumerate(stdout.splitlines(), start=1):
    if not line.strip():
      continue
    try:
      event = json.loads(line)
    except json.JSONDecodeError as e:
      raise LauncherError(
          f"cm-runner stdout line {line_no} is not valid JSON: {line[:200]!r}"
      ) from e
    if not isinstance(event, dict):
      raise LauncherError(
          f"cm-runner stdout line {line_no} is not a JSON object: {line[:200]!r}"
      )
    events.append(event)
  return events


class Launcher(abc.ABC):
  """Starts cm-runner somewhere and returns its result.

  Implementations decide *where* cm-runner runs (local docker, Cloud Run,
  GKE, ...) and what is passed into that environment. They must never pass
  the GitHub token to cm-runner (ADR-0002).
  """

  @abc.abstractmethod
  def run(self, command: str, args: Sequence[str] = ()) -> RunResult:
    """Runs `cm-runner <command> [args]` and waits for it to finish.

    Args:
      command: cm-runner subcommand, e.g. "version".
      args: Extra flags for the subcommand.

    Returns:
      The exit code and parsed stdout events.

    Raises:
      LauncherError: if cm-runner could not be started or its stdout broke
        the NDJSON contract.
    """
