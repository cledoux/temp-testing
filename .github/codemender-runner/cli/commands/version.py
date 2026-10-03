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

"""`cm-runner version` -- report orchestrator, cm, and contract versions.

`main` checks that `cm` is present and runs before any command starts. If it
is not, the run exits `exit_codes.FAILED` with the reason on stderr and this
command never runs.
"""

from __future__ import annotations

import cli
from cli import exit_codes
from cli.events import EventEmitter
from codemender.cm import CmAdapter
from codemender.cm import detect_cm

# The `cm` CLI surface this orchestrator was built and tested against.
#
# Recorded so that version drift is visible rather than mysterious. There is
# precedent: cm 0.7.0 changed `cm report --format json` from PascalCase to
# snake_case keys, which `codemender/cm.py` still carries a workaround for.
# Observed working: cm 0.9.0 on 2026-09-24; cm 0.11.0 on 2026-09-30.
CM_CONTRACT = "cm-0.11.x"


def run(adapter: CmAdapter, emitter: EventEmitter) -> int:
  """Emits a single `version` event.

  Args:
    adapter: The cm found and checked by `main`.
    emitter: Destination for the event.

  Returns:
    Always `exit_codes.OK`.
  """
  cm = detect_cm(adapter)
  emitter.emit(
      "version",
      orchestrator=cli.__version__,
      cm=cm,
      contract=CM_CONTRACT,
  )
  return exit_codes.OK
