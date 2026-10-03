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

"""cm-runner: the command-line face of the CodeMender orchestrator.

This package is deliberately independent of `main.py`. That module calls
`logging.basicConfig()` with a **stdout** handler at import time, so anything
importing it inherits log output on stdout -- which would corrupt the
machine-readable event stream this CLI emits.

The env-var driven pipelines (`CODEMENDER_RUN_MODE=scan|worker|aggregate`)
continue to run through `main.py` unchanged. This package is an additional way
in, not a replacement.
"""

__version__ = "0.1.0"
