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

"""Exit codes for cm-runner.

There are deliberately only three, mirroring codemender-connect's taxonomy.

Why not fine-grained codes (10 = cm missing, 13 = credentials, ...)?

  * GitHub Actions does not expose a step's numeric exit code to later steps.
    Only `outcome` and `conclusion` are available, and those are just
    "success"/"failure"/"cancelled". Reading an actual number requires
    `continue-on-error: true` plus `set +e` plus writing to `$GITHUB_OUTPUT`,
    and even then it surfaces exactly one reason.

  * The NDJSON event stream is a strictly better channel. A single jq filter
    reports *every* failed check together with its remediation text.

  * Codes can be added later without breaking any caller. They can never be
    removed. Starting narrow keeps that door open.

Decision recorded 2026-09-24 (Workstream 1, E1, decision 0.2).
"""

# Everything the command was asked to do succeeded.
OK = 0

# The caller made a mistake: unknown subcommand, bad flag, missing argument.
# Matches argparse's own exit code for parse failures.
USAGE = 2

# The command ran correctly but its subject failed: a check did not pass, a
# required binary was missing, an underlying tool errored.
FAILED = 3
