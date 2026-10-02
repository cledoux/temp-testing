#!/usr/bin/env python3
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

"""CodeMender Runner top-level package entrypoint.

Enables native directory execution (e.g. `python3 .github/codemender-runner <command>`).
Dispatches to the CLI subcommands (`cli.__main__`).
"""

from typing import List, Optional
import sys


def main(argv: Optional[List[str]] = None) -> int:
  args = list(sys.argv[1:] if argv is None else argv)
  from cli.__main__ import main as cli_main  # pylint: disable=import-outside-toplevel

  return cli_main(args)


if __name__ == "__main__":
  sys.exit(main())
