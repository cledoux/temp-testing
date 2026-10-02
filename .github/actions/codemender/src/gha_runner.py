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

"""Entry point for the CodeMender GitHub Action.

Flow (M0, walking skeleton):
  1. Read the GitHub event. Same-repo and fork pull requests are handled.
     Fork PRs rely on the repository's fork-PR settings (write token and
     secrets); if those are off, the job fails with guidance (see README).
  2. Start cm-runner through a launcher (M0: local `docker run`) and run
     `cm-runner version`.
  3. Post or update one PR comment with the result.
  4. Exit non-zero if cm-runner failed or the comment could not be posted.

Later milestones replace step 2's `version` with find-diff / fix / verify
once those cm-runner commands exist. Nothing here assumes their flags yet.

Configuration comes from environment variables set by `action.yml`:
  CODEMENDER_RUNNER_IMAGE  cm-runner image (pinned SHA tag). Required.
  CODEMENDER_LOG_LEVEL     cm-runner --log-level. Default: info.
  GITHUB_TOKEN             Token used only here, to post the PR comment.
  GITHUB_EVENT_NAME, GITHUB_EVENT_PATH, GITHUB_REPOSITORY,
  GITHUB_SERVER_URL, GITHUB_RUN_ID   Standard GitHub Actions variables.
"""

import json
import logging
import os
import sys
from typing import Any, Dict, Mapping, Optional

from launcher.base import Launcher, LauncherError, RunResult
from launcher.local_docker import LocalDockerLauncher
from vcs.github import post_or_update_sticky_comment

logger = logging.getLogger("codemender-github-actions")

_PR_EVENTS = ("pull_request",)


def _inline(value: Any) -> str:
  """Renders an untrusted value safely inside a Markdown code span."""
  text = str(value).replace("`", "'").replace("\n", " ").replace("\r", " ")
  return f"`{text[:200]}`"


def _run_url(env: Mapping[str, str]) -> str:
  server = env.get("GITHUB_SERVER_URL", "https://github.com")
  repo = env.get("GITHUB_REPOSITORY", "")
  run_id = env.get("GITHUB_RUN_ID", "")
  return f"{server}/{repo}/actions/runs/{run_id}"


def is_fork_pr(event: Dict[str, Any]) -> bool:
  """True if the PR's head branch lives in a different repository."""
  pr = event.get("pull_request") or {}
  head_repo = ((pr.get("head") or {}).get("repo") or {}).get("full_name")
  base_repo = ((pr.get("base") or {}).get("repo") or {}).get("full_name")
  return bool(head_repo) and head_repo != base_repo


def format_version_comment(
    result: Optional[RunResult],
    image: str,
    run_url: str,
    error: Optional[str] = None,
) -> str:
  """Builds the PR comment body for the M0 `cm-runner version` check."""
  lines = ["### CodeMender", ""]
  version = result.find_event("version") if result else None

  if result is not None and result.ok and version:
    cm = version.get("cm") or {}
    cm_ok = bool(cm.get("found"))
    lines.append(
        "✅ cm-runner is reachable." if cm_ok
        else "⚠️ cm-runner is reachable, but the `cm` binary was not found."
    )
    lines += [
        "",
        "| | |",
        "| :--- | :--- |",
        f"| cm-runner | {_inline(version.get('orchestrator', 'unknown'))} |",
        f"| cm | {_inline(cm.get('version', 'not found'))} |",
        f"| Contract | {_inline(version.get('contract', 'unknown'))} |",
        f"| Image | {_inline(image)} |",
    ]
  else:
    lines.append("❌ cm-runner check failed.")
    lines.append("")
    if error:
      lines.append(f"Reason: {_inline(error)}")
    elif result is not None and not result.ok:
      lines.append(f"cm-runner exited with code {_inline(result.exit_code)}.")
    else:
      lines.append("cm-runner did not emit a `version` event.")
    lines.append(f"Image: {_inline(image)}")

  lines += ["", f"[Workflow run logs]({run_url})"]
  return "\n".join(lines)


def run_pr(event: Dict[str, Any], env: Mapping[str, str], launcher: Launcher) -> int:
  """Handles a pull_request event. Returns the process exit code."""
  pr_number = (event.get("pull_request") or {}).get("number")
  if not pr_number:
    print("::error::Event payload has no pull_request.number.")
    return 1

  fork = is_fork_pr(event)
  if fork:
    print("::notice::Fork PR: running with the repository's fork-PR settings.")

  image = env.get("CODEMENDER_RUNNER_IMAGE", "")
  result: Optional[RunResult] = None
  error: Optional[str] = None
  try:
    result = launcher.run("version")
  except LauncherError as e:
    error = str(e)

  runner_ok = error is None and result is not None and result.ok and bool(
      result.find_event("version")
  )
  if not runner_ok:
    print(f"::error::cm-runner version check failed: {error or result}")

  body = format_version_comment(result, image, _run_url(env), error)
  comment_url = post_or_update_sticky_comment(
      env.get("GITHUB_TOKEN", ""),
      env.get("GITHUB_REPOSITORY", ""),
      int(pr_number),
      body,
  )
  if comment_url is None:
    print("::error::Could not post the CodeMender comment to the pull request.")
    if fork:
      print(
          "::error::This is a fork PR. Ask a repository or organization admin"
          " to enable 'Send write tokens to workflows from pull requests'"
          " (Settings > Actions > General > Fork pull request workflows)."
      )
    return 1

  return 0 if runner_ok else 1


def main(env: Mapping[str, str] = os.environ) -> int:
  logging.basicConfig(
      level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr
  )

  event_name = env.get("GITHUB_EVENT_NAME", "")
  if event_name not in _PR_EVENTS:
    print(f"::notice::CodeMender: event {event_name!r} is not handled yet; skipping.")
    return 0

  for required in ("GITHUB_EVENT_PATH", "GITHUB_REPOSITORY", "GITHUB_TOKEN",
                   "CODEMENDER_RUNNER_IMAGE"):
    if not env.get(required):
      print(f"::error::Missing required environment variable {required}.")
      return 1

  with open(env["GITHUB_EVENT_PATH"], encoding="utf-8") as f:
    event = json.load(f)

  launcher = LocalDockerLauncher(
      image=env["CODEMENDER_RUNNER_IMAGE"],
      log_level=env.get("CODEMENDER_LOG_LEVEL", "info"),
  )
  return run_pr(event, env, launcher)


if __name__ == "__main__":
  sys.exit(main())
