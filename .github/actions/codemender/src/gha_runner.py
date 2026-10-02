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

Flow (M1, differential PR scan):
  1. Read the GitHub `pull_request` event (base SHA, head SHA, PR number).
     Same-repo and fork pull requests are handled.
  2. Stage an isolated copy of `$GITHUB_WORKSPACE` (including `.git`) and
     shared `/root/.codemender` + `/out` directories under `$RUNNER_TEMP`.
  3. Run `cm-runner init --repo /workspace` followed by
     `cm-runner find-diff --repo /workspace --base <base_sha> --out /out`
     through the container launcher (under gVisor by default).
  4. Parse the SARIF v2.1.0 output from `find-diff` and post or update one
     sticky Markdown comment on the PR summarizing the findings.
  5. Exit non-zero if `init`, `find-diff`, or comment posting failed.

Configuration comes from environment variables set by `action.yml`:
  CODEMENDER_RUNNER_IMAGE       cm-runner image (pinned SHA tag). Required.
  CODEMENDER_LOG_LEVEL          cm-runner --log-level. Default: info.
  CODEMENDER_CONTAINER_RUNTIME  `runsc` (gVisor, default) or `runc`.
  CODEMENDER_OUT_DIR            Host path where `report.sarif` and `report.md`
                                are written for artifact upload. Optional.
  GOOGLE_CLOUD_PROJECT          GCP project ID for Vertex AI / CodeMender API.
  GOOGLE_GHA_CREDS_PATH         Host path to WIF ADC JSON file (or
                                GOOGLE_APPLICATION_CREDENTIALS).
  GITHUB_WORKSPACE              Checked-out repository on the runner host.
  GITHUB_TOKEN                  Token used only here, to post the PR comment.
  GITHUB_EVENT_NAME, GITHUB_EVENT_PATH, GITHUB_REPOSITORY,
  GITHUB_SERVER_URL, GITHUB_RUN_ID, RUNNER_TEMP   Standard GitHub Actions vars.
"""

import json
import logging
import os
import shutil
import sys
import tempfile
from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.parse import quote

from launcher.base import Launcher, LauncherError, RunResult
from launcher.local_docker import (
    CONTAINER_OUT_DIR,
    CONTAINER_WORKSPACE_DIR,
    RUNTIME_GVISOR,
    LocalDockerLauncher,
)
from vcs.github import post_or_update_sticky_comment

logger = logging.getLogger("codemender-github-actions")

_PR_EVENTS = ("pull_request",)

_SARIF_LEVEL_LABELS = {
    "error": "🔴 High / Critical",
    "warning": "🟠 Medium",
    "note": "🟡 Low",
}


def _inline(value: Any, max_len: int = 200) -> str:
  """Renders an untrusted value safely inside a Markdown code span."""
  text = str(value).replace("`", "'").replace("\n", " ").replace("\r", " ")
  text = text.replace("|", "\\|")
  return f"`{text[:max_len]}`"


def _sanitize_block_text(value: Any, max_len: int = 2000) -> str:
  """Sanitizes untrusted multi-line text so it cannot break Markdown blocks."""
  text = str(value).replace("\r\n", "\n").replace("\r", "\n").strip()
  # Prevent embedded code fences or raw HTML closing tags from breaking out of
  # `<details>` blocks.
  text = text.replace("```", "'''").replace("~~~", "'''")
  text = text.replace("<", "&lt;").replace(">", "&gt;")
  if len(text) > max_len:
    text = text[:max_len] + "…"
  return text


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


def _split_title_and_analysis(message_text: str) -> Tuple[str, str]:
  """Splits `cm`'s `<Title>: <Analysis>` SARIF message into (title, analysis)."""
  text = (message_text or "").strip()
  if not text:
    return ("Vulnerability finding", "")
  first_line, _, rest = text.partition("\n")
  if ": " in first_line:
    prefix, after = first_line.split(": ", 1)
    if 0 < len(prefix) <= 120:
      analysis = f"{after}\n{rest}".strip() if rest else after.strip()
      return (prefix.strip(), analysis)
  return (first_line[:120].strip(), text)


def _format_location(
    result: Dict[str, Any],
    server_url: str,
    repo: str,
    head_sha: str,
) -> str:
  """Formats the primary physicalLocation of a SARIF result as a Markdown link."""
  locations = result.get("locations")
  if not isinstance(locations, list) or not locations:
    return "—"
  phys = (locations[0] or {}).get("physicalLocation") or {}
  uri = ((phys.get("artifactLocation") or {}).get("uri") or "").strip()
  uri = uri.lstrip("/")
  if not uri:
    return "—"

  region = phys.get("region") or {}
  start_line = region.get("startLine")
  end_line = region.get("endLine")

  label = uri
  anchor = ""
  if isinstance(start_line, int) and start_line > 0:
    if isinstance(end_line, int) and end_line > start_line:
      label = f"{uri}:{start_line}-{end_line}"
      anchor = f"#L{start_line}-L{end_line}"
    else:
      label = f"{uri}:{start_line}"
      anchor = f"#L{start_line}"

  safe_label = _inline(label)
  if repo and head_sha:
    encoded_path = "/".join(quote(part, safe="") for part in uri.split("/"))
    url = f"{server_url.rstrip('/')}/{repo}/blob/{quote(head_sha, safe='')}/{encoded_path}{anchor}"
    return f"[{safe_label}]({url})"
  return safe_label


def extract_sarif_results(sarif_doc: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
  """Extracts the flat list of SARIF result objects, or None if invalid SARIF."""
  if not isinstance(sarif_doc, dict):
    return None
  runs = sarif_doc.get("runs")
  if not isinstance(runs, list):
    return None
  results: List[Dict[str, Any]] = []
  for run_entry in runs:
    if not isinstance(run_entry, dict):
      return None
    run_results = run_entry.get("results")
    if not isinstance(run_results, list):
      return None
    for item in run_results:
      if isinstance(item, dict):
        results.append(item)
  return results


def _failed_init_check(init_result: Optional[RunResult]) -> Optional[Dict[str, Any]]:
  """Returns the first failed `check` event from `cm-runner init`, if any."""
  if init_result is None:
    return None
  for event in init_result.events:
    if event.get("event") == "check" and event.get("status") == "fail":
      return event
  return None


def format_find_diff_comment(
    scan_result: Optional[RunResult],
    image: str,
    run_url: str,
    base_sha: str = "",
    head_sha: str = "",
    repo: str = "",
    server_url: str = "https://github.com",
    init_result: Optional[RunResult] = None,
    error: Optional[str] = None,
) -> str:
  """Builds the sticky PR comment body for a `cm-runner find-diff` run."""
  lines = ["### CodeMender Security Scan", ""]
  short_base = base_sha[:12] if base_sha else "HEAD"

  failed_check = _failed_init_check(init_result)
  sarif_doc = (
      scan_result.events[0]
      if (scan_result is not None and scan_result.ok and scan_result.events)
      else None
  )
  findings = extract_sarif_results(sarif_doc) if sarif_doc is not None else None

  if error is None and failed_check is None and findings is not None:
    count = len(findings)
    if count == 0:
      lines.append(
          "✅ **No vulnerabilities found** in the changes for this pull request."
      )
    else:
      noun = "vulnerability" if count == 1 else "vulnerabilities"
      lines.append(
          f"⚠️ **Found {count} {noun}** in the changes for this pull request."
      )
      lines += [
          "",
          "| # | Severity | Rule | Location | Finding |",
          "| :--- | :--- | :--- | :--- | :--- |",
      ]
      detail_blocks: List[str] = []
      for idx, item in enumerate(findings, start=1):
        rule_id = item.get("ruleId") or "unknown"
        level = str(item.get("level") or "warning").lower()
        sev_label = _SARIF_LEVEL_LABELS.get(level, f"⚪ {level}")
        msg_text = ((item.get("message") or {}).get("text") or "").strip()
        title, analysis = _split_title_and_analysis(msg_text)
        loc_md = _format_location(item, server_url, repo, head_sha)

        lines.append(
            f"| {idx} | {sev_label} | {_inline(rule_id, 60)} | {loc_md} |"
            f" {_inline(title, 120)} |"
        )

        detail_lines = [
            f"#### {idx}. {_inline(rule_id, 60)} — {_inline(title, 120)}",
            f"- **Severity:** {sev_label} ({_inline(level, 20)})",
            f"- **Location:** {loc_md}",
        ]
        if analysis:
          detail_lines.append(
              f"- **Details:** {_sanitize_block_text(analysis)}"
          )
        detail_blocks.append("\n".join(detail_lines))

      lines += [
          "",
          "<details>",
          f"<summary><strong>Finding details ({count})</strong></summary>",
          "",
          "\n\n".join(detail_blocks),
          "",
          "</details>",
      ]
    lines += [
        "",
        f"Scanned diff against base {_inline(short_base, 40)}"
        f" · [Workflow run logs]({run_url})",
    ]
    return "\n".join(lines)

  # Failure path (`init` or `find-diff` failed).
  lines.append("❌ **CodeMender scan failed.**")
  lines.append("")
  if error:
    lines.append(f"Reason: {_inline(error)}")
  elif failed_check is not None:
    check_name = failed_check.get("name", "unknown")
    check_msg = failed_check.get("message", "check failed")
    lines.append(
        f"`cm-runner init` failed at {_inline(check_name, 60)}:"
        f" {_inline(check_msg)}"
    )
  elif init_result is not None and not init_result.ok:
    lines.append(
        f"`cm-runner init` exited with code {_inline(init_result.exit_code)}."
    )
  elif scan_result is not None and not scan_result.ok:
    lines.append(
        "`cm-runner find-diff` exited with code"
        f" {_inline(scan_result.exit_code)}."
    )
  else:
    lines.append(
        "`cm-runner find-diff` did not emit a valid SARIF 2.1.0 document."
    )
  lines.append(f"Image: {_inline(image)}")
  lines += ["", f"[Workflow run logs]({run_url})"]
  return "\n".join(lines)


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


def run_pr(
    event: Dict[str, Any], env: Mapping[str, str], launcher: Launcher
) -> int:
  """Handles a pull_request event. Returns the process exit code."""
  pr = event.get("pull_request") or {}
  pr_number = pr.get("number")
  if not pr_number:
    print("::error::Event payload has no pull_request.number.")
    return 1

  base_sha = (
      ((pr.get("base") or {}).get("sha") or "").strip()
      or ((pr.get("base") or {}).get("ref") or "").strip()
  )
  if not base_sha:
    print("::error::Event payload has no pull_request.base.sha.")
    return 1
  head_sha = ((pr.get("head") or {}).get("sha") or "").strip()

  fork = is_fork_pr(event)
  if fork:
    print("::notice::Fork PR: running with the repository's fork-PR settings.")

  image = env.get("CODEMENDER_RUNNER_IMAGE", "")
  init_result: Optional[RunResult] = None
  scan_result: Optional[RunResult] = None
  error: Optional[str] = None

  try:
    init_result = launcher.run("init", ["--repo", CONTAINER_WORKSPACE_DIR])
    if init_result.ok and _failed_init_check(init_result) is None:
      scan_result = launcher.run(
          "find-diff",
          [
              "--repo",
              CONTAINER_WORKSPACE_DIR,
              "--base",
              base_sha,
              "--out",
              CONTAINER_OUT_DIR,
          ],
      )
  except LauncherError as e:
    error = str(e)

  sarif_doc = (
      scan_result.events[0]
      if (scan_result is not None and scan_result.ok and scan_result.events)
      else None
  )
  findings = extract_sarif_results(sarif_doc) if sarif_doc is not None else None
  runner_ok = (
      error is None
      and init_result is not None
      and init_result.ok
      and _failed_init_check(init_result) is None
      and scan_result is not None
      and scan_result.ok
      and findings is not None
  )
  if not runner_ok:
    print(
        "::error::cm-runner scan failed:"
        f" {error or scan_result or init_result}"
    )

  body = format_find_diff_comment(
      scan_result=scan_result,
      image=image,
      run_url=_run_url(env),
      base_sha=base_sha,
      head_sha=head_sha,
      repo=env.get("GITHUB_REPOSITORY", ""),
      server_url=env.get("GITHUB_SERVER_URL", "https://github.com"),
      init_result=init_result,
      error=error,
  )
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


def _stage_host_directories(
    src_workspace: str,
    temp_root: Optional[str],
    out_dir_override: Optional[str],
) -> Tuple[str, str, str, str]:
  """Creates isolated host directories for one scan run.

  Returns:
    (staging_root, workspace_copy_dir, cm_home_dir, out_dir).
  """
  staging_root = tempfile.mkdtemp(
      prefix="codemender-", dir=temp_root if temp_root else None
  )
  workspace_copy = os.path.join(staging_root, "workspace")
  shutil.copytree(src_workspace, workspace_copy, symlinks=True)

  cm_home_dir = os.path.join(staging_root, "cm-home")
  os.makedirs(cm_home_dir, exist_ok=True)

  out_dir = out_dir_override or os.path.join(staging_root, "out")
  os.makedirs(out_dir, exist_ok=True)
  return staging_root, workspace_copy, cm_home_dir, out_dir


def main(env: Mapping[str, str] = os.environ) -> int:
  logging.basicConfig(
      level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr
  )

  event_name = env.get("GITHUB_EVENT_NAME", "")
  if event_name not in _PR_EVENTS:
    print(
        f"::notice::CodeMender: event {event_name!r} is not handled yet;"
        " skipping."
    )
    return 0

  for required in (
      "GITHUB_EVENT_PATH",
      "GITHUB_REPOSITORY",
      "GITHUB_TOKEN",
      "CODEMENDER_RUNNER_IMAGE",
      "GITHUB_WORKSPACE",
      "GOOGLE_CLOUD_PROJECT",
  ):
    if not env.get(required):
      print(f"::error::Missing required environment variable {required}.")
      return 1

  creds_file = (
      env.get("GOOGLE_GHA_CREDS_PATH")
      or env.get("GOOGLE_APPLICATION_CREDENTIALS")
      or ""
  )
  if not creds_file:
    print(
        "::error::Missing GCP credentials file"
        " (GOOGLE_GHA_CREDS_PATH or GOOGLE_APPLICATION_CREDENTIALS)."
    )
    return 1

  src_workspace = env["GITHUB_WORKSPACE"]
  if not os.path.isdir(src_workspace):
    print(
        f"::error::GITHUB_WORKSPACE {src_workspace!r} does not exist or is not"
        " a directory."
    )
    return 1

  with open(env["GITHUB_EVENT_PATH"], encoding="utf-8") as f:
    event = json.load(f)

  staging_root, workspace_copy, cm_home_dir, out_dir = _stage_host_directories(
      src_workspace=src_workspace,
      temp_root=env.get("RUNNER_TEMP"),
      out_dir_override=env.get("CODEMENDER_OUT_DIR"),
  )
  try:
    try:
      launcher = LocalDockerLauncher(
          image=env["CODEMENDER_RUNNER_IMAGE"],
          log_level=env.get("CODEMENDER_LOG_LEVEL", "info"),
          runtime=env.get("CODEMENDER_CONTAINER_RUNTIME") or RUNTIME_GVISOR,
          workspace_dir=workspace_copy,
          cm_home_dir=cm_home_dir,
          out_dir=out_dir,
          gcp_credentials_file=creds_file,
          gcp_project=env["GOOGLE_CLOUD_PROJECT"],
      )
    except ValueError as e:
      print(f"::error::{e}")
      return 1
    print(f"::notice::cm-runner container runtime: {launcher.runtime}")
    return run_pr(event, env, launcher)
  finally:
    shutil.rmtree(staging_root, ignore_errors=True)


if __name__ == "__main__":
  sys.exit(main())
