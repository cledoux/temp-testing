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

"""GitHub REST API helpers used by the CodeMender GitHub Actions integration.

Posting to the repo host is the CI job's responsibility (ADR-0002); cm-runner
never receives a GitHub token. This module is therefore only ever imported by
the GitHub Actions side (`gha_runner.py`), never by cm-runner.

M0 scope: a single "sticky" PR comment that is created on the first run and
updated in place on subsequent runs, so re-runs never spam the PR.
"""

import functools
import logging
import re
import time
from typing import Any, Callable, Optional

import requests

logger = logging.getLogger("codemender-github-actions")

GITHUB_API_URL = "https://api.github.com"

# Hidden HTML marker that identifies the comment owned by CodeMender, so it
# can be found and updated instead of posting a new comment on every run.
STICKY_SUMMARY_MARKER = "<!-- codemender-summary -->"

# GitHub rejects issue comment bodies longer than this.
MAX_COMMENT_BODY_CHARS = 65536
_TRUNCATION_NOTICE = (
    "\n\n---\n"
    "*⚠️ This comment was truncated because it exceeded GitHub's 65,536"
    " character limit. See the workflow run logs for the full output.*"
)
_TRUNCATION_SLACK = 16
_MD_FENCE_RE = re.compile(r"^(`{3,}|~{3,})(.*)$")
_REQUEST_TIMEOUT_SECONDS = 15


def retry_on_exception(
    max_tries: int = 3,
    initial_delay: float = 2.0,
    backoff_factor: float = 2.0,
) -> Callable:
  """Retries a function with exponential backoff when an exception occurs."""

  def decorator(func: Callable) -> Callable:
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
      delay = initial_delay
      for attempt in range(1, max_tries + 1):
        try:
          return func(*args, **kwargs)
        except Exception as e:  # pylint: disable=broad-exception-caught
          if attempt == max_tries:
            raise
          logger.warning(
              "Attempt %d failed for %s: %s. Retrying in %s seconds...",
              attempt,
              func.__name__,
              e,
              delay,
          )
          time.sleep(delay)
          delay *= backoff_factor

    return wrapper

  return decorator


def _terminate_open_fence(text: str) -> str:
  """Appends a closing delimiter if `text` leaves a Markdown code fence open."""
  open_delim = ""
  for line in text.split("\n"):
    match = _MD_FENCE_RE.match(line)
    if not match:
      continue
    delim, info = match.group(1), match.group(2)
    if not open_delim:
      open_delim = delim
    elif (
        delim[0] == open_delim[0]
        and len(delim) >= len(open_delim)
        and not info.strip()
    ):
      open_delim = ""
  return f"{text}\n{open_delim}" if open_delim else text


def truncate_comment_body(body: str, reserved: int = 0) -> str:
  """Trims a comment body to GitHub's maximum length, appending a notice.

  Runner output is untrusted and unbounded, so every body is passed through
  here before posting. Truncation happens on a line boundary and any code
  fence left open by the cut is closed so the rest of the comment renders.
  """
  limit = MAX_COMMENT_BODY_CHARS - reserved
  if len(body) <= limit:
    return body

  head = body[: limit - len(_TRUNCATION_NOTICE) - _TRUNCATION_SLACK]
  last_newline = head.rfind("\n")
  if last_newline > 0:
    head = head[:last_newline]
  result = _terminate_open_fence(head) + _TRUNCATION_NOTICE
  return result if len(result) <= limit else result[:limit]


def _headers(token: str) -> dict:
  return {
      "Authorization": f"Bearer {token}",
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
  }


def _find_sticky_comment_id(
    session: requests.Session, token: str, repo: str, pr_number: int
) -> Optional[int]:
  """Returns the id of the existing CodeMender comment on the PR, if any."""
  url: Optional[str] = (
      f"{GITHUB_API_URL}/repos/{repo}/issues/{pr_number}/comments?per_page=100"
  )
  while url:
    resp = session.get(
        url, headers=_headers(token), timeout=_REQUEST_TIMEOUT_SECONDS
    )
    resp.raise_for_status()
    comments = resp.json()
    if not isinstance(comments, list):
      return None
    for comment in comments:
      if STICKY_SUMMARY_MARKER in (comment.get("body") or ""):
        return comment.get("id")
    url = resp.links.get("next", {}).get("url")
  return None


@retry_on_exception(max_tries=3, initial_delay=3, backoff_factor=2)
def _post_or_update_sticky_comment_api(
    token: str, repo: str, pr_number: int, body: str
) -> Optional[str]:
  """Creates or updates the single marker-tagged CodeMender comment on a PR."""
  marked_body = f"{STICKY_SUMMARY_MARKER}\n" + truncate_comment_body(
      body, reserved=len(STICKY_SUMMARY_MARKER) + 1
  )

  with requests.Session() as session:
    existing_id = _find_sticky_comment_id(session, token, repo, pr_number)
    if existing_id is not None:
      resp = session.patch(
          f"{GITHUB_API_URL}/repos/{repo}/issues/comments/{existing_id}",
          headers=_headers(token),
          json={"body": marked_body},
          timeout=_REQUEST_TIMEOUT_SECONDS,
      )
    else:
      resp = session.post(
          f"{GITHUB_API_URL}/repos/{repo}/issues/{pr_number}/comments",
          headers=_headers(token),
          json={"body": marked_body},
          timeout=_REQUEST_TIMEOUT_SECONDS,
      )
    resp.raise_for_status()

  comment_url = resp.json().get("html_url")
  logger.info(
      "%s CodeMender comment on PR #%d: %s",
      "Updated" if existing_id is not None else "Posted",
      pr_number,
      comment_url,
  )
  return comment_url


def post_or_update_sticky_comment(
    token: str, repo: str, pr_number: int, body: str
) -> Optional[str]:
  """Posts or updates the CodeMender PR comment. Never raises.

  Args:
    token: GitHub token with `pull-requests: write`.
    repo: Repository in `owner/name` form (e.g. `$GITHUB_REPOSITORY`).
    pr_number: Pull request number.
    body: Markdown body. Truncated to GitHub's limit if needed.

  Returns:
    The comment's HTML URL, or None if posting failed (failure is logged).
  """
  try:
    return _post_or_update_sticky_comment_api(token, repo, pr_number, body)
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.warning("Failed to post CodeMender comment on PR #%d: %s", pr_number, e)
    return None
