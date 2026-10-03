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

"""Unit tests for github-actions vcs.github (sticky PR comment)."""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from vcs import github  # pylint: disable=g-import-not-at-top
from vcs.github import (  # pylint: disable=g-import-not-at-top
    MAX_COMMENT_BODY_CHARS,
    STICKY_SUMMARY_MARKER,
    post_or_update_sticky_comment,
    truncate_comment_body,
)


def _response(json_body, links=None):
  resp = MagicMock()
  resp.json.return_value = json_body
  resp.links = links or {}
  resp.raise_for_status.return_value = None
  return resp


class TestTruncateCommentBody(unittest.TestCase):

  def test_short_body_unchanged(self):
    self.assertEqual(truncate_comment_body("hello"), "hello")

  def test_long_body_truncated_within_limit_with_notice(self):
    body = "line\n" * (MAX_COMMENT_BODY_CHARS // 2)
    result = truncate_comment_body(body)
    self.assertLessEqual(len(result), MAX_COMMENT_BODY_CHARS)
    self.assertIn("truncated", result)

  def test_open_code_fence_is_closed(self):
    body = "```\n" + ("x\n" * MAX_COMMENT_BODY_CHARS)
    result = truncate_comment_body(body)
    before_notice = result.split("\n\n---\n")[0]
    self.assertEqual(before_notice.count("```") % 2, 0)


@patch.object(github.time, "sleep", lambda _: None)
class TestStickyComment(unittest.TestCase):

  @patch.object(github.requests, "Session")
  def test_posts_new_comment_when_none_exists(self, mock_session_cls):
    session = mock_session_cls.return_value.__enter__.return_value
    session.get.return_value = _response([{"id": 1, "body": "unrelated"}])
    session.post.return_value = _response({"html_url": "https://x/c/2"})

    url = post_or_update_sticky_comment("tok", "o/r", 7, "hi")

    self.assertEqual(url, "https://x/c/2")
    session.patch.assert_not_called()
    post_url = session.post.call_args.args[0]
    self.assertTrue(post_url.endswith("/repos/o/r/issues/7/comments"))
    body = session.post.call_args.kwargs["json"]["body"]
    self.assertTrue(body.startswith(STICKY_SUMMARY_MARKER))
    self.assertIn("hi", body)
    headers = session.post.call_args.kwargs["headers"]
    self.assertEqual(headers["Authorization"], "Bearer tok")

  @patch.object(github.requests, "Session")
  def test_updates_existing_marked_comment(self, mock_session_cls):
    session = mock_session_cls.return_value.__enter__.return_value
    session.get.return_value = _response(
        [{"id": 42, "body": f"{STICKY_SUMMARY_MARKER}\nold"}]
    )
    session.patch.return_value = _response({"html_url": "https://x/c/42"})

    url = post_or_update_sticky_comment("tok", "o/r", 7, "new")

    self.assertEqual(url, "https://x/c/42")
    session.post.assert_not_called()
    self.assertTrue(
        session.patch.call_args.args[0].endswith("/repos/o/r/issues/comments/42")
    )

  @patch.object(github.requests, "Session")
  def test_follows_pagination_to_find_marker(self, mock_session_cls):
    session = mock_session_cls.return_value.__enter__.return_value
    session.get.side_effect = [
        _response([{"id": 1, "body": "a"}], links={"next": {"url": "page2"}}),
        _response([{"id": 99, "body": STICKY_SUMMARY_MARKER}]),
    ]
    session.patch.return_value = _response({"html_url": "https://x/c/99"})

    self.assertEqual(
        post_or_update_sticky_comment("tok", "o/r", 7, "b"), "https://x/c/99"
    )
    self.assertEqual(session.get.call_args_list[1].args[0], "page2")

  @patch.object(github.requests, "Session")
  def test_never_raises_and_returns_none_on_failure(self, mock_session_cls):
    session = mock_session_cls.return_value.__enter__.return_value
    session.get.side_effect = RuntimeError("boom")

    self.assertIsNone(post_or_update_sticky_comment("tok", "o/r", 7, "b"))
    self.assertEqual(session.get.call_count, 3)  # retried


if __name__ == "__main__":
  unittest.main()
