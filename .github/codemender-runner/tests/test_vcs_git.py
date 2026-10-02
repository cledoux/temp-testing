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

"""Unit tests for vcs.git module."""

import base64
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vcs.git import (
    diff_working_tree,
    enforce_https_url,
    filter_stageable_files,
    generate_branch_name,
    get_git_auth_header,
    is_git_repository,
    list_uncommitted_paths,
    normalize_repo_relative_path,
    parse_repo_owner_and_name,
    ref_exists,
    sanitize_git_url,
    setup_local_git_excludes,
)



class TestVcsGit(unittest.TestCase):

  def test_get_git_auth_header(self):
    """Verify the generation of HTTP Basic auth header for Git."""
    token = "fake_token"
    header = get_git_auth_header(token)
    expected_token_b64 = base64.b64encode(b"x-access-token:fake_token").decode(
        "utf-8"
    )
    self.assertEqual(
        header, f"http.extraheader=AUTHORIZATION: Basic {expected_token_b64}"
    )

  def test_enforce_https_url(self):
    """Verify SSH git repository URLs are correctly converted to HTTPS."""
    test_cases = [
        (
            "git@github.com:my-org/my-repo.git",
            "https://github.com/my-org/my-repo.git",
        ),
        (
            "ssh://git@github.com/my-org/my-repo.git",
            "https://github.com/my-org/my-repo.git",
        ),
        ("git@github.corp.com:org/repo", "https://github.corp.com/org/repo"),
        ("https://github.com/org/repo.git", "https://github.com/org/repo.git"),
    ]
    for url, expected in test_cases:
      with self.subTest(url=url):
        self.assertEqual(enforce_https_url(url), expected)

  def test_sanitize_git_url(self):
    """Verify embedded credentials and parameters are removed from Git URLs."""
    test_cases = [
        (
            "https://github.com/my-org/my-repo.git",
            "https://github.com/my-org/my-repo.git",
        ),
        (
            "https://x-access-token:token123@github.com/my-org/my-repo.git",
            "https://github.com/my-org/my-repo.git",
        ),
        (
            "http://user:pass@github.corp.com:8443/org/repo?branch=main#readme",
            "http://github.corp.com:8443/org/repo",
        ),
        ("git@github.com:org/repo.git", "https://github.com/org/repo.git"),
    ]
    for url, expected in test_cases:
      with self.subTest(url=url):
        self.assertEqual(sanitize_git_url(url), expected)

  def test_parse_repo_owner_and_name(self):
    """Verify parsing owner and repo name from GitHub URLs."""
    owner, repo = parse_repo_owner_and_name(
        "https://github.com/my-org/my-repo.git"
    )
    self.assertEqual(owner, "my-org")
    self.assertEqual(repo, "my-repo")

  def test_generate_branch_name(self):
    """Verify creation of idempotent branch names."""
    branch = generate_branch_name("SQL Injection", "abcdef1234567890")
    self.assertEqual(branch, "codemender/fix-sql-injection-abcdef12")



  def test_normalize_repo_relative_path(self):
    """Verify normalize_repo_relative_path strips leading CI runner mount patterns and paths."""
    test_cases = [
        (
            "/__w/juice-shop-local/juice-shop-local/juice-shop-local/routes/profileImageUrlUpload.ts",
            "/__w/juice-shop-local/juice-shop-local/juice-shop-local",
            "routes/profileImageUrlUpload.ts",
        ),
        (
            "/__w/juice-shop-local/juice-shop-local/juice-shop-local/routes/profileImageUrlUpload.ts",
            None,
            "routes/profileImageUrlUpload.ts",
        ),
        (
            "/workspace/juice-shop-local/routes/profileImageUrlUpload.ts",
            "/workspace/juice-shop-local",
            "routes/profileImageUrlUpload.ts",
        ),
        (
            "/github/workspace/routes/profileImageUrlUpload.ts",
            None,
            "routes/profileImageUrlUpload.ts",
        ),
        (
            "./routes/profileImageUrlUpload.ts",
            None,
            "routes/profileImageUrlUpload.ts",
        ),
        (
            "routes/profileImageUrlUpload.ts",
            None,
            "routes/profileImageUrlUpload.ts",
        ),
    ]
    for path, repo_dir, expected in test_cases:
      with self.subTest(path=path, repo_dir=repo_dir):
        self.assertEqual(normalize_repo_relative_path(path, repo_dir=repo_dir), expected)

  def test_setup_local_git_excludes(self):
    """Verify local git excludes are correctly appended without duplicates."""
    with tempfile.TemporaryDirectory() as repo_dir:
      git_info_dir = os.path.join(repo_dir, ".git", "info")
      os.makedirs(git_info_dir, exist_ok=True)
      exclude_path = os.path.join(git_info_dir, "exclude")

      setup_local_git_excludes(repo_dir)

      self.assertTrue(os.path.exists(exclude_path))
      with open(exclude_path, "r") as f:
        content = f.read()

      self.assertIn(".cm_project", content)
      self.assertIn(".exploit", content)
      self.assertIn(".codemender_cache", content)

  def test_sanitize_exploit_and_artifacts(self):
    """Verify sanitize_exploit_and_artifacts removes junk build caches while preserving exploit files."""
    from vcs.git import sanitize_exploit_and_artifacts

    with tempfile.TemporaryDirectory() as repo_dir:
      with tempfile.TemporaryDirectory() as cm_home:
        # Create .exploit directory with valid files and junk build directories
        exploit_dir = os.path.join(repo_dir, ".exploit")
        os.makedirs(os.path.join(exploit_dir, ".cache", "node-gyp", "node"), exist_ok=True)
        os.makedirs(os.path.join(exploit_dir, "node_modules", "express"), exist_ok=True)
        os.makedirs(os.path.join(exploit_dir, "venv", "bin"), exist_ok=True)
        os.makedirs(os.path.join(exploit_dir, "__pycache__"), exist_ok=True)

        valid_poc = os.path.join(exploit_dir, "exploit.py")
        valid_payload = os.path.join(exploit_dir, "payload.json")
        with open(valid_poc, "w") as f:
          f.write("print('poc')")
        with open(valid_payload, "w") as f:
          f.write("{}")

        # Create artifacts directory with junk build cache
        artifacts_dir = os.path.join(cm_home, "artifacts", "finding_123")
        os.makedirs(os.path.join(artifacts_dir, ".cache"), exist_ok=True)
        os.makedirs(os.path.join(artifacts_dir, "node_modules"), exist_ok=True)
        valid_artifact_file = os.path.join(artifacts_dir, "exploit.py")
        with open(valid_artifact_file, "w") as f:
          f.write("print('poc')")

        sanitize_exploit_and_artifacts(repo_dir, codemender_home=cm_home)

        # Assert valid files are preserved
        self.assertTrue(os.path.exists(valid_poc))
        self.assertTrue(os.path.exists(valid_payload))
        self.assertTrue(os.path.exists(valid_artifact_file))

        # Assert junk directories are removed
        self.assertFalse(os.path.exists(os.path.join(exploit_dir, ".cache")))
        self.assertFalse(os.path.exists(os.path.join(exploit_dir, "node_modules")))
        self.assertFalse(os.path.exists(os.path.join(exploit_dir, "venv")))
        self.assertFalse(os.path.exists(os.path.join(exploit_dir, "__pycache__")))
        self.assertFalse(os.path.exists(os.path.join(artifacts_dir, ".cache")))
        self.assertFalse(os.path.exists(os.path.join(artifacts_dir, "node_modules")))

  @unittest.skipUnless(
      os.path.exists(
          os.path.join(
              os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
              "utils.py",
          )
      ),
      "requires legacy utils.py",
  )
  def test_filter_stageable_files(self):
    """Verify filter_stageable_files normalizes, deduplicates, and excludes metadata and ignored files."""
    with tempfile.TemporaryDirectory() as repo_dir:
      # Initialize git repository
      subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
      setup_local_git_excludes(repo_dir)

      # Create user repository .gitignore
      with open(os.path.join(repo_dir, ".gitignore"), "w") as f:
        f.write("*.log\nnode_modules/\n")

      # Create valid source file and directories
      routes_dir = os.path.join(repo_dir, "routes")
      os.makedirs(routes_dir, exist_ok=True)
      valid_source = os.path.join(routes_dir, "userProfile.ts")
      with open(valid_source, "w") as f:
        f.write("console.log('profile');")

      # Create exploit directory and exploit script
      exploit_dir = os.path.join(repo_dir, ".exploit")
      os.makedirs(exploit_dir, exist_ok=True)
      exploit_file = os.path.join(exploit_dir, "exploit.sh")
      with open(exploit_file, "w") as f:
        f.write("#!/bin/bash\necho evil")

      # Create internal metadata directories and files
      cm_project_dir = os.path.join(repo_dir, ".cm_project")
      os.makedirs(cm_project_dir, exist_ok=True)
      with open(os.path.join(cm_project_dir, "state.json"), "w") as f:
        f.write("{}")

      # Create git-ignored log file
      with open(os.path.join(repo_dir, "debug.log"), "w") as f:
        f.write("debug")

      raw_edited_files = [
          # Duplicates of absolute path
          valid_source,
          valid_source,
          # CI runner mount path pattern
          f"/__w/juice-shop-local/juice-shop-local/juice-shop-local/routes/userProfile.ts",
          # Relative path with ./
          "./routes/userProfile.ts",
          # Exploit paths (MUST be excluded)
          exploit_file,
          f"/__w/juice-shop-local/juice-shop-local/juice-shop-local/.exploit/exploit.sh",
          ".exploit/exploit.sh",
          # Internal metadata paths (MUST be excluded)
          ".cm_project/state.json",
          ".codemender_cache/cache.dat",
          ".codemender/config.yaml",
          # Git-ignored file (*.log)
          "debug.log",
          # Non-existent file
          "routes/non_existent.ts",
          # Falsy / invalid items
          "",
          None,
      ]

      stageable = filter_stageable_files(repo_dir, raw_edited_files)

      # Should only contain 'routes/userProfile.ts' exactly once
      self.assertEqual(stageable, ["routes/userProfile.ts"])

  def test_is_git_repository(self):
    """Verify is_git_repository identifies valid Git worktrees and subdirectories and rejects non-Git paths."""
    with tempfile.TemporaryDirectory() as non_git_dir:
      self.assertFalse(is_git_repository(non_git_dir))
      self.assertFalse(is_git_repository(os.path.join(non_git_dir, "does_not_exist")))
      self.assertFalse(is_git_repository(""))

    with tempfile.TemporaryDirectory() as repo_dir:
      subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
      self.assertTrue(is_git_repository(repo_dir))

      sub_dir = os.path.join(repo_dir, "nested", "subdir")
      os.makedirs(sub_dir, exist_ok=True)
      self.assertTrue(is_git_repository(sub_dir))

  def test_ref_exists(self):
    """Verify ref_exists resolves valid commit refs and rejects missing, malformed, or flag-like refs."""
    with tempfile.TemporaryDirectory() as repo_dir:
      self.assertFalse(ref_exists(os.path.join(repo_dir, "nonexistent_dir"), "HEAD"))
      self.assertFalse(ref_exists("", "HEAD"))

      subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
      subprocess.run(
          ["git", "config", "user.name", "Test"],
          cwd=repo_dir,
          check=True,
          capture_output=True,
      )
      subprocess.run(
          ["git", "config", "user.email", "test@example.com"],
          cwd=repo_dir,
          check=True,
          capture_output=True,
      )

      with open(os.path.join(repo_dir, "README.md"), "w") as f:
        f.write("# Test\n")
      subprocess.run(
          ["git", "add", "README.md"], cwd=repo_dir, check=True, capture_output=True
      )
      subprocess.run(
          ["git", "commit", "-m", "initial commit"],
          cwd=repo_dir,
          check=True,
          capture_output=True,
      )

      # Create a branch and a tag
      subprocess.run(
          ["git", "branch", "feature-branch"],
          cwd=repo_dir,
          check=True,
          capture_output=True,
      )
      subprocess.run(
          ["git", "tag", "v1.0.0"],
          cwd=repo_dir,
          check=True,
          capture_output=True,
      )

      sha_res = subprocess.run(
          ["git", "rev-parse", "HEAD"],
          cwd=repo_dir,
          check=True,
          capture_output=True,
          text=True,
      )
      full_sha = sha_res.stdout.strip()
      short_sha = full_sha[:7]

      # Valid references
      self.assertTrue(ref_exists(repo_dir, "HEAD"))
      self.assertTrue(ref_exists(repo_dir, "feature-branch"))
      self.assertTrue(ref_exists(repo_dir, "v1.0.0"))
      self.assertTrue(ref_exists(repo_dir, full_sha))
      self.assertTrue(ref_exists(repo_dir, short_sha))

      # Invalid / missing references
      self.assertFalse(ref_exists(repo_dir, "origin/nonexistent"))
      self.assertFalse(ref_exists(repo_dir, "origin/..bad..ref"))
      self.assertFalse(ref_exists(repo_dir, ""))
      self.assertFalse(ref_exists(repo_dir, "   "))
      self.assertFalse(ref_exists(repo_dir, "--help"))
      self.assertFalse(ref_exists(repo_dir, "-q"))



class TestWorkingTreeHelpers(unittest.TestCase):
  """`list_uncommitted_paths` and `diff_working_tree`, used by `cm-runner fix`."""

  _EXCLUDE = (".cm_project", ".exploit")

  def setUp(self):
    super().setUp()
    self.repo = tempfile.mkdtemp(prefix="cm_runner_worktree_")
    self.addCleanup(shutil.rmtree, self.repo, True)
    self.git("init", "-q")
    self.git("config", "user.name", "Test User")
    self.git("config", "user.email", "test@example.com")
    self.git("config", "core.autocrlf", "false")
    self.write("app.py", b"x = 1\n")
    self.write("crlf.txt", b"one\r\ntwo\r\n")
    self.write("sub/old.py", b"y = 2\n")
    self.write(".gitignore", b"*.log\n")
    self.git("add", ".")
    self.git("commit", "-q", "-m", "init")

  def git(self, *args):
    return subprocess.run(
        ["git", *args], cwd=self.repo, check=True, capture_output=True,
        timeout=30,
    ).stdout

  def write(self, path, data):
    full = os.path.join(self.repo, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as handle:
      handle.write(data)

  def test_clean_tree_with_only_excluded_and_ignored_files(self):
    self.write(".cm_project", b"{}")
    self.write(".exploit/poc.sh", b"#!/bin/sh\n")
    self.write("debug.log", b"noise\n")
    self.assertEqual(list_uncommitted_paths(self.repo, self._EXCLUDE), [])
    self.assertEqual(diff_working_tree(self.repo, self._EXCLUDE), b"")

  def test_lists_modified_staged_untracked_and_renamed(self):
    self.write("app.py", b"x = 3\n")
    self.write("new.py", b"z = 4\n")
    self.git("mv", "sub/old.py", "sub/renamed.py")
    self.write(".cm_project", b"{}")
    self.assertEqual(
        sorted(list_uncommitted_paths(self.repo, self._EXCLUDE)),
        ["app.py", "new.py", "sub/renamed.py"],
    )

  def test_not_a_repository(self):
    plain = tempfile.mkdtemp(prefix="cm_runner_plain_")
    self.addCleanup(shutil.rmtree, plain, True)
    with self.assertLogs("codemender-orchestrator", level="ERROR"):
      self.assertIsNone(list_uncommitted_paths(plain))
      self.assertIsNone(diff_working_tree(plain))

  def test_patch_round_trips_byte_for_byte(self):
    self.write("app.py", b"x = 3\n")
    self.write("crlf.txt", b"one\r\nTWO\r\n")
    self.write("new.py", b"z = 4\n")
    self.write("blob.bin", bytes(range(256)))
    self.write(".cm_project", b"{}")
    self.write(".exploit/poc.sh", b"#!/bin/sh\n")

    patch = diff_working_tree(self.repo, self._EXCLUDE)

    self.assertIn(b"one\r\n-two\r\n+TWO\r\n", patch)
    self.assertNotIn(b".cm_project", patch)
    self.assertNotIn(b".exploit", patch)
    clone = tempfile.mkdtemp(prefix="cm_runner_clone_")
    self.addCleanup(shutil.rmtree, clone, True)
    subprocess.run(
        ["git", "clone", "-q", "-c", "core.autocrlf=false", self.repo, clone],
        check=True, capture_output=True, timeout=30,
    )
    subprocess.run(
        ["git", "apply", "-"], cwd=clone, input=patch, check=True,
        capture_output=True, timeout=30,
    )
    for name in ("app.py", "crlf.txt", "new.py", "blob.bin"):
      with self.subTest(file=name):
        with open(os.path.join(clone, name), "rb") as got, open(
            os.path.join(self.repo, name), "rb"
        ) as want:
          self.assertEqual(got.read(), want.read())

  def test_new_file_contents_are_not_staged(self):
    self.write("new.py", b"z = 4\n")
    diff_working_tree(self.repo, self._EXCLUDE)
    self.assertEqual(self.git("diff", "--cached"), b"")
    self.assertEqual(self.git("ls-files", "new.py").strip(), b"new.py")

  def test_user_git_config_cannot_change_the_format(self):
    for key, value in (
        ("color.diff", "always"),
        ("diff.noprefix", "true"),
        ("diff.mnemonicPrefix", "true"),
        ("diff.relative", "true"),
    ):
      self.git("config", key, value)
    self.write("app.py", b"x = 3\n")
    patch = diff_working_tree(os.path.join(self.repo), self._EXCLUDE)
    self.assertTrue(patch.startswith(b"diff --git a/app.py b/app.py\n"), patch)
    self.assertNotIn(b"\x1b[", patch)


if __name__ == "__main__":
  unittest.main()
