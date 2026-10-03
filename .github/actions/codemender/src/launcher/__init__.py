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

"""Launchers: how the GitHub Actions side starts cm-runner.

A launcher owns the *outer* boundary around cm-runner (container / VM) and
decides what goes into it (never the GitHub token). cm-runner itself is the
same image and CLI everywhere; only the launcher differs per environment.

M0 ships `LocalDockerLauncher` (docker run on the GitHub Actions VM).
Cloud Run / GKE launchers will implement the same `Launcher` interface.
"""
