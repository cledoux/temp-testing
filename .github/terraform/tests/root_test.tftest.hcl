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

# Governing: docs/openspec/specs/wif/spec.md#req-0001, docs/openspec/specs/wif/spec.md#req-0002, docs/openspec/specs/wif/spec.md#req-0005, docs/openspec/specs/wif/spec.md#req-0007

mock_provider "google" {}
mock_provider "google-beta" {}
mock_provider "github" {}

variables {
  gcp_project_id = "test-codemender-project"
  gcp_region     = "us-central1"
  github_owner   = "test-org"
}

run "default_local_mode" {
  command = plan

  assert {
    condition     = output.execution_mode == "local"
    error_message = "Default execution_mode must be 'local'."
  }

  assert {
    condition     = local.use_github_app_auth == false
    error_message = "Expected local.use_github_app_auth to be false when GitHub App variables are not provided."
  }
}

run "github_app_auth" {
  command = plan

  variables {
    github_app_id              = "123456"
    github_app_installation_id = "7891011"
    github_app_pem_file        = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
  }

  assert {
    condition     = local.use_github_app_auth == true
    error_message = "Expected local.use_github_app_auth to be true when GitHub App variables are provided."
  }
}
