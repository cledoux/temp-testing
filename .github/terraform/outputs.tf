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

# Governing: docs/openspec/specs/wif/spec.md#req-0001, docs/openspec/specs/wif/spec.md#req-0005

output "gcp_workload_identity_provider" {
  description = "Full resource name of the Workload Identity Provider for GitHub Actions secret GCP_WORKLOAD_IDENTITY_PROVIDER."
  value       = module.wif.gcp_workload_identity_provider
}

output "gcp_service_account" {
  description = "Service Account email for GitHub Actions secret GCP_SERVICE_ACCOUNT."
  value       = module.wif.gcp_service_account
}

output "execution_mode" {
  description = "Configured CodeMender execution mode ('local' or 'cloud_run')."
  value       = module.wif.execution_mode
}

output "next_step_private_key_injection" {
  description = "One-line command to securely inject the GitHub App Private Key using GitHub CLI without exposing it in Terraform state."
  value       = module.wif.next_step_private_key_injection
}
