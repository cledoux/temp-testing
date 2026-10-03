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

# Governing: SPEC-WIF, REQ-0006

locals {
  # Extract pure repository name if formatted as "owner/repo" or "repo"
  short_repo_names = toset([
    for r in var.github_repositories : element(reverse(split("/", trimspace(r))), 0)
  ])
}

# 1. Create 'codemender-scan' label in target repositories
resource "github_issue_label" "codemender_scan" {
  for_each    = local.short_repo_names
  repository  = each.value
  name        = "codemender-scan"
  description = "Triggers CodeMender automated security scan and remediation"
  color       = "0E8A16"
}

# 2. Configure GCP_WORKLOAD_IDENTITY_PROVIDER secret in target repositories
resource "github_actions_secret" "wif_provider" {
  for_each    = local.short_repo_names
  repository  = each.value
  secret_name = "CODEMENDER_WORKLOAD_IDENTITY_PROVIDER"
  value       = google_iam_workload_identity_pool_provider.github_provider.name
}

# 3. Configure GCP_SERVICE_ACCOUNT secret in target repositories
resource "github_actions_secret" "runner_sa" {
  for_each    = local.short_repo_names
  repository  = each.value
  secret_name = "CODEMENDER_SERVICE_ACCOUNT"
  value       = google_service_account.runner_sa.email
}

# Configure the project for running codemender in.
resource "github_actions_variable" "gcp_project_id" {
  for_each      = local.short_repo_names
  repository    = each.value
  variable_name = "CODEMENDER_GCP_PROJECT_ID"
  value         = var.gcp_project_id
}

# 4. Configure GH_APP_ID secret in target repositories (when provided)
resource "github_actions_secret" "app_id" {
  for_each    = var.github_app_id != "" ? local.short_repo_names : toset([])
  repository  = each.value
  secret_name = "GH_APP_ID"
  value       = var.github_app_id
}

# 5. Configure GCS_TRANSIT_BUCKET repository variable in Cloud Run execution mode
resource "github_actions_variable" "gcs_transit_bucket" {
  for_each      = var.execution_mode == "cloud_run" ? local.short_repo_names : toset([])
  repository    = each.value
  variable_name = "CODEMENDER_GCS_TRANSIT_BUCKET"
  value         = var.gcs_transit_bucket_name
}

# 6. Configure CLOUD_RUN_JOB_NAME repository variable in Cloud Run execution mode (when provided)
resource "github_actions_variable" "cloud_run_job_name" {
  for_each      = (var.execution_mode == "cloud_run" && var.cloud_run_job_name != "") ? local.short_repo_names : toset([])
  repository    = each.value
  variable_name = "CODEMENDER_CLOUD_RUN_JOB_NAME"
  value         = var.cloud_run_job_name
}

# 7. Configure GCP_REGION repository variable in Cloud Run execution mode (when non-default)
resource "github_actions_variable" "gcp_region" {
  for_each      = (var.execution_mode == "cloud_run" && var.gcp_region != "" && var.gcp_region != "global") ? local.short_repo_names : toset([])
  repository    = each.value
  variable_name = "GCP_REGION"
  value         = var.gcp_region
}
