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

# Governing: SPEC-WIF, REQ-0001, REQ-0003, REQ-0004

# 1. Dedicated Service Account for CodeMender Runner in GitHub Actions
resource "google_service_account" "runner_sa" {
  project      = var.gcp_project_id
  account_id   = var.gcp_service_account_id
  display_name = "CodeMender GitHub Actions Runner SA"
  description  = "Assumed by GitHub Actions runners via Workload Identity Federation for CodeMender execution"
  depends_on   = [google_project_service.enabled_apis["iam.googleapis.com"]]
}

# 2a. Local Mode: Grant Vertex AI User role for Gemini model inference (REQ-0003)
resource "google_project_iam_member" "vertex_ai_user" {
  count   = var.execution_mode == "local" ? 1 : 0
  project = var.gcp_project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.runner_sa.email}"
}

# 2b. Cloud Run Mode: Predefined Caller IAM, Transit Bucket Access & Runtime SA actAs (REQ-0004)
# Needed so the GitHub Actions WIF caller SA can trigger Cloud Run Job executions with
# per-run container argument/volume overrides (`gcloud run jobs execute --args ... --wait`)
# and poll execution/operation completion status.
resource "google_project_iam_member" "cloud_run_job_caller_binding" {
  count   = var.execution_mode == "cloud_run" ? 1 : 0
  project = var.gcp_project_id
  role    = "roles/run.developer"
  member  = "serviceAccount:${google_service_account.runner_sa.email}"
}

# Needed so the GitHub Actions runner can upload the repository snapshot/findings tarball
# to the GCS transit bucket before job execution and download the execution receipt,
# SARIF report, and patch artifacts afterward.
resource "google_storage_bucket_iam_member" "transit_bucket_access" {
  count  = var.execution_mode == "cloud_run" ? 1 : 0
  bucket = var.gcs_transit_bucket_name
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${google_service_account.runner_sa.email}"
}

# Needed because GCP Cloud Run enforces an `iam.serviceAccounts.actAs` check on the
# Cloud Run Job's attached runtime Service Account whenever a caller invokes
# `run.jobs.run` / `run.jobs.runWithOverrides`.
resource "google_service_account_iam_member" "cloud_run_runtime_sa_act_as" {
  for_each           = var.execution_mode == "cloud_run" ? toset(var.cloud_run_runtime_sa_emails) : toset([])
  service_account_id = "projects/${var.gcp_project_id}/serviceAccounts/${each.value}"
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.runner_sa.email}"
}

# 3. Workload Identity Pool for GitHub Actions (REQ-0001)
resource "google_iam_workload_identity_pool" "github_pool" {
  project                   = var.gcp_project_id
  workload_identity_pool_id = var.gcp_wif_pool_id
  display_name              = "GitHub Actions Pool"
  description               = "OIDC Identity Pool for CodeMender GitHub Actions workflows"
  depends_on                = [google_project_service.enabled_apis["iam.googleapis.com"]]
}

# 4. Workload Identity Pool OIDC Provider with Scoping Conditions (REQ-0001)
locals {
  full_repo_names = [for r in var.github_repositories : strcontains(trimspace(r), "/") ? trimspace(r) : "${var.github_owner}/${trimspace(r)}"]

  # Build attribute condition based on selected scope type
  attribute_condition = (
    var.github_scope_type == "org" || var.github_scope_type == "user"
    ? "assertion.repository_owner == '${var.github_owner}'"
    : "assertion.repository in ${jsonencode(local.full_repo_names)}"
  )

  # Principal set for user or org wide scope
  owner_principal_set = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool.name}/attribute.repository_owner/${var.github_owner}"
}

resource "google_iam_workload_identity_pool_provider" "github_provider" {
  project                            = var.gcp_project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_pool.workload_identity_pool_id
  workload_identity_pool_provider_id = var.gcp_wif_provider_id
  display_name                       = "GitHub Actions Provider"
  description                        = "OIDC Provider for GitHub Actions runners"

  attribute_mapping = {
    "google.subject"             = "assertion.sub"
    "attribute.actor"            = "assertion.actor"
    "attribute.repository"       = "assertion.repository"
    "attribute.repository_owner" = "assertion.repository_owner"
  }

  attribute_condition = local.attribute_condition

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# 5a. Service Account Binding for Org / User Scope (REQ-0001)
resource "google_service_account_iam_member" "wif_user_org_binding" {
  count              = (var.github_scope_type == "org" || var.github_scope_type == "user") ? 1 : 0
  service_account_id = google_service_account.runner_sa.name
  role               = "roles/iam.workloadIdentityUser"
  member             = local.owner_principal_set
}

# 5b. Service Account Binding for Specific Repository List Scope (REQ-0001)
resource "google_service_account_iam_member" "wif_repo_binding" {
  for_each           = var.github_scope_type == "repositories" ? toset(local.full_repo_names) : toset([])
  service_account_id = google_service_account.runner_sa.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool.name}/attribute.repository/${each.value}"
}
