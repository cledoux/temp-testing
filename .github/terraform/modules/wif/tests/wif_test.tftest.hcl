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

# Governing: SPEC-WIF, REQ-0001, REQ-0002, REQ-0003, REQ-0004, REQ-0005, REQ-0006, REQ-0007
# Hermetic unit tests for GCP Workload Identity Federation (WIF) and GitHub setup
mock_provider "google" {}
mock_provider "github" {}

variables {
  gcp_project_id      = "test-codemender-project"
  gcp_region          = "global"
  github_owner        = "test-org"
  github_app_id       = "123456"
  github_repositories = ["repo-a", "test-org/repo-b"]
}

run "default_local_mode_wif_and_github_resources" {
  command = plan

  assert {
    condition     = output.execution_mode == "local"
    error_message = "Default execution_mode must be 'local'."
  }

  assert {
    condition     = google_service_account.runner_sa.account_id == "codemender-wif-sa"
    error_message = "Runner Service Account ID does not match expected default 'codemender-wif-sa'."
  }

  assert {
    condition     = google_iam_workload_identity_pool.github_pool.workload_identity_pool_id == "codemender-wif-pool"
    error_message = "Workload Identity Pool ID does not match expected default 'codemender-wif-pool'."
  }

  assert {
    condition     = google_iam_workload_identity_pool_provider.github_provider.workload_identity_pool_provider_id == "codemender-wif-provider"
    error_message = "Workload Identity Provider ID does not match expected default 'codemender-wif-provider'."
  }

  assert {
    condition     = google_iam_workload_identity_pool_provider.github_provider.attribute_condition == "assertion.repository_owner == 'test-org'"
    error_message = "Provider attribute condition does not match expected org scoping."
  }

  assert {
    condition     = contains(keys(google_project_service.enabled_apis), "aiplatform.googleapis.com")
    error_message = "Local execution mode must enable aiplatform.googleapis.com."
  }

  assert {
    condition     = !contains(keys(google_project_service.enabled_apis), "run.googleapis.com") && !contains(keys(google_project_service.enabled_apis), "storage.googleapis.com")
    error_message = "Local execution mode must not enable run.googleapis.com or storage.googleapis.com."
  }

  assert {
    condition     = length(google_project_iam_member.vertex_ai_user) == 1 && google_project_iam_member.vertex_ai_user[0].role == "roles/aiplatform.user"
    error_message = "Runner Service Account must be granted Vertex AI User role in local mode."
  }

  assert {
    condition     = length(google_service_account_iam_member.wif_user_org_binding) == 1
    error_message = "Org-scoped WIF binding must be created."
  }

  assert {
    condition     = length(github_issue_label.codemender_scan) == 2
    error_message = "Label 'codemender-scan' must be created for both target repositories."
  }

  assert {
    condition     = length(github_actions_secret.wif_provider) == 2
    error_message = "GCP_WORKLOAD_IDENTITY_PROVIDER secret must be created for both target repositories."
  }

  assert {
    condition     = length(github_actions_secret.runner_sa) == 2
    error_message = "GCP_SERVICE_ACCOUNT secret must be created for both target repositories."
  }

  assert {
    condition     = length(github_actions_secret.app_id) == 2
    error_message = "GH_APP_ID secret must be created for both target repositories."
  }

  assert {
    condition     = length(google_project_iam_member.cloud_run_job_caller_binding) == 0
    error_message = "Cloud Run caller role binding must not be created in local mode."
  }

  assert {
    condition     = length(google_storage_bucket_iam_member.transit_bucket_access) == 0
    error_message = "Transit bucket IAM binding must not be created in local mode."
  }

  assert {
    condition     = length(google_service_account_iam_member.cloud_run_runtime_sa_act_as) == 0
    error_message = "Cloud Run runtime SA actAs bindings must not be created in local mode."
  }

  assert {
    condition     = length(github_actions_variable.gcs_transit_bucket) == 0 && length(github_actions_variable.cloud_run_job_name) == 0 && length(github_actions_variable.gcp_region) == 0
    error_message = "Cloud Run GitHub repository variables must not be created in local mode."
  }
}

run "cloud_run_execution_mode_iam_and_github_variables" {
  command = plan

  override_resource {
    target          = google_service_account.runner_sa
    override_during = plan
    values = {
      name  = "projects/test-codemender-project/serviceAccounts/codemender-wif-sa@test-codemender-project.iam.gserviceaccount.com"
      email = "codemender-wif-sa@test-codemender-project.iam.gserviceaccount.com"
    }
  }

  variables {
    execution_mode          = "cloud_run"
    gcp_region              = "us-central1"
    gcs_transit_bucket_name = "cm-transit-bucket"
    cloud_run_job_name      = "codemender-runner"
    cloud_run_runtime_sa_emails = [
      "codemender-runner-sa@test-codemender-project.iam.gserviceaccount.com",
      "codemender-worker-sa@test-codemender-project.iam.gserviceaccount.com",
    ]
  }

  assert {
    condition     = output.execution_mode == "cloud_run"
    error_message = "execution_mode output must reflect 'cloud_run'."
  }

  assert {
    condition     = contains(keys(google_project_service.enabled_apis), "run.googleapis.com") && contains(keys(google_project_service.enabled_apis), "storage.googleapis.com")
    error_message = "Cloud Run execution mode must enable run.googleapis.com and storage.googleapis.com."
  }

  assert {
    condition     = !contains(keys(google_project_service.enabled_apis), "aiplatform.googleapis.com")
    error_message = "Cloud Run execution mode must not enable aiplatform.googleapis.com in terraform/wif."
  }

  assert {
    condition     = length(google_project_iam_member.vertex_ai_user) == 0
    error_message = "WIF Service Account must not be granted roles/aiplatform.user in cloud_run mode."
  }

  assert {
    condition     = length(google_project_iam_member.cloud_run_job_caller_binding) == 1 && google_project_iam_member.cloud_run_job_caller_binding[0].role == "roles/run.developer"
    error_message = "Predefined roles/run.developer must be bound to the WIF Service Account in cloud_run mode."
  }

  assert {
    condition     = length(google_storage_bucket_iam_member.transit_bucket_access) == 1 && google_storage_bucket_iam_member.transit_bucket_access[0].bucket == "cm-transit-bucket" && google_storage_bucket_iam_member.transit_bucket_access[0].role == "roles/storage.objectUser"
    error_message = "WIF Service Account must be granted roles/storage.objectUser on the GCS transit bucket."
  }

  assert {
    condition     = length(google_service_account_iam_member.cloud_run_runtime_sa_act_as) == 2 && alltrue([for b in google_service_account_iam_member.cloud_run_runtime_sa_act_as : b.role == "roles/iam.serviceAccountUser"])
    error_message = "WIF Service Account must be granted roles/iam.serviceAccountUser on both Cloud Run runtime Service Accounts."
  }

  assert {
    condition     = length(github_actions_variable.gcs_transit_bucket) == 2 && github_actions_variable.gcs_transit_bucket["repo-a"].value == "cm-transit-bucket"
    error_message = "GCS_TRANSIT_BUCKET repository variable must be configured on both target repositories."
  }

  assert {
    condition     = length(github_actions_variable.cloud_run_job_name) == 2 && github_actions_variable.cloud_run_job_name["repo-a"].value == "codemender-runner"
    error_message = "CLOUD_RUN_JOB_NAME repository variable must be configured on both target repositories."
  }

  assert {
    condition     = length(github_actions_variable.gcp_region) == 2 && github_actions_variable.gcp_region["repo-a"].value == "us-central1"
    error_message = "GCP_REGION repository variable must be configured on both target repositories."
  }
}

run "repository_list_scoping" {
  command = plan

  variables {
    github_scope_type   = "repositories"
    github_repositories = ["repo-a", "test-org/repo-b"]
  }

  assert {
    condition     = google_iam_workload_identity_pool_provider.github_provider.attribute_condition == "assertion.repository in [\"test-org/repo-a\",\"test-org/repo-b\"]"
    error_message = "Provider attribute condition does not match expected repository list scoping."
  }

  assert {
    condition     = length(google_service_account_iam_member.wif_user_org_binding) == 0
    error_message = "Org-scoped WIF IAM binding must not be created when github_scope_type is 'repositories'."
  }

  assert {
    condition     = length(google_service_account_iam_member.wif_repo_binding) == 2 && contains(keys(google_service_account_iam_member.wif_repo_binding), "test-org/repo-a") && contains(keys(google_service_account_iam_member.wif_repo_binding), "test-org/repo-b")
    error_message = "Per-repository WIF IAM bindings must be created for each normalized full repository name."
  }

  assert {
    condition     = length(github_issue_label.codemender_scan) == 2 && contains(keys(github_issue_label.codemender_scan), "repo-a") && contains(keys(github_issue_label.codemender_scan), "repo-b")
    error_message = "Labels must be created based on short_repo_names."
  }
}

run "repositories_scope_requires_non_empty_github_repositories" {
  command = plan

  variables {
    github_scope_type   = "repositories"
    github_repositories = []
  }

  expect_failures = [
    var.github_repositories,
  ]
}

run "cloud_run_mode_requires_gcs_transit_bucket_name" {
  command = plan

  variables {
    execution_mode          = "cloud_run"
    gcs_transit_bucket_name = ""
  }

  expect_failures = [
    var.gcs_transit_bucket_name,
  ]
}

run "invalid_execution_mode_rejected" {
  command = plan

  variables {
    execution_mode = "gke"
  }

  expect_failures = [
    var.execution_mode,
  ]
}
