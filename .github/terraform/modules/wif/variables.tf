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

# Governing: SPEC-WIF, REQ-0001, REQ-0002, REQ-0005

# --- GCP Infrastructure Variables ---

variable "gcp_project_id" {
  type        = string
  description = "The GCP Project ID hosting Vertex AI or Cloud Run Jobs."
}

variable "gcp_region" {
  type        = string
  default     = "global"
  description = "The GCP region for resource deployment."
}

variable "gcp_service_account_id" {
  type        = string
  default     = "codemender-wif-sa"
  description = "ID of the dedicated Service Account to create for CodeMender WIF authentication in GCP."
}

variable "gcp_wif_pool_id" {
  type        = string
  default     = "codemender-wif-pool"
  description = "ID of the Workload Identity Pool to create in GCP."
}

variable "gcp_wif_provider_id" {
  type        = string
  default     = "codemender-wif-provider"
  description = "ID of the Workload Identity Provider to create in GCP."
}

# --- Execution Mode & Cloud Run Composition (SPEC-WIF, REQ-0002, REQ-0005) ---

variable "execution_mode" {
  type        = string
  default     = "local"
  description = "Execution mode for GitHub Actions workflows: 'local' (runs cm-runner on runner with Vertex AI access) or 'cloud_run' (stages repository to GCS transit bucket and invokes Cloud Run Job)."

  validation {
    condition     = contains(["local", "cloud_run"], var.execution_mode)
    error_message = "execution_mode must be either 'local' or 'cloud_run'."
  }
}

variable "gcs_transit_bucket_name" {
  type        = string
  default     = ""
  description = "Name of the GCS transit bucket (e.g. reports_bucket_name from terraform/gcp) used for source snapshot staging and receipt retrieval when execution_mode is 'cloud_run'."

  validation {
    condition     = var.execution_mode != "cloud_run" || length(trimspace(var.gcs_transit_bucket_name)) > 0
    error_message = "gcs_transit_bucket_name is required when execution_mode is 'cloud_run'."
  }
}

variable "cloud_run_runtime_sa_emails" {
  type        = list(string)
  default     = []
  description = "List of Cloud Run Job runtime Service Account email addresses (e.g. runner_service_account_email and worker_service_account_email from terraform/gcp) that the WIF Service Account is authorized to actAs (roles/iam.serviceAccountUser) when execution_mode is 'cloud_run'."
}

variable "cloud_run_job_name" {
  type        = string
  default     = ""
  description = "Optional Cloud Run Job name (e.g. runner_job_name from terraform/gcp) to configure as CLOUD_RUN_JOB_NAME repository variable when execution_mode is 'cloud_run'."
}

# --- Workload Identity Federation (WIF) Scoping ---

variable "github_scope_type" {
  type        = string
  default     = "org"
  description = "Scoping type for WIF authentication: 'org' (all repos in org), 'user' (all repos under user), or 'repositories' (specific repo allowlist)."

  validation {
    condition     = contains(["org", "user", "repositories"], var.github_scope_type)
    error_message = "github_scope_type must be one of: 'org', 'user', 'repositories'."
  }
}

variable "github_owner" {
  type        = string
  default     = ""
  description = "GitHub organization name (e.g. 'my-org') or username (e.g. 'octocat'). Required if github_scope_type is 'org' or 'user'."
}

variable "github_repositories" {
  type        = list(string)
  default     = []
  description = "List of target GitHub repositories in 'repo' or 'owner/repo' format."

  validation {
    condition     = var.github_scope_type != "repositories" || length(var.github_repositories) > 0
    error_message = "github_repositories must contain at least one repository when github_scope_type is 'repositories'."
  }
}

# --- GitHub Platform Configuration ---

variable "github_app_id" {
  type        = string
  default     = ""
  description = "Numeric GitHub App ID to automatically populate as GH_APP_ID secret in target repositories."
}
