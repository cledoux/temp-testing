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

# Governing: docs/openspec/specs/wif/spec.md#req-0001, docs/openspec/specs/wif/spec.md#req-0002, docs/openspec/specs/wif/spec.md#req-0005

# --- GCP Project & Identity Naming ---

variable "gcp_project_id" {
  type        = string
  description = "The GCP Project ID where resources will be deployed and Vertex AI / Cloud Run Jobs reside."
}

variable "gcp_region" {
  type        = string
  default     = "us-central1"
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

# --- Execution Mode & Cloud Run Inputs ---

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
  description = "Optional override for the GCS transit bucket name. In 'cloud_run' mode, automatically defaults to reports_bucket_name provisioned by module.gcp."
}

variable "cloud_run_job_name" {
  type        = string
  default     = ""
  description = "Optional override for the Cloud Run Job name. In 'cloud_run' mode, automatically defaults to runner_job_name provisioned by module.gcp."
}

variable "cloud_run_runtime_sa_emails" {
  type        = list(string)
  default     = []
  description = "Optional override for Cloud Run Job runtime Service Account email addresses authorized for actAs. In 'cloud_run' mode, automatically defaults to runtime SAs provisioned by module.gcp."
}

# --- Cloud Run Module Pass-Through Variables ---

variable "resource_prefix" {
  type        = string
  default     = "codemender"
  description = "Prefix used for naming provisioned GCP resources to prevent multi-deployment collisions."
}

variable "reports_bucket_name" {
  type        = string
  default     = ""
  description = "Name of the GCS bucket for scan reports and source snapshot staging."
}

variable "runner_cpu" {
  type        = string
  default     = "2000m"
  description = "CPU limit for Cloud Run Job worker tasks (e.g. '2000m', '2', '4')."
}

variable "runner_memory" {
  type        = string
  default     = "4Gi"
  description = "Memory limit for Cloud Run Job worker tasks (e.g. '2Gi', '4Gi', '8Gi')."
}

variable "create_vpc_and_nat" {
  type        = bool
  default     = false
  description = "Whether to create a dedicated VPC network, subnet, connector, and Cloud NAT for private egress."
}

variable "existing_vpc_connector_id" {
  type        = string
  default     = null
  description = "ID of an existing Serverless VPC Access Connector if create_vpc_and_nat is false."
}

variable "vpc_connector_cidr" {
  type        = string
  default     = "10.8.0.0/28"
  description = "CIDR range (/28) for the Serverless VPC Access Connector."

  validation {
    condition     = can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$", var.vpc_connector_cidr))
    error_message = "vpc_connector_cidr must be a valid IPv4 CIDR string (e.g., 10.8.0.0/28)."
  }
}

variable "vpc_connector_min_instances" {
  type        = number
  default     = 2
  description = "Minimum number of instances for the Serverless VPC Access Connector."
}

variable "vpc_connector_max_instances" {
  type        = number
  default     = 3
  description = "Maximum number of instances for the Serverless VPC Access Connector."
}

variable "vpc_connector_machine_type" {
  type        = string
  default     = "e2-micro"
  description = "Machine type for the Serverless VPC Access Connector."
}

variable "scheduler_cron" {
  type        = string
  default     = "0 2 * * *"
  description = "Cron expression for the Cloud Scheduler nightly trigger."
}

# --- WIF Scoping & Target Repositories ---

variable "github_owner" {
  type        = string
  default     = ""
  description = "GitHub organization name (e.g. 'my-org') or username (e.g. 'octocat'). Required if github_scope_type is 'org' or 'user'."
}

variable "github_scope_type" {
  type        = string
  default     = "org"
  description = "Scoping type for WIF authentication: 'org' (all repos in org), 'user' (all repos under user), or 'repositories' (specific repo allowlist)."

  validation {
    condition     = contains(["org", "user", "repositories"], var.github_scope_type)
    error_message = "github_scope_type must be one of: 'org', 'user', 'repositories'."
  }
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

# --- GitHub Platform & Authentication ---

variable "github_app_id" {
  type        = string
  default     = ""
  description = "Numeric GitHub App ID for GitHub provider app_auth and GH_APP_ID repository secret bootstrap."
}

variable "github_app_installation_id" {
  type        = string
  default     = ""
  description = "GitHub App Installation ID for GitHub provider app_auth."
}

variable "github_app_pem_file" {
  type        = string
  default     = ""
  sensitive   = true
  description = "Path to GitHub App private key PEM file or raw PEM content for GitHub provider app_auth."
}

variable "github_mgmt_token" {
  type        = string
  default     = null
  sensitive   = true
  description = "Personal access token (classic or fine-grained) for GitHub provider authentication when not using GitHub App or ambient auth."
}
