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

# Governing: docs/openspec/specs/wif/spec.md#req-0001, docs/openspec/specs/wif/spec.md#req-0006

# ==============================================================================
# SECTION 1: GCP Project & Identity Naming
# ==============================================================================
# Configures the Google Cloud Project and Workload Identity Federation (WIF)
# resource identifiers. These identifiers establish the federated identity
# used by GitHub Actions workflows to authenticate to GCP without long-lived keys.

# Required: The Google Cloud Project ID where WIF resources and/or Cloud Run
# infrastructure will be deployed.
gcp_project_id = "codemender-playground-cc26"

# The Google Cloud region for regional resources (e.g. Cloud Run Jobs, Serverless
# VPC Access Connectors, and repository configuration variables).
gcp_region = "us-central1"

# The Service Account ID (name) created for GitHub Actions authentication.
# This Service Account is granted least-privilege IAM roles depending on the execution_mode.
# Default: "codemender-wif-sa"
gcp_service_account_id = "codemender-wif-sa"

# The Workload Identity Pool ID to create in GCP for federating GitHub Actions OIDC tokens.
# Default: "codemender-wif-pool"
gcp_wif_pool_id = "codemender-wif-pool"

# The Workload Identity Pool Provider ID to create within the pool.
# Default: "codemender-wif-provider"
gcp_wif_provider_id = "codemender-wif-provider"


# ==============================================================================
# SECTION 2: Execution Mode & Cloud Run Infrastructure
# ==============================================================================
# Controls the architectural execution mode for CodeMender scans:
#
# - "local": (Default) Runs cm-runner directly on the GitHub Actions runner host
#   (LocalDockerLauncher). The WIF Service Account is granted roles/aiplatform.user
#   to interact with Vertex AI Gemini models directly from CI runner. No Cloud Run
#   or GCS transit infrastructure is provisioned.
#
# - "cloud_run": Automatically provisions terraform/modules/gcp (Cloud Run Jobs,
#   GCS transit/reports bucket, and runtime service accounts) and seamlessly wires
#   them into terraform/modules/wif without manual wiring. GitHub Actions acts as
#   an orchestrator staging repository snapshots to GCS and triggering remote Cloud
#   Run Job execution. The WIF Service Account is granted roles/run.developer,
#   roles/storage.objectUser on the transit bucket, and roles/iam.serviceAccountUser
#   on Cloud Run runtime SAs (Vertex AI permissions reside solely on Cloud Run SAs).

execution_mode = "local" # or "cloud_run"

# Optional Cloud Run Infrastructure Settings (effective when execution_mode = "cloud_run"):
# The root module automatically wires module.gcp outputs into module.wif. Uncomment
# and customize any of the following settings to override defaults:

# Prefix for provisioned GCP resources (buckets, jobs, service accounts, VPCs).
# Default: "codemender"
# resource_prefix = "codemender"

# Custom name for the GCS reports and transit bucket. If left empty, a unique name
# is automatically generated using resource_prefix and random suffix.
# reports_bucket_name = ""

# CPU limit allocated to Cloud Run worker tasks (e.g., "1", "2", "4", "8").
# Default: "2"
# runner_cpu = "2"

# Memory limit allocated to Cloud Run worker tasks (e.g., "2Gi", "4Gi", "8Gi", "16Gi").
# Default: "4Gi"
# runner_memory = "4Gi"

# Whether to provision a dedicated VPC network, subnets, and Cloud NAT gateway.
# Default: false
# create_vpc_and_nat = false

# ID of an existing Serverless VPC Access Connector if create_vpc_and_nat is false.
# existing_vpc_connector_id = null

# CIDR block (/28 or /26) for the Serverless VPC Access Connector when create_vpc_and_nat is true.
# Default: "10.0.0.0/26"
# vpc_connector_cidr = "10.0.0.0/26"

# Cron schedule expression for Cloud Scheduler nightly triggers.
# Default: "0 2 * * *" (2:00 AM UTC daily)
# scheduler_cron = "0 2 * * *"


# ==============================================================================
# SECTION 3: GCP WIF OIDC Trust Perimeter & Target Repositories
# ==============================================================================
# Defines the GitHub identity perimeter allowed to authenticate through GCP WIF,
# and specifies target repositories to configure.

# Scoping model for WIF authentication:
# - "org": WIF trusts the entire organization (assertion.repository_owner == github_owner).
#          github_repositories lists repos to bootstrap (or empty [] to skip GitHub API calls).
# - "user": WIF trusts all repos owned by the user (assertion.repository_owner == github_owner).
#           github_repositories lists repos to bootstrap (or empty [] to skip GitHub API calls).
# - "repositories": WIF trust is strictly constrained to the repositories explicitly enumerated
#                   in github_repositories. At least one repository is required.
github_scope_type = "user" # or "user", "repositories"

# GitHub organization name (e.g., "my-github-org") or personal account username.
# Required if github_scope_type is "org" or "user".
github_owner = "cledoux"

# Target repositories list:
# - Accepts either short names ("repo") or full repository names ("owner/repo").
# - Both formats are automatically normalized by the module.
# - When github_scope_type = "repositories", at least one repository is required and defines
#   both the GCP WIF trust perimeter and target repos to bootstrap.
# - When github_scope_type = "org" or "user", WIF trusts the entire org/user, and this list
#   determines which repositories have GitHub secrets/variables/labels bootstrapped
#   (or set to empty [] to skip all GitHub API operations).
github_repositories = [
    "cledoux/temp-testing",
]


# ==============================================================================
# SECTION 4: Optional GitHub Repository Bootstrap & Provider Auth
# ==============================================================================
# When github_repositories is non-empty, CodeMender bootstraps target repositories
# with required GitHub Actions Secrets (GCP_WORKLOAD_IDENTITY_PROVIDER, GCP_SERVICE_ACCOUNT),
# Labels (codemender-scan), and Variables (GCS_TRANSIT_BUCKET, CLOUD_RUN_JOB_NAME in cloud_run mode).
#
# To manage these GitHub resources, Terraform supports 3 authentication methods:
#
# 1. Ambient CLI / Environment (Default):
#    Leave the variables below empty/null. The GitHub provider will automatically use:
#    - `gh auth login` credentials from your local machine, or
#    - GITHUB_TOKEN environment variable in CI pipelines.
#
# 2. GitHub App `app_auth` (Recommended for Organizations):
#    Authenticates as a GitHub App installation with fine-grained repository permissions.
#    Provide github_app_id, github_app_installation_id, and github_app_pem_file:
github_app_id              = ""
github_app_installation_id = ""
github_app_pem_file        = "" # Path to .pem private key file or raw PEM file content

# 3. Explicit Token:
#    Provide a GitHub Personal Access Token (classic with 'repo' scope or fine-grained PAT).
#    Overrides ambient CLI credentials when specified.
github_mgmt_token = null
