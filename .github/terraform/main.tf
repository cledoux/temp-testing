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

locals {
  gcp_module_bucket_name       = ""
  gcp_module_job_name          = ""
  gcp_module_runtime_sa_emails = []
}

module "wif" {
  source = "./modules/wif"

  gcp_project_id              = var.gcp_project_id
  gcp_region                  = var.gcp_region
  gcp_service_account_id      = var.gcp_service_account_id
  gcp_wif_pool_id             = var.gcp_wif_pool_id
  gcp_wif_provider_id         = var.gcp_wif_provider_id
  execution_mode              = var.execution_mode
  gcs_transit_bucket_name     = var.gcs_transit_bucket_name != "" ? var.gcs_transit_bucket_name : local.gcp_module_bucket_name
  cloud_run_job_name          = var.cloud_run_job_name != "" ? var.cloud_run_job_name : local.gcp_module_job_name
  cloud_run_runtime_sa_emails = length(var.cloud_run_runtime_sa_emails) > 0 ? var.cloud_run_runtime_sa_emails : local.gcp_module_runtime_sa_emails
  github_scope_type           = var.github_scope_type
  github_owner                = var.github_owner
  github_repositories         = var.github_repositories
  github_app_id               = var.github_app_id
}
