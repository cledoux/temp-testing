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

# Governing: SPEC-WIF, REQ-0003, REQ-0004

locals {
  baseline_apis = [
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
  ]

  codemender_apis = [
    "aiplatform.googleapis.com",
  ]

  gcp_cloud_run_apis = [
    "run.googleapis.com",
    "storage.googleapis.com",
  ]

  required_apis = concat(
    local.baseline_apis,
    var.execution_mode == "local" ? local.codemender_apis : [],
    var.execution_mode == "cloud_run" ? local.gcp_cloud_run_apis : [],
  )
}

resource "google_project_service" "enabled_apis" {
  for_each           = toset(local.required_apis)
  project            = var.gcp_project_id
  service            = each.key
  disable_on_destroy = false
}
