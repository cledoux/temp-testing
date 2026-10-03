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

# Governing: docs/openspec/specs/wif/spec.md#req-0001, docs/openspec/specs/wif/spec.md#req-0002

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 5.0.0"
    }
    github = {
      source  = "integrations/github"
      version = ">= 6.0.0"
    }
  }
}

locals {
  use_github_app_auth = (var.github_app_id != "" && var.github_app_installation_id != "" && var.github_app_pem_file != "")
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

provider "google-beta" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

provider "github" {
  owner = var.github_owner != "" ? var.github_owner : null
  token = !local.use_github_app_auth && var.github_mgmt_token != null && var.github_mgmt_token != "" ? var.github_mgmt_token : null

  dynamic "app_auth" {
    for_each = local.use_github_app_auth ? [1] : []
    content {
      id              = var.github_app_id
      installation_id = var.github_app_installation_id
      pem_file        = fileexists(pathexpand(trimspace(var.github_app_pem_file))) ? file(pathexpand(trimspace(var.github_app_pem_file))) : var.github_app_pem_file
    }
  }
}
