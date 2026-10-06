# Placeholder OpenTofu module for documenting security integration endpoints.
# Does not provision live panels. Wire provider credentials in a private fork.

terraform {
  required_version = ">= 1.5.0"
}

variable "site_name" {
  type        = string
  description = "Site or campus label"
}

variable "fire_panel_host" {
  type        = string
  description = "Primary fire panel / gateway host"
  default     = ""
}

variable "pacs_api_base_url" {
  type        = string
  description = "PACS API base URL (OnGuard/Genetec/ACM/etc.)"
  default     = ""
}

variable "vms_api_base_url" {
  type        = string
  description = "VMS API base URL"
  default     = ""
}

output "ansible_env_exports" {
  description = "Suggested env exports for Security & Fire Systems playbooks"
  value = {
    SECURITY_PANEL_HOST    = var.fire_panel_host
    SECURITY_API_BASE_URL  = var.pacs_api_base_url != "" ? var.pacs_api_base_url : var.vms_api_base_url
    SITE_NAME              = var.site_name
  }
}
