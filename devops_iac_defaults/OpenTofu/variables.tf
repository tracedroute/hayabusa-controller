# Variable *declarations* shared across environments.
# Values live in common.tfvars (defaults for all envs) and in
# environments/<env>/terraform.tfvars (env-specific overrides).

variable "project" {
  description = "Logical project name used to tag resources."
  type        = string
  default     = "peregrine-tofu"
}

variable "region" {
  description = "Cloud region or geographic locator (string is provider-agnostic)."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name: dev, prod, etc."
  type        = string
}

variable "common_tags" {
  description = "Tags merged onto every taggable resource."
  type        = map(string)
  default     = {}
}
