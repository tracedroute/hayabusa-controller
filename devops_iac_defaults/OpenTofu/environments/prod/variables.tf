variable "project" { type = string }
variable "region" { type = string }
variable "environment" { type = string }

variable "common_tags" {
  type    = map(string)
  default = {}
}

variable "node_count" {
  description = "How many example hosts the network module should provision."
  type        = number
  default     = 1
}
