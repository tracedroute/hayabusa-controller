variable "project" { type = string }
variable "environment" { type = string }
variable "region" { type = string }

variable "node_count" {
  type    = number
  default = 1
}

variable "tags" {
  type    = map(string)
  default = {}
}
