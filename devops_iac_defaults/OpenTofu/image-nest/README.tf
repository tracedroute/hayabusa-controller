# Image Nest — OpenTofu variable placeholders
#
# Full operator guide: docs/IMAGE-NEST-AND-WINDOWS-IMAGES.md
#
# Queue this stack from Hayabusa. On LAN approve the controller hydrates
# <<IMAGE_NEST:…>> the same way it hydrates <<SECRET:…>>.
#
# After strip/full bake, Image Nest publishes aliases such as:
#   latest-win11-iso / latest-winserver-iso
#   latest-win11-stripped / latest-winserver-stripped
#   latest-win11-full / latest-winserver-full
#   latest-windows-* (last banked of that flavor, either family)
#
# Bare refs resolve to source_image (WIM / qcow2 / ISO path on the controller).
# Optional field: <<IMAGE_NEST:latest-win11-iso:source_iso>>
# Server example: <<IMAGE_NEST:latest-winserver-stripped>>

variable "source_image" {
  type        = string
  description = "Path to banked Win11 media (hydrated from Image Nest)"
}

variable "image_nest_ref" {
  type        = string
  description = "Resolved Image Nest registry ref"
  default     = ""
}

variable "image_flavor" {
  type        = string
  description = "stripped | full | iso"
  default     = ""
}

# Example terraform.tfvars (commit placeholders only — never real paths):
#
#   source_image   = "<<IMAGE_NEST:latest-win11-stripped>>"
#   image_nest_ref = "<<IMAGE_NEST:latest-win11-stripped:image_nest_ref>>"
#   image_flavor   = "<<IMAGE_NEST:latest-win11-stripped:image_flavor>>"
#
# Ansible equivalent:
#   win11_image: "{{ lookup('env', 'HAYABUSA_IMAGE_NEST_LATEST_WIN11_STRIPPED') }}"
