# No cloud creds needed for the default scaffold.
# Add real providers here (aws, proxmox, libvirt, cisco, ...) when you
# wire this env to actual infrastructure.

provider "null" {}

provider "local" {}
