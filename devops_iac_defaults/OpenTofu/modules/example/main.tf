locals {
  hosts = [
    for i in range(var.node_count) :
    {
      name = format("%s-%s-%02d", var.project, var.environment, i + 1)
      role = i == 0 ? "leader" : "follower"
    }
  ]

  inventory_yaml = yamlencode({
    all = {
      vars = {
        environment = var.environment
        region      = var.region
        tags        = var.tags
      }
      hosts = {
        for h in local.hosts : h.name => {
          ansible_host = "127.0.0.1"
          role         = h.role
        }
      }
    }
  })
}

resource "local_file" "inventory" {
  filename        = "${path.root}/out/inventory.yml"
  content         = local.inventory_yaml
  file_permission = "0644"
}

resource "null_resource" "marker" {
  triggers = {
    project     = var.project
    environment = var.environment
    nodes       = jsonencode(local.hosts)
    tags_hash   = sha256(jsonencode(var.tags))
  }
}
