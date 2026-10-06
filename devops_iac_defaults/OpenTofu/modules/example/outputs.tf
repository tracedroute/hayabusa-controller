output "summary" {
  value = {
    project     = var.project
    environment = var.environment
    region      = var.region
    node_count  = var.node_count
    hosts       = [for h in local.hosts : h.name]
  }
}

output "inventory_path" {
  value = local_file.inventory.filename
}
