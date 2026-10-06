output "environment" {
  value = var.environment
}

output "example_summary" {
  value = module.example.summary
}

output "example_inventory_path" {
  description = "Path to the rendered inventory file written by the example module."
  value       = module.example.inventory_path
}
