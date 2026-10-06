# Self-contained root module for the prod environment.
# Calls shared modules from ../../modules/.

locals {
  env_tags = merge(var.common_tags, {
    environment = var.environment
  })
}

module "example" {
  source = "../../modules/example"

  project     = var.project
  environment = var.environment
  region      = var.region
  node_count  = var.node_count
  tags        = local.env_tags
}
