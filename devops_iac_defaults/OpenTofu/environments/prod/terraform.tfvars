environment = "prod"
project     = "peregrine-tofu"
region      = "us-east-1"
node_count  = 3

common_tags = {
  managed_by  = "opentofu"
  project     = "peregrine-tofu"
  environment = "prod"
  cost_center = "ops"
}
