# Remote backend example -- intentionally COMMENTED OUT.
# Default state is on-disk under ./terraform.tfstate (also gitignored).
# Uncomment + fill in to move state to a shared backend.
#
# terraform {
#   backend "s3" {
#     bucket         = "my-tofu-state"
#     key            = "prod/terraform.tfstate"
#     region         = "us-east-1"
#     dynamodb_table = "my-tofu-locks"
#     encrypt        = true
#   }
# }
#
# terraform {
#   backend "http" {
#     address        = "https://state.example.com/prod"
#     lock_address   = "https://state.example.com/prod/lock"
#     unlock_address = "https://state.example.com/prod/lock"
#     username       = "ci"
#     # password set via TF_HTTP_PASSWORD env var, never in this file
#   }
# }
