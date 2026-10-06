#!/usr/bin/env bash
set -euo pipefail

# Run `tofu plan` for an environment.
#   ./scripts/tofu-plan.sh                # dev
#   ./scripts/tofu-plan.sh prod           # prod
#   ./scripts/tofu-plan.sh dev -refresh=false

ENV="${1:-dev}"
shift || true

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_DIR="$ROOT_DIR/environments/$ENV"

if [ ! -d "$ENV_DIR" ]; then
  echo "ERROR: environment '$ENV' not found at $ENV_DIR" >&2
  exit 2
fi

cd "$ENV_DIR"
tofu init -input=false
exec tofu plan -input=false -var-file="$ROOT_DIR/common.tfvars" "$@"
