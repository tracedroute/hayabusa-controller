#!/usr/bin/env bash
set -euo pipefail

# Run `tofu apply` for an environment. Refuses prod without explicit
# AUTO_APPROVE_PROD=1 to make accidental prod applies harder.
#   ./scripts/tofu-apply.sh                # dev (interactive)
#   AUTO_APPROVE_PROD=1 ./scripts/tofu-apply.sh prod -auto-approve

ENV="${1:-dev}"
shift || true

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_DIR="$ROOT_DIR/environments/$ENV"

if [ ! -d "$ENV_DIR" ]; then
  echo "ERROR: environment '$ENV' not found at $ENV_DIR" >&2
  exit 2
fi

if [ "$ENV" = "prod" ] && [ "${AUTO_APPROVE_PROD:-0}" != "1" ]; then
  echo "Refusing to apply prod without AUTO_APPROVE_PROD=1." >&2
  echo "Re-run as: AUTO_APPROVE_PROD=1 $0 prod -auto-approve" >&2
  exit 3
fi

cd "$ENV_DIR"
tofu init -input=false
exec tofu apply -input=false -var-file="$ROOT_DIR/common.tfvars" "$@"
