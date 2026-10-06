#!/bin/bash
# Hayabusa observability agent — pass bootstrap token as $1 or PEREGRINE_BOOTSTRAP_TOKEN
set -euo pipefail
TOKEN="${1:-${PEREGRINE_BOOTSTRAP_TOKEN:-}}"
BASE="https://hayabusa.tracedroute.net"
if [[ -z "$TOKEN" ]]; then
  echo "Usage: $0 <bootstrap-token>" >&2
  echo "Obtain a token from Hayabusa → Observability → Generate bootstrap token" >&2
  exit 1
fi
exec curl -fsSL "${BASE}/api/observability/agent-install.sh?token=${TOKEN}" | bash
