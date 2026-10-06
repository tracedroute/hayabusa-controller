#!/usr/bin/env bash
# Opt-in lab runner: executes an existing pack sequence against an inventory.
# Does not modify playbooks. Usage:
#   ./run_scada_pack.sh openplc-modbus [inventory-file]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHECK_ONLY=0
if [[ "${1:-}" == "--check" ]]; then
  CHECK_ONLY=1
  shift
fi
PACK_NAME="${1:-}"
INV="${2:-$ROOT/inventory.example.yml}"
if [[ -z "$PACK_NAME" ]]; then
  echo "usage: $0 <pack-name> [inventory]" >&2
  echo "packs:" >&2
  ls "$ROOT/packs"/*.sequence.yml 2>/dev/null | xargs -n1 basename | sed 's/\.sequence\.yml$//' >&2
  exit 2
fi
SEQ="$ROOT/packs/${PACK_NAME}.sequence.yml"
if [[ ! -f "$SEQ" ]]; then
  echo "missing pack sequence: $SEQ" >&2
  exit 1
fi
if ! command -v ansible-playbook >/dev/null; then
  echo "ansible-playbook not installed" >&2
  exit 1
fi
echo "Running pack=$PACK_NAME inventory=$INV"
# sequence file: YAML list of relative playbook paths (comments allowed with #)
while IFS= read -r line; do
  line="${line%%#*}"
  line="$(echo "$line" | sed -e 's/^[[:space:]]*-[[:space:]]*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^["'\'']//' -e 's/["'\'']$//')"
  [[ -z "$line" || "$line" == "---" ]] && continue
  pb="$ROOT/$line"
  if [[ ! -f "$pb" ]]; then
    echo "SKIP missing playbook: $line" >&2
    continue
  fi
  if [[ "$CHECK_ONLY" == "1" ]]; then
    echo "=== ansible-playbook --syntax-check $line ==="
    ansible-playbook --syntax-check -i localhost, -c local "$pb"
  else
    echo "=== ansible-playbook $line ==="
    ansible-playbook -i "$INV" "$pb"
  fi
done < "$SEQ"
echo "OK pack $PACK_NAME finished"
