#!/usr/bin/env bash
# Industrial-realistic SCADA & PLC lab suite — ubuntu-pnetnode (192.168.2.137)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$(basename "$SCRIPT_DIR")" == "scripts" ]]; then
  ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
else
  ROOT="$SCRIPT_DIR"
fi
INV="${INV:-$ROOT/inventory-lab-pnetnode.yml}"
LAB_HOST="${LAB_HOST:-192.168.2.137}"
LAB_SSH_USER="${LAB_SSH_USER:-pnet}"
LAB_SSH_PASS="${LAB_SSH_PASS:-pnet}"

pass=0
fail=0
skip=0

run_pb() {
  local name="$1"
  local pb="$2"
  shift 2
  echo "----------------------------------------"
  echo "PLAYBOOK: $name"
  if ansible-playbook -i "$INV" "$pb" "$@" 2>&1; then
    echo "OK  $name"
    ((pass++)) || true
  else
    echo "FAIL $name"
    ((fail++)) || true
  fi
  echo
}

ssh_lab() {
  sshpass -p "$LAB_SSH_PASS" ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    "${LAB_SSH_USER}@${LAB_HOST}" "$@"
}

start_persona() {
  local persona="$1"
  echo "Starting lab persona: $persona on $LAB_HOST"
  ssh_lab "cd ~/plc-emulator-lab && ./plc-emulator stop 2>/dev/null; ./plc-emulator start ${persona} && sleep 5 && ./plc-emulator status"
}

echo "=== SCADA & PLC industrial-realistic lab suite ==="
echo "Inventory: $INV"
echo "Target: $LAB_HOST"
echo

pip3 install -q cpppo 2>/dev/null || true

run_pb "ensure-lab-cip-deps" "$ROOT/common/ensure-lab-cip-deps.yml"
run_pb "lab-persona-status" "$ROOT/common/lab-persona-status.yml"
run_pb "site-smoke" "$ROOT/site-smoke.yml"
run_pb "check-drivers" "$ROOT/common/check-drivers.yml"
run_pb "fuxa-health" "$ROOT/scada/fuxa-health-check.yml"

start_persona schneider-m221
run_pb "modbus-read-coils" "$ROOT/modbus/read-coils.yml"
run_pb "modbus-read-holding" "$ROOT/modbus/read-holding-registers.yml"
run_pb "schneider-modbus-read" "$ROOT/schneider/modbus-read-holding.yml"
run_pb "openplc-modbus-read" "$ROOT/modbus/openplc-read-slave.yml"
run_pb "modbus-write-read-verify" "$ROOT/modbus/modbus-write-read-verify.yml" -e modbus_verify_address=0 -e modbus_verify_write_value=4242
run_pb "negative-modbus-port" "$ROOT/common/negative-modbus-unit-id.yml"

start_persona modbuspal
run_pb "modbuspal-automation-read" "$ROOT/modbuspal/read-holding-automation.yml"
run_pb "modbuspal-write-read-verify" "$ROOT/modbus/modbus-write-read-verify.yml" -e modbus_verify_address=100 -e modbus_verify_write_value=555

start_persona rockwell-modbus
run_pb "rockwell-compactlogix-modbus" "$ROOT/rockwell/compactlogix-modbus-read.yml"

start_persona rockwell
run_pb "rockwell-logix-identity" "$ROOT/rockwell/logix-identity-check.yml"
run_pb "rockwell-logix-read-tags" "$ROOT/rockwell/logix-read-tags.yml"
run_pb "rockwell-logix-write-verify" "$ROOT/rockwell/logix-write-read-verify.yml"

start_persona siemens
run_pb "siemens-s7-read" "$ROOT/siemens/s7-read-db.yml"
run_pb "siemens-s7-rest" "$ROOT/siemens/s7-read-db-rest.yml"
run_pb "siemens-s7-write-verify" "$ROOT/siemens/s7-write-read-verify.yml" -e s7_verify_hex=4849 -e s7_verify_size=2

start_persona beckhoff-ads
run_pb "beckhoff-ads-read" "$ROOT/beckhoff/twincat-read-symbols.yml" -e beckhoff_symbols=test1,test2,GVL.test1
run_pb "beckhoff-ads-write-verify" "$ROOT/beckhoff/twincat-write-read-verify-ads.yml" -e beckhoff_verify_symbol=test1 -e beckhoff_verify_write_value=88

start_persona beckhoff
run_pb "beckhoff-symbol-catalog" "$ROOT/beckhoff/softbeckhoff-health.yml"
run_pb "beckhoff-rest-read" "$ROOT/beckhoff/twincat-read-symbols-rest.yml"
run_pb "beckhoff-rest-write-verify" "$ROOT/beckhoff/twincat-write-read-verify-rest.yml" -e beckhoff_verify_symbol=test1 -e beckhoff_verify_rest_value_b64=Vw==
run_pb "beckhoff-negative-ads" "$ROOT/beckhoff/negative-softbeckhoff-ads.yml" -e beckhoff_symbols=test1,test2

start_persona opcua
run_pb "opcua-read-node" "$ROOT/scada/opcua-read-node.yml"
run_pb "opcua-read-nodes" "$ROOT/scada/opcua-read-nodes.yml"
run_pb "opcua-write-verify" "$ROOT/scada/opcua-write-read-verify.yml" -e opcua_verify_write_value=4242

start_persona mitsubishi
run_pb "mitsubishi-mc-read" "$ROOT/mitsubishi/mc-read-word-units.yml"
run_pb "mitsubishi-mc-write-verify" "$ROOT/mitsubishi/mc-write-read-verify.yml" -e mitsubishi_verify_address=D10 -e mitsubishi_verify_write_value=4321

start_persona omron
run_pb "omron-fins-read" "$ROOT/omron/fins-read-dm.yml"
run_pb "omron-fins-write-verify" "$ROOT/omron/fins-write-read-verify.yml" -e omron_verify_address=10 -e omron_verify_write_value=2468

start_persona openplc-v4
run_pb "openplc-v4-api-health" "$ROOT/openplc-v4/runtime-health.yml"
run_pb "openplc-v4-api-authenticated" "$ROOT/openplc-v4/runtime-api-authenticated.yml"
run_pb "openplc-v4-api-diagnostics" "$ROOT/openplc-v4/runtime-api-diagnostics.yml"

run_pb "lab-coverage-summary" "$ROOT/common/lab-coverage-summary.yml"

echo "=== SUMMARY: pass=$pass fail=$fail skip=$skip ==="
[[ "$fail" -eq 0 ]]
