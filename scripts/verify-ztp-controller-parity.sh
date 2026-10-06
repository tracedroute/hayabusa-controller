#!/usr/bin/env bash
set -euo pipefail
H="/home/swoopingbird/hayabusa/controller-hotfixes"
ok=0; fail=0
chk(){ if eval "$2"; then echo "  OK: $1"; ok=$((ok+1)); else echo "  FAIL: $1"; fail=$((fail+1)); fi; }

echo "=== ZTP parity verify (5 passes) ==="
for pass in 1 2 3 4 5; do
  echo "-- pass $pass --"
  chk "approve_ztp permission" "rg -q 'approve_ztp' '$H/rbac_store.py'"
  chk "ztp secret category" "rg -q '\"ztp\": \"ZTP provisioning\"' '$H/secrets_vault.py'"
  chk "ztp job kinds" "rg -q 'ztp-dhcp-start' '$H/bridge_rpc.py' && rg -q '\"ztp\"' '$H/bridge_rpc.py'"
  chk "ztp hydrate dhcp" "rg -q 'ztp-dhcp-start' '$H/bridge_rpc.py' && rg -q 'ztp_action' '$H/bridge_rpc.py'"
  chk "start gated approve_ztp" "rg -q 'approve_ztp' '$H/controller_main.py' && rg -q 'api_ztp_start' '$H/controller_main.py'"
  chk "job approve by kind" "rg -q 'ZTP_JOB_KINDS' '$H/controller_main.py'"
  chk "ztp switch UI" "rg -q 'ztpEnableSwitch' '$H/templates/dashboard.html'"
  chk "ztp warning JS" "rg -q 'ztpWarnEnable' '$H/static/js/controller.js'"
  chk "sync ztp roots" "rg -q 'bare-metal-ztp' '$H/rbac_store.py'"
  python3 -m py_compile "$H/bridge_rpc.py" "$H/controller_main.py" "$H/rbac_store.py" "$H/secrets_vault.py"
  chk "python syntax pass $pass" "true"
done
echo "ok=$ok fail=$fail"
[[ "$fail" -eq 0 ]]
