# Smoke matrix — what we prove in CI vs lab

CI never talks to real devices. Checks are local-only.

| Area | CI proof | Lab-proven (manual / pack runner) | Do not touch blindly |
|------|----------|-----------------------------------|----------------------|
| ZTP `*-dispatch`, `ztp.sh` | non-empty + `bash -n` when shell shebang | Device boot / DHCP option 67 fetch | Working dispatch scripts |
| ZTP `*.py` | `py_compile` | Device Python ZTP path | Cisco/Juniper vendor `.py` |
| ZTP `manifest.json` | every listed `filename` exists on disk | Manifest tags match DHCP model | — |
| ZTP `default.json` | vendor/`device_type` match path (`check_iac_tree`) | PnP / config render | — |
| Residential `app/*.py` | `py_compile` | `/health` against LAN device | Existing per-device APIs |
| IoT playbooks | placeholder banned; V2 pattern required | Probe with `IOT_DEVICE_HOST` set | Rich V2 playbooks |
| SCADA / OpenPLC | sample `ansible-playbook --syntax-check` when ansible present | `scripts/run_scada_pack.sh openplc-modbus` | Existing playbooks under `scada/playbooks/` |
| SECops `Security/` | sample syntax-check when ansible present | Controller LAN approve queue | — |

## Labels

- **CI-proven**: automated on every push/PR via `scripts/smoke_iac_tree.py`
- **Lab-proven**: operator ran against real/lab inventory; record in PR notes
- **Stub / scaffold**: safe defaults; expand in place, don’t delete

## Commands

```bash
python3 scripts/check_iac_tree.py .
python3 scripts/smoke_iac_tree.py
# optional, needs ansible + lab inventory:
./Ansible/scada/playbooks/scripts/run_scada_pack.sh openplc-modbus
```
