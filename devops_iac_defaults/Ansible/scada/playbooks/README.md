# SCADA & PLC Ansible playbooks

Remote interaction playbooks for industrial controllers and SCADA/HMI systems supported by Hayabusa. Each playbook runs on **localhost** and talks directly to the target IP/port using the same Python dispatch stack as the Fleet/Workstations **PLC Viewer** (`/api/plc/read`, `/api/plc/write`).

## Layout

| Directory | Vendors / systems | Transport |
|-----------|-------------------|-----------|
| `scada/` | FUXA, OPC UA servers | HTTP, OPC UA |
| `modbus/` | OpenPLC, Schneider, WAGO, Phoenix Contact | Modbus TCP :502 |
| `siemens/` | S7-1200/1500/300/400 | ISO-on-TCP :102 (snap7) |
| `rockwell/` | ControlLogix, CompactLogix | EtherNet/IP CIP (pycomm3) |
| `beckhoff/` | TwinCAT | ADS (pyads) |
| `mitsubishi/` | Q/L/iQ-F (MC enabled) | MC Protocol Type3E :5007 |
| `omron/` | CJ/CS/NJ/NX (FINS enabled) | FINS UDP :9600 |
| `common/` | Driver inventory | local |

## Prerequisites

- Run from the Hayabusa app container (or any host with `/peregrine/run.py` and PLC Python deps).
- Set target addresses: `-e plc_host=10.0.0.50` or edit `group_vars/all.yml`.
- **Writes** require operator policy `plc_writes_enabled` and are blocked in several playbooks by default.

## Examples

**Note:** The workspace folder name contains spaces (`SCADA & PLC`). Quote paths in shell commands.

```bash
PB="SCADA & PLC/playbooks"
cd "$PB/.."   # workspace SCADA & PLC root

# Quick local smoke (drivers + FUXA — no PLC target needed)
ansible-playbook -i "$PB/inventory.example.yml" "$PB/site-smoke.yml"

# Check which PLC drivers are installed
ansible-playbook -i "$PB/inventory.example.yml" "$PB/common/check-drivers.yml"

# Modbus read (OpenPLC default slave)
ansible-playbook -i "$PB/inventory.example.yml" "$PB/modbus/read-holding-registers.yml" -e plc_host=192.168.1.216

# Siemens S7 DB read
ansible-playbook -i "$PB/inventory.example.yml" "$PB/siemens/s7-read-db.yml" -e plc_host=10.0.0.10 -e siemens_db_number=1

# Rockwell tag read
ansible-playbook -i "$PB/inventory.example.yml" "$PB/rockwell/logix-read-tags.yml" -e ab_tags='Program:MainProgram.MotorRun'

# FUXA SCADA health
ansible-playbook -i "$PB/inventory.example.yml" "$PB/scada/fuxa-health-check.yml"
```

## Scripts

`scripts/plc_cli.py` wraps Hayabusa `_plc_read_dispatch` / `_plc_write_dispatch` so playbook results match the PLC Viewer API exactly.

## Lab testing (ubuntu-pnetnode)

See `docs/LAB-PERSONAS.md` for the full persona ↔ playbook matrix on `192.168.2.137`.

```bash
docker exec peregrine11252025 bash /peregrine/data/scada-plc-playbooks/scripts/run-lab-playbook-tests.sh
# Expected: pass=37 fail=0 skip=0
```

Lab inventory: `inventory-lab-pnetnode.yml` (write flags + `ab_cip_engine=cpppo`).
