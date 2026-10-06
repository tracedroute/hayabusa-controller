# Hayabusa Infrastructure Templates

Default **OpenTofu** (Creation) and **Ansible** (Configuration) trees for the Hayabusa Fleet crafting console.

## Layout

```
OpenTofu/                 # Creation tab
  environments/
  modules/
  templates/              # shared versions.tf / cloud-init
  ztp/<vendor>/           # Creation-side vendor ZTP (canonical)
  …

Ansible/                  # Configuration tab
  inventory/              # single inventory home
  ztp/<vendor>/           # Configuration-side vendor ZTP (canonical)
  iot/                    # IoT vendors (+ _template, _shared)
  scada/                  # SCADA / PLC (includes openplc) — many playbooks are live lab-tested
  residential/            # residential routers & switches (+ device APIs)
  security-fire/          # security & fire systems
  Security/               # SECops playbooks (capital S required by Core)
  bare-metal-ztp/         # PXE / image recipes
  playbooks/, roles/, group_vars/
```

## Supported surface (expand here; don't delete)

| Area | Supported vendors / packs |
|------|---------------------------|
| **ZTP** | Cisco, Arista, Aruba, Juniper, Palo Alto (+ Proxmox / VMware docs under Ansible ZTP) |
| **IoT** | All folders under `Ansible/iot/` (Amazon → Yale, Home Assistant, protocols, …) |
| **Residential APIs** | Per-device `*-router-api` / `*-switch-api` trees (working scaffolds — do not overwrite) |
| **SCADA / PLC** | OpenPLC v4, Modbus, Rockwell, Siemens, Beckhoff, Mitsubishi, Omron, Schneider, OPC UA, FUXA |
| **Security & Fire** | `security-fire/` playbooks |
| **SECops** | `Security/` playbooks |
| **Bare metal** | Ubuntu/Debian/Proxmox/Windows/ESXi + network-OS ZTP recipes |

## Scaffolding (additive only)

```bash
python3 scripts/scaffold_iot_device.py --vendor Acme --device "Smart Plug"
python3 scripts/scaffold_residential_api.py --kind routers --vendor acme --slug acme-widget-router-api --title "Acme Widget"
python3 scripts/link_residential_requirements.py .
```

## Hygiene

```bash
python3 scripts/check_iac_tree.py .              # CI / local; never mutates
python3 scripts/cleanup_iac_defaults_tree.py .   # idempotent re-canonicalize only
```

CI runs `check_iac_tree.py` on push/PR. Forbidden nests, tracked `.env` secrets, empty ZTP scripts, and placeholder IoT stubs fail the job. Working `OpenTofu/ztp` ↔ `Ansible/ztp` mirrors are intentional.

## Notes

- Do **not** nest Ansible under `OpenTofu/` or OpenTofu under `Ansible/`.
- Never edit working ZTP `*-dispatch` / `ztp.sh` / vendor `.py` / `.cfg` / `.conf` unless fixing a proven bug.
- Never overwrite SCADA/OpenPLC playbooks or programs that already run in lab — add beside them.
- `Ansible/Security/` and `Ansible/security-fire/` are different products; keep both.
- Design & Deploy (`catalog.json`) is a separate surface from this console workspace seed.
- Prefer `.env.example`; never commit `.env`.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the PR checklist.

## Docs

- [Workspace migration](docs/WORKSPACE_MIGRATION.md)
- [Smoke matrix](docs/SMOKE_MATRIX.md)
- [Secret rotation](docs/SECRET_ROTATION.md)
- [Contributing / PR checklist](CONTRIBUTING.md)
- Design & Deploy **Fleet Console** bridges include **Open in Fleet** deep links into the crafting workspace.
