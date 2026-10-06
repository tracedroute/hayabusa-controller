# Ansible (Configuration)

Fleet console **Configuration** tab root. Keep vendor and domain support here — do not nest OpenTofu under this tree.

| Path | Tab / purpose |
|------|----------------|
| `inventory/`, `playbooks/`, `roles/`, `group_vars/` | Shared Ansible home |
| `ztp/` | Configuration-side vendor ZTP (pairs with `OpenTofu/ztp/`) |
| `iot/` | IoT vendors |
| `scada/` | SCADA / PLC (incl. OpenPLC) |
| `residential/` | Residential routers & switches (+ device APIs) |
| `security-fire/` | **Security & Fire Systems** (panels, VMS, PACS, fire) — Configuration |
| `Security/` | **SECops** tool playbooks — Security tab (capital `S` is required by Core) |
| `bare-metal-ztp/` | PXE / image recipes |

`Security/` and `security-fire/` are different products. Do not merge or rename `Security/` — the Fleet Security tab and SECops queue paths hard-depend on `Ansible/Security/`.
