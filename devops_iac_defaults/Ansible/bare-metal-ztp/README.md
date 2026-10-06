# Bare metal ZTP

PXE / iPXE / image staging for hosts with **no OS yet**. All bare-metal lab content lives **only** under this folder at the workspace root (next to `ansible/`, `my-tofu-project/`, and `ztp/` — not under `ansible/`).

| Subfolder | Purpose |
|-----------|--------|
| `playbooks/` | Ansible playbooks (pair with Fleet **Incoming** + catalog recipes) |
| `recipes/` | cloud-init, kickstart, unattend fragments |

OpenTofu for lab infra stays under **`my-tofu-project/`**; use **Sync inventory** there.
