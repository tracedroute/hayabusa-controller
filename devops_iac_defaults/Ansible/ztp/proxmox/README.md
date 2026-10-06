# Proxmox VE — ZTP / PXE / cloud-init (lab)

Peregrine maps `proxmox`, `pve`, and recipe `proxmox-pxe` to this **`proxmox/`** folder.

- Typical flow: **Pixie / iPXE** → kernel + initrd → **cloud-init** (`user-data` / `meta-data`) or an **answer.toml**-style automation you host from Peregrine’s TFTP/HTTP roots (`step_in` / `tftp_root` in orchestrator config).
- Align **`PEREGRINE_ZTP_FETCH_ROOT`** (or the baked defaults tree) so dispatch payloads and autoinstall snippets stay under version control in your org workspace.

OpenTofu state and Ansible inventory sync behave the same as other vendors (see `vmware/README.md` in this tree).
