# Bare-metal recipe packs

Existing recipes under this tree (Ubuntu, Debian, Proxmox, Windows, ESXi, Aruba, Arista) are preserved.

Shared cloud-init user-data for several Linux recipes is symlinked from `OpenTofu/templates/cloud-init.user-data.yaml.tpl`.
Edit the template once; do not duplicate blobs.

| Pack | Recipes |
|------|---------|
| Linux cloud | `ubuntu-22-server`, `ubuntu-24-server`, `debian-cloud`, `proxmox-pxe` |
| Desktop | `ubuntu-22-desktop`, `ubuntu-24-desktop` |
| Windows | `windows-cloudbase`, `windows-11-cloudbase`, `windows-server-2022-cloudbase` |
| Network OS ZTP | `arista-eos-ztp`, `aruba-aoscx-ztp`, `aruba-aoss-ztp`, `aruba-vmc-ztp` |
| Observability | `observability-node-exporter`, `observability-telegraf-influx` |
