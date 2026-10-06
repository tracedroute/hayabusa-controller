# VMware ESXi — ZTP / scripted install (lab)

Peregrine maps device types `vmware`, `esxi`, `vsphere`, and bare-metal recipe `esxi-kickstart` to this **`vmware/`** vendor folder under the ZTP fetch root.

- Stage a **kickstart** or **jumpstart** script your lab TFTP/HTTP profile expects, and reference it from your **dnsmasq** / **iPXE** menu.
- DHCP alternate ports and interface selection are on **`/ztp`** (Fleet header can mirror orchestrator state).
- For **inventory correlation**, use **DevOps → Sync inventory** (`POST /api/devops-iac/opentofu-sync-inventory`): delivered ZTP hosts are merged into `ansible/inventory/opentofu_inventory_hosts.json` even before state lists them.

StrongSwan / IPsec and mesh controls are unrelated to hypervisor kickstart delivery.
