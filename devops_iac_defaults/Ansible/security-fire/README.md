# Security & Fire Systems

Ansible starters for commercial **fire alarm**, **intrusion**, **access control (PACS)**,
**video/VMS**, **mass notification**, and **BMS life-safety** integrations in the
Hayabusa Ansible & OpenTofu console.

## Safety

- Playbooks are **read-only by default**.
- Set `panel_apply_changes=true` (extra-var) only with owner/AHJ approval and a change window.
- Life-safety commands (silence, reset, unlock, notify) can affect real people and code compliance.

## Layout

- `playbooks/fire-alarm/` — Notifier, Simplex, EST, Siemens Desigo Fire, Potter, Gamewell-FCI, Hochiki, Farenhyt
- `playbooks/intrusion/` — DMP, Bosch, DSC Neo, Honeywell commercial, Qolsys
- `playbooks/access-control/` — Lenel OnGuard, Genetec, C-CURE, Avigilon ACM, HID, Brivo, Kisi
- `playbooks/video-vms/` — Milestone, Genetec video, Avigilon ACC, exacqVision, Hanwha WAVE
- `playbooks/mass-notification/` — InformaCast, Alertus, Athena
- `playbooks/bms-life-safety/` — BACnet gateway, Niagara N4, Metasys
- `playbooks/common/` — shared safety brief
- `playbooks/site-smoke.yml` — imports common safety + a lightweight coverage summary

## Quick start

```bash
# Read-only reachability against a panel/gateway
SECURITY_PANEL_HOST=192.168.10.50 ansible-playbook \
  "playbooks/fire-alarm/notifier-honeywell-nfs2-3030-onyxworks-health.yml"

# Optional token for authenticated GETs
SECURITY_PANEL_HOST=vms.example.com SECURITY_PANEL_TOKEN=... \
  ansible-playbook "playbooks/video-vms/milestone-xprotect-health.yml"
```

Use Hayabusa Craft → Workstations → **Ansible & OpenTofu** to browse and run these under
`Security & Fire Systems/`.

## Not SECops

SECops tool playbooks live under `../Security/` (Fleet Security tab). This tree is building Security & Fire Systems only.
