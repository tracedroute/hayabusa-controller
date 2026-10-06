# Security alerts → Hayabusa runbook hooks

Use these as operator checklists when Wazuh or Shuffle raises physical-security alarms.

## Wazuh

1. Open **Watch → Wazuh SIEM** and identify the rule/decoder for the site.
2. Map the asset to an inventory host in `Security & Fire Systems/playbooks/inventory.example.yml`
   (fire panel, PACS, VMS, door, camera).
3. From Craft → Ansible & OpenTofu run the matching read-only health playbook, e.g.:
   - fire panel → `playbooks/fire-alarm/*-health.yml`
   - door/PACS → `playbooks/access-control/*-health.yml` or `playbooks/common/zone-door-camera-health.yml`
4. For BACnet-exposed supervisory points: `playbooks/common/bacnet-read-points.yml`
5. Escalate to AHJ/owner before any `panel_apply_changes=true` action.

## Shuffle SOAR

1. Open **Watch → Shuffle SOAR** workflow for the security/fire alert.
2. Recommended enrich steps (HTTP GET only):
   - Call Hayabusa `/api/hosts` for site context
   - Trigger a read-only Ansible job against the Security & Fire Systems playbook path
3. Do **not** auto-silence fire panels or unlock doors from SOAR without a human approval gate.
4. Optional: attach compliance export via `playbooks/compliance/inspection-checklist-export.yml`
   with `SECURITY_COMPLIANCE_ALLOW_EXPORT=true` after the incident window.

## Environment variables

- `SECURITY_PANEL_HOST` / `PANEL_HOST` — appliance or gateway IP/DNS
- `SECURITY_PANEL_TOKEN` / `SECURITY_API_TOKEN` — bearer token for GETs
- `SECURITY_API_BASE_URL` — vendor API root for integration read playbooks
- `BACNET_HOST`, `BACNET_OBJECT_IDS` — BACnet read helpers
