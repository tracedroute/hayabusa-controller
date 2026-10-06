# SCADA lab packs

Compose existing working playbooks (do not fork them) for common lab personas.

| Pack | Suggested playbooks |
|------|---------------------|
| OpenPLC Modbus | `openplc-v4/runtime-health.yml`, `modbus/openplc-read-slave.yml` |
| Rockwell Logix | `rockwell/logix-identity-check.yml`, `rockwell/logix-read-tags.yml` |
| Siemens S7 | `siemens/s7-read-db.yml` |
| Beckhoff | `beckhoff/softbeckhoff-health.yml`, `beckhoff/twincat-read-symbols.yml` |
| OPC UA / FUXA | `scada/opcua-read-node.yml`, `scada/fuxa-health-check.yml` |

Use `../inventory.example.yml` and `../group_vars/all.yml` as-is. This pack index is documentation only.
