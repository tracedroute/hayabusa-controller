# Security (SECops Ansible)

Open-source SECops tool playbooks for the **Security** workspace tab and the SECops sidenav.

## How runs work

1. Hayabusa queues `ansible-playbook` via `POST /api/my-controller/jobs/run`
2. Approve on the controller (**Job approvals**)
3. Controller hydrates vault secrets and runs Ansible here (names only on the wire to Core)
4. Results appear on the controller under **Job results**, and as files under `results/`

Prefer secret **names** in playbooks: `{{ hayabusa_secret:key }}` or `<<SECRET:key>>`.
Do not embed live passwords.

## Playbooks

| Playbook | Tool |
|----------|------|
| `playbooks/rustscan.yml` | RustScan |
| `playbooks/nuclei.yml` | Nuclei |
| `playbooks/netexec.yml` | NetExec / nxc |
| `playbooks/metasploit.yml` | Metasploit |
| `playbooks/zap.yml` | OWASP ZAP |
| `playbooks/packet-capture.yml` | tcpdump / Zeek |
| `playbooks/prowler.yml` | Prowler |
| `playbooks/trivy.yml` | Trivy |
| `playbooks/bloodhound.yml` | BloodHound.py |

## Common extra-vars

- `secops_execute=true` — actually run the tool (default is prefight only)
- `secops_target=` — host/URL/path as required by the tool
- `secops_cli_args=` — optional free-form argv string (shell-split) for custom runs
- `secops_timeout_sec=` — async timeout (seconds)

Example:

```bash
ansible-playbook playbooks/nuclei.yml \
  -e secops_execute=true \
  -e secops_target=https://lab.example \
  -e secops_timeout_sec=300
```

## Not Security & Fire

Building/PACS/VMS/fire content lives under `../security-fire/`. Keep this directory named `Security`.
