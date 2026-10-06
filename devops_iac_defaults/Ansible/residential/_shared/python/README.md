# residential_shared (opt-in)

Helpers for **new** residential FastAPI apps. Do not rewrite existing `*-router-api` /
`*-switch-api` trees to use this unless deliberately migrating one device at a time.

```bash
export PYTHONPATH="Ansible/residential/_shared/python:$PYTHONPATH"
python -c "from residential_shared import health_payload; print(health_payload(device='x', reachable=True))"
```
