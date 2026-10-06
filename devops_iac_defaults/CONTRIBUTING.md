# Contributing to Hayabusa Infrastructure Templates

Default OpenTofu (Creation) and Ansible (Configuration) trees for the Fleet console.

## PR checklist

- [ ] Paths stay under `OpenTofu/` (Creation) or `Ansible/` (Configuration) — no cross-engine nests
- [ ] Working ZTP dispatch scripts (`*-dispatch`, `ztp.sh`, vendor `.py`) are not removed; only true junk (`.tmp`, `.backup`) or proven duplicate *non-script* copies may go
- [ ] `OpenTofu/ztp/` ↔ `Ansible/ztp/` mirrors are intentional — keep both tabs working
- [ ] `Ansible/Security/` (SECops, capital S) and `Ansible/security-fire/` stay separate
- [ ] New IoT vendors copy from `Ansible/iot/_template/`; prefer adding device classes over deleting vendors
- [ ] Identical `requirements.txt` / `versions.tf` / cloud-init examples prefer symlinks into `_shared/` or `OpenTofu/templates/`
- [ ] `python3 scripts/check_iac_tree.py .` passes (CI runs this)
- [ ] No `.env` files staged (use `.env.example` only)
- [ ] SCADA/OpenPLC and ZTP dispatch changes are additive or proven bugfixes — not drive-by rewrites

## Do not

- Rewrite or delete vendor ZTP scripts that boot/configure devices unless replacing with an equivalent
- Overwrite residential `*-router-api` / `*-switch-api` apps that already work — scaffold new ones from `_shared/fastapi_skeleton`
- Rename `Ansible/Security/` — Core Security tab and SECops queue hard-depend on it
- Hand-edit only the baked Core defaults tree; change this repo and sync defaults from here
- Commit secrets (API keys, passwords, tokens)

## Secrets

Run gitleaks locally when possible. Never commit `.env`. See [docs/SECRET_ROTATION.md](docs/SECRET_ROTATION.md).
