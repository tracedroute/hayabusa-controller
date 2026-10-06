# Workspace migration (Fleet console seeds)

How OpenTofu/Ansible defaults from this repo reach a user’s Fleet crafting workspace.

## One-way seed

```
GitHub (this repo)
  → devops_iac_defaults (controller / Core bake path)
    → per-user workspace on first open / seed
```

Controller ↔ Core sync of the defaults tree is allowed and unchanged by hygiene CI.

## No-clobber rule

Workspace seed **never overwrites** files that already exist in the user’s tree.
- New paths from defaults appear on next seed/migrate.
- User edits to playbooks, ZTP JSON, residential APIs, etc. are preserved.
- Empty directories may be created for canonical children (`ztp`, `iot`, …).

## When to re-seed

| Situation | Action |
|-----------|--------|
| Brand-new workspace | Automatic seed from defaults |
| Defaults gained new vendor folders | Open console / trigger seed — new paths copy in; existing files stay |
| User wants a fresh copy of one file | Delete or rename the local file, then re-seed (only that path is restored) |
| Legacy nests (`Ansible/OpenTofu`, `OpenTofu/ansible`, old IoT folder names) | Core migration rewrites layout; content merged, not deleted |

## What not to do

- Don’t hand-edit only the baked image defaults and skip this GitHub repo.
- Don’t force-reset a whole workspace to defaults unless the operator intends to discard local work.
- Don’t merge Design & Deploy `catalog.json` snippets into the workspace seed tree.

## Related

- Layout + supported surface: [README.md](../README.md)
- PR / contribution rules: [CONTRIBUTING.md](../CONTRIBUTING.md)
- CI smoke labels: [SMOKE_MATRIX.md](SMOKE_MATRIX.md)
- Secret rotation after history purge: [SECRET_ROTATION.md](SECRET_ROTATION.md)

## Design & Deploy → Fleet deep links

Fleet Console bridge templates in Design & Deploy expose **Open in Fleet**, which navigates to:

```
/workstations?devops=1&path=<workspace_rel>&mode=creation|configuration|security
```

The devops-iac console auto-opens, seeds if needed (no-clobber), and browses or edits that path.
