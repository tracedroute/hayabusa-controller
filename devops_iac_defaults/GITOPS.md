# GitOps placeholders

When GitOps is enabled, this tree is **not** the editable source of truth.
Edit the configured GitHub/GitLab repository instead.

Playbooks must use secret **names** only (values stay on the controller vault). Prefer:

- `{{ hayabusa_secret:KEY }}`
- `<<SECRET:KEY>>`

Hayabusa Core recognizes those forms. Legacy `lookup('env', 'HAYABUSA_SECRET_…')` still hydrates here but is not preferred.

See `docs/GITOPS.md` (controller) and `docs/GITOPS-CORE.md` (Hayabusa Core: webhooks and who pulls Git).
