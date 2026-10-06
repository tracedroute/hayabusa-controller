# GitOps setup (GitHub / GitLab)

Opt-in GitOps makes a remote Git repository the source of truth for Ansible and OpenTofu.

**Who talks to GitLab/GitHub:** **Hayabusa Core** (not this controller). Webhooks and Git API pulls terminate on Core. Core then pushes files onto the connected controller. Core-facing detail: `docs/GITOPS-CORE.md` (in the Hayabusa repo).

**Push-to-controller model:** on GitLab/GitHub webhook (or Sync now / poll), **Hayabusa Core** fetches the repo, updates its workspace, then **pushes** `Ansible/` and `OpenTofu/` onto the **connected controller** via `iac.import_sync`. Packaged **default playbooks in the console are never overwritten**.

When GitOps is **enabled**, local UI edits on the controller workspace are blocked (edit the Git repo instead). Secrets and LAN approve/hydrate stay on the controller.

Switching back to **Novice** (setup redo → Novice) requests a final push from Hayabusa onto this controller, then disables GitOps and re-seeds any *missing* packaged defaults only (`--ignore-existing`).

## Prerequisites

1. Controller connected to Hayabusa over the mesh bridge.
2. Admin role with `manage_gitops` (included in builtin `admin`).
3. `git` installed on the **Hayabusa** host/image (not required on the controller image).

## 1. Create vault secrets on the controller

In **Secrets**, create (category **GitOps** recommended):

| Key (example) | Kind | Value |
|---|---|---|
| `gitops_github_pat` | token | Fine-grained PAT / deploy key with **Contents: Read** on that repo only (no org admin) |
| `gitops_webhook_secret` | token | Random secret **≥ 16 characters** (Core rejects shorter / empty) |

For GitLab: use a Project Access Token or Deploy Token with `read_repository` (add `write_repository` only if you use publish-owned), and the same webhook secret pattern.

**Never put real passwords in the Git repo.** Use secret **names** only (prefer these — Hayabusa Core recognizes them):

- `{{ hayabusa_secret:KEY }}`
- `<<SECRET:KEY>>`

(`lookup('env', 'HAYABUSA_SECRET_…')` still hydrates on this controller for legacy playbooks, but is not preferred and Core does not scan for it.)

Image Nest media refs hydrate the same way on LAN Approve (`<<IMAGE_NEST:…>>`). Operator guide: `docs/IMAGE-NEST-AND-WINDOWS-IMAGES.md`.

## 2. Configure GitOps on the controller

Open **GitOps** on the controller dashboard (or choose **Advanced** in first-run setup):

1. Provider: `github` or `gitlab`
2. Instance base URL: `https://github.com`, `https://gitlab.com`, or your self-hosted URL
3. Repository: `org/name`
4. Branch/ref: e.g. `main`
5. Path prefix (optional): subdirectory that contains `Ansible/` and/or `OpenTofu/`
6. Auth secret key + webhook secret key (vault keys from step 1)
7. Poll interval (fallback), default 600s

## 3. Webhooks

Point the repo webhook at **Hayabusa Core** (the hub) — **never** at this controller’s LAN address or port:

- GitHub: `https://<hayabusa-core>/api/gitops/webhook/github`
- GitLab: `https://<hayabusa-core>/api/gitops/webhook/gitlab`

Use the vault webhook secret as the shared secret / token. Each push notifies **Core**; Core pulls Git, then pushes non-default files onto this controller (`iac.import_sync`).

Inbound SoT path: `Git → Core → controller`.  
Outbound owned publish (team bindings) is separate: `controller → Git` for owned paths only.

## 4. Defaults protection

Files that exist in the packaged `devops_iac_defaults` tree (console defaults) are skipped on import. Custom / site playbooks and OpenTofu projects from Git land on the controller beside those defaults.

## 5. Disable / return to Novice

Uncheck **Enable GitOps** and Save, or redo setup and choose Novice. Local workspace editing returns; missing defaults are restored without deleting Git-synced custom content.

## 6. Security notes

- Prefer **OAuth Link** for GitHub/GitLab identity used by publish-owned. **Declare login** is lab-only and is blocked when that provider’s OAuth app is configured (override: `CONTROLLER_ALLOW_DECLARED_GIT_LINK=1`).
- Core rate-limits webhook POSTs per source IP (default 30/min). Put the same limit on your reverse proxy in production.
- Full Core-facing hardening checklist: `docs/GITOPS-CORE.md` → **Security hardening**.
