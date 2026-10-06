"""Controller-local RBAC: roles, permissions, users, teams, playbook ownership.

The appliance stores playbooks and secrets. Ansible/OpenTofu are not run here;
owned playbooks sync to the matching Hayabusa user session for execution.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any

_LOCK = threading.RLock()

PERMISSIONS: dict[str, str] = {
    "manage_rbac": "Create roles, assign permissions, manage users and teams",
    "read_infrastructure": "View infrastructure (networks, VMs, containers, playbooks, catalogs)",
    "write_infrastructure": "Create and modify infrastructure (networks, VMs, containers, playbooks)",
    "read_secrets": "View secret catalog (category, host, label — not values)",
    "manage_secrets": "Create, edit values, rotate, and delete vault secrets",
    "read_playbooks": "Read playbooks you own or your teams own",
    "write_playbooks": "Create and edit playbooks you own or your teams own",
    "approve_jobs": "Approve or deny pending Hayabusa jobs on this LAN (playbooks, scans, and controller jobs)",
    "approve_playbooks": "Approve or deny Ansible and OpenTofu playbooks for Hayabusa execution",
    "approve_ztp": "Approve ZTP scripts and enable/disable site DHCP on this LAN",
    "sync_hayabusa": "Sync owned playbooks to your Hayabusa session workspace",
    "read_all_playbooks": "Read all playbooks on this controller (admin)",
    "write_all_playbooks": "Edit all playbooks on this controller (admin)",
    "read_image_nest": "View Image Nest ISO bank, manifests, and bake status",
    "manage_image_nest": "Upload ISOs, run strip/full bake, and manage the Image Nest bank",
    "manage_gitops": "Configure GitOps (GitHub/GitLab) as the Ansible/OpenTofu source of truth",
}

# Higher rank = more power (Discord-style). Owner/admin is the top.
BUILTIN_ROLE_META: dict[str, dict[str, Any]] = {
    "admin": {
        "rank": 100,
        "label": "Owner",
        "permissions": list(PERMISSIONS.keys()),
    },
    "operator": {
        "rank": 60,
        "label": "Operator",
        "permissions": [
            "read_infrastructure",
            "write_infrastructure",
            "read_secrets",
            "manage_secrets",
            "read_playbooks",
            "write_playbooks",
            "sync_hayabusa",
            "read_image_nest",
            "manage_image_nest",
        ],
    },
    "playbook_approver": {
        "rank": 40,
        "label": "Approver",
        "permissions": [
            "approve_jobs",
            "approve_playbooks",
            "approve_ztp",
            "read_infrastructure",
            "read_playbooks",
        ],
    },
    "viewer": {
        "rank": 20,
        "label": "Viewer",
        "permissions": [
            "read_infrastructure",
            "read_playbooks",
            "read_secrets",
            "read_image_nest",
        ],
    },
    "visitor": {
        "rank": 0,
        "label": "Visitor",
        "permissions": [],
    },
}

# Back-compat alias used by older code paths.
BUILTIN_ROLES: dict[str, list[str]] = {
    name: list(meta["permissions"]) for name, meta in BUILTIN_ROLE_META.items()
}

ROLE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,31}$")

# Granting a role requires the actor's highest rank to be at least this far above the target.
ROLE_GRANT_GAP = 1

# Infra expands to owned/team playbook + secrets + Image Nest access — NOT site-wide
# read_all/write_all (those stay Owner/admin-only via the admin role).
_INFRA_READ_EXPAND = frozenset(
    {"read_playbooks", "read_secrets", "read_image_nest"}
)
_INFRA_WRITE_EXPAND = frozenset(
    {
        "write_playbooks",
        "manage_secrets",
        "manage_image_nest",
        "sync_hayabusa",
        "read_infrastructure",
        "read_playbooks",
        "read_secrets",
        "read_image_nest",
    }
)

USER_KEY_RE = re.compile(r"^[a-zA-Z0-9._@+:-]{1,128}$")
TEAM_KEY_RE = re.compile(r"^[a-zA-Z0-9._:-]{1,64}$")


def _bare_key(raw: str = "") -> str:
    return re.sub(r"[^a-zA-Z0-9_.@+:-]", "", str(raw or "").strip()).lower()[:128]


def _is_opaque_subject(raw: str = "") -> bool:
    """True for OAuth subject-looking ids (long digit strings)."""
    s = str(raw or "").strip()
    if s.isdigit() and len(s) >= 12:
        return True
    return False


def _norm_user_key(username: str = "", email: str = "", sub: str = "") -> str:
    """Prefer email, then human username, then OAuth subject."""
    em = _bare_key(email)
    if em and "@" in em:
        return em
    u = _bare_key(username)
    if u and not _is_opaque_subject(u):
        return u
    for raw in (sub, username, email):
        k = _bare_key(raw)
        if k:
            return k
    return ""


def _display_name_for_user(user: dict[str, Any] | None) -> str:
    u = user or {}
    email = str(u.get("email") or "").strip()
    username = str(u.get("username") or "").strip()
    sub = str(u.get("sub") or "").strip()
    key = str(u.get("user_key") or "").strip()
    if email and (not username or username == sub or username == key or _is_opaque_subject(username)):
        return email
    if username and not _is_opaque_subject(username):
        return username
    if email:
        return email
    if username:
        return username
    return key or "user"


def _now() -> float:
    return time.time()


def _role_slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9_]+", "_", str(name or "").strip().lower()).strip("_")[:32]
    return slug


class RbacStore:
    def __init__(self, data_dir: Path) -> None:
        self.path = Path(data_dir) / "rbac.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _empty(self) -> dict[str, Any]:
        roles = {}
        for name, meta in BUILTIN_ROLE_META.items():
            roles[name] = {
                "permissions": list(meta["permissions"]),
                "builtin": True,
                "rank": int(meta["rank"]),
                "label": str(meta["label"]),
            }
        return {
            "version": 2,
            "roles": roles,
            "users": {},
            "teams": {},
            "playbook_owners": {},
            "aliases": {},
        }

    def _normalize_role_meta(self, name: str, meta: dict[str, Any] | None) -> dict[str, Any]:
        builtin = name in BUILTIN_ROLE_META
        seed = BUILTIN_ROLE_META.get(name) or {}
        raw = dict(meta or {})
        if builtin:
            # Permissions/label stay in sync with code; rank may be reordered by Owner.
            if name == "admin":
                rank = 100
            else:
                try:
                    rank = int(raw["rank"]) if raw.get("rank") is not None else int(seed.get("rank") or 0)
                except (TypeError, ValueError):
                    rank = int(seed.get("rank") or 0)
                rank = max(0, min(99, rank))
            return {
                "permissions": list(seed.get("permissions") or []),
                "builtin": True,
                "rank": rank,
                "label": str(seed.get("label") or name),
            }
        perms = [str(p) for p in (raw.get("permissions") or []) if str(p) in PERMISSIONS]
        try:
            rank = int(raw.get("rank"))
        except (TypeError, ValueError):
            rank = 10
        rank = max(0, min(99, rank))
        label = str(raw.get("label") or name).strip()[:64] or name
        return {
            "permissions": perms,
            "builtin": False,
            "rank": rank,
            "label": label,
        }

    def _ensure_builtins(self, state: dict[str, Any]) -> None:
        roles = state.setdefault("roles", {})
        for name, seed in BUILTIN_ROLE_META.items():
            roles[name] = self._normalize_role_meta(name, roles.get(name) or seed)
        # Normalize custom roles too.
        for name, meta in list(roles.items()):
            if name in BUILTIN_ROLE_META:
                continue
            if not isinstance(meta, dict):
                roles.pop(name, None)
                continue
            roles[name] = self._normalize_role_meta(name, meta)

    def _load(self) -> dict[str, Any]:
        try:
            if not self.path.is_file():
                state = self._empty()
                self._save(state)
                return state
            with self.path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                return self._empty()
            data.setdefault("roles", {})
            data.setdefault("users", {})
            data.setdefault("teams", {})
            data.setdefault("playbook_owners", {})
            data.setdefault("aliases", {})
            self._ensure_builtins(data)
            self._link_duplicate_identities(data)
            if self._rekey_opaque_users(data):
                data["_identity_link_dirty"] = True
            if data.pop("_identity_link_dirty", None):
                try:
                    self._save(data)
                except OSError:
                    pass
            return data
        except (OSError, ValueError, TypeError):
            return self._empty()

    def _rekey_opaque_users(self, state: dict[str, Any]) -> bool:
        """Move digit-subject keys to email keys when email is known."""
        users = state.get("users") or {}
        aliases = state.setdefault("aliases", {})
        dirty = False
        for old_key in list(users.keys()):
            if not _is_opaque_subject(old_key):
                continue
            u = users.get(old_key)
            if not isinstance(u, dict):
                continue
            em = _bare_key(str(u.get("email") or ""))
            if not em or "@" not in em or em == old_key or em in users:
                continue
            u["user_key"] = em
            if not str(u.get("provider") or "").strip():
                if _is_opaque_subject(str(u.get("sub") or old_key)):
                    u["provider"] = "google"
            users[em] = u
            users.pop(old_key, None)
            aliases[old_key] = em
            aliases[em] = em
            sub = _bare_key(str(u.get("sub") or ""))
            if sub:
                aliases[sub] = em
            dirty = True
        state["users"] = users
        return dirty

    def _save(self, state: dict[str, Any]) -> None:
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _link_duplicate_identities(self, state: dict[str, Any]) -> None:
        """Same email / username must share one RBAC row (TOTP vs Google sub)."""
        users = state.get("users") or {}
        aliases = state.setdefault("aliases", {})
        by_email: dict[str, list[str]] = {}
        for uk, u in users.items():
            if not isinstance(u, dict):
                continue
            em = _bare_key(str(u.get("email") or ""))
            if em and "@" in em:
                by_email.setdefault(em, []).append(uk)
            for extra in (u.get("sub"), u.get("username"), u.get("user_key"), uk):
                k = _bare_key(str(extra or ""))
                if k and k != uk:
                    aliases.setdefault(k, uk)
        dirty = False
        for em, keys in by_email.items():
            uniq = []
            for k in keys:
                if k not in uniq:
                    uniq.append(k)
            if len(uniq) < 2:
                canonical = uniq[0] if uniq else ""
                if canonical:
                    aliases[em] = canonical
                    local = em.split("@", 1)[0]
                    if local:
                        aliases.setdefault(local, canonical)
                continue
            def _score(uk: str) -> tuple:
                u = users.get(uk) or {}
                roles = list(u.get("roles") or [])
                return (
                    1 if "admin" in roles else 0,
                    0 if uk in {"admin", "manual:admin"} or str(uk).startswith("manual:") else 1,
                    -float(u.get("created_at") or 0),
                )
            canonical = sorted(uniq, key=_score, reverse=True)[0]
            canon_u = users.get(canonical) or {}
            if "admin" not in list(canon_u.get("roles") or []):
                # First real person with this mailbox is admin.
                canon_u["roles"] = ["admin"]
                dirty = True
            aliases[em] = canonical
            local = em.split("@", 1)[0]
            if local:
                aliases[local] = canonical
            for uk in uniq:
                if uk == canonical:
                    continue
                other = users.get(uk) or {}
                aliases[uk] = canonical
                if other.get("sub"):
                    aliases[_bare_key(str(other.get("sub")))] = canonical
                if "admin" in list(other.get("roles") or []):
                    if "admin" not in list(canon_u.get("roles") or []):
                        canon_u["roles"] = ["admin"]
                        dirty = True
                # Fold duplicate row into canonical, then drop it.
                if other.get("email") and not canon_u.get("email"):
                    canon_u["email"] = other.get("email")
                users.pop(uk, None)
                dirty = True
        if dirty:
            state["users"] = users
            state["aliases"] = aliases
            state["_identity_link_dirty"] = True

    def resolve_user_key(self, username: str = "", email: str = "", sub: str = "") -> str:
        cands: list[str] = []
        for raw in (sub, username, email):
            k = _bare_key(raw)
            if k and k not in cands:
                cands.append(k)
        with _LOCK:
            state = self._load()
            return self._resolve_in_state(state, cands, email)

    def _resolve_in_state(self, state: dict[str, Any], cands: list[str], email: str = "") -> str:
        users = state.get("users") or {}
        aliases = state.get("aliases") or {}
        for k in cands:
            dest = aliases.get(k) or k
            if dest in users:
                return dest
            if k in users:
                return k
        em = _bare_key(email)
        if em:
            dest = aliases.get(em)
            if dest in users:
                return dest
            for uk, u in users.items():
                if not isinstance(u, dict):
                    continue
                if _bare_key(str(u.get("email") or "")) == em:
                    return uk
                if _bare_key(str(u.get("sub") or "")) == em:
                    return uk
        return cands[0] if cands else ""

    def ensure_bootstrap_admin(
        self,
        *,
        username: str,
        email: str = "",
        sub: str = "",
        provider: str = "",
        touch_activity: bool = False,
    ) -> str:
        """First real sign-in is admin. Later identities with the same email join that admin."""
        primary = _norm_user_key(username, email, sub)
        if not primary:
            return ""
        with _LOCK:
            state = self._load()
            users = state["users"]
            aliases = state.setdefault("aliases", {})
            cands = []
            for raw in (sub, username, email, primary):
                k = _bare_key(raw)
                if k and k not in cands:
                    cands.append(k)
            canonical = self._resolve_in_state(state, cands, email)
            if canonical in users:
                u = users[canonical]
                if username and (
                    not u.get("username")
                    or u.get("username") == canonical
                    or _is_opaque_subject(str(u.get("username") or ""))
                ):
                    if username and not _is_opaque_subject(username):
                        u["username"] = str(username)[:120]
                if email:
                    u["email"] = str(email)[:200]
                if sub:
                    u["sub"] = str(sub)[:200]
                if provider:
                    u["provider"] = str(provider).strip().lower()[:32]
                if touch_activity:
                    u["last_seen_at"] = _now()
                for k in cands:
                    if k != canonical:
                        aliases[k] = canonical
                if email:
                    aliases[_bare_key(email)] = canonical

                # Re-key opaque Google/Discord subjects to email when available.
                em = _bare_key(email)
                if (
                    em
                    and "@" in em
                    and _is_opaque_subject(canonical)
                    and em != canonical
                    and em not in users
                ):
                    u["user_key"] = em
                    users[em] = u
                    users.pop(canonical, None)
                    aliases[canonical] = em
                    aliases[em] = em
                    if sub:
                        aliases[_bare_key(sub)] = em
                    canonical = em
                else:
                    u["user_key"] = canonical

                u["updated_at"] = _now()
                self._save(state)
                return canonical
            env_keys = {"admin", "manual:admin"}
            human_admin = any(
                isinstance(u, dict)
                and "admin" in list(u.get("roles") or [])
                and uk not in env_keys
                and not str(uk).startswith("manual:")
                for uk, u in users.items()
            )
            roles = ["admin"] if not human_admin else ["visitor"]
            now = _now()
            users[primary] = {
                "user_key": primary,
                "username": str(username or primary)[:120],
                "email": str(email or "")[:200],
                "sub": str(sub or "")[:200],
                "provider": str(provider or "").strip().lower()[:32],
                "roles": roles,
                "team_ids": [],
                "created_at": now,
                "updated_at": now,
                "last_seen_at": now if touch_activity else None,
            }
            if email:
                aliases[_bare_key(email)] = primary
            if sub and _bare_key(sub) != primary:
                aliases[_bare_key(sub)] = primary
            self._save(state)
            return primary

    def _public_user(self, user: dict[str, Any]) -> dict[str, Any]:
        u = dict(user or {})
        email = str(u.get("email") or "").strip()
        username = str(u.get("username") or "").strip()
        provider = str(u.get("provider") or "").strip().lower()
        if not provider:
            key = str(u.get("user_key") or "")
            if key.startswith("manual:") or key in {"admin", "manual:admin"}:
                provider = "manual"
            elif _is_opaque_subject(key) or _is_opaque_subject(str(u.get("sub") or "")):
                provider = "google"
            else:
                provider = "unknown"
        display = _display_name_for_user(u)
        # Never surface opaque ids as the primary label.
        username_out = username if username and not _is_opaque_subject(username) else (
            email.split("@")[0] if email and "@" in email else display
        )
        return {
            "user_key": str(u.get("user_key") or ""),
            "username": username_out,
            "email": email,
            "display_name": display,
            "sub": str(u.get("sub") or ""),
            "provider": provider,
            "roles": list(u.get("roles") or []),
            "team_ids": list(u.get("team_ids") or []),
            "created_at": u.get("created_at"),
            "updated_at": u.get("updated_at"),
            "last_seen_at": u.get("last_seen_at") or u.get("updated_at"),
            "joined_at": u.get("created_at"),
        }

    def public_catalog(self) -> dict[str, Any]:
        with _LOCK:
            state = self._load()
        roles_out = {}
        for name, meta in sorted(
            (state.get("roles") or {}).items(),
            key=lambda kv: (-int((kv[1] or {}).get("rank") or 0), kv[0]),
        ):
            m = self._normalize_role_meta(name, meta if isinstance(meta, dict) else {})
            roles_out[name] = {
                "permissions": list(m.get("permissions") or []),
                "builtin": bool(m.get("builtin")),
                "rank": int(m.get("rank") or 0),
                "label": str(m.get("label") or name),
            }
        users_out = [
            self._public_user(u)
            for u in (state.get("users") or {}).values()
            if isinstance(u, dict)
        ]
        return {
            "ok": True,
            "permissions": [{"id": k, "description": v} for k, v in PERMISSIONS.items()],
            "roles": roles_out,
            "users": users_out,
            "teams": list((state.get("teams") or {}).values()),
            "playbook_owners": dict(state.get("playbook_owners") or {}),
            "hierarchy": {
                "grant_gap": ROLE_GRANT_GAP,
                "note": "Higher rank is more powerful. You may only edit roles below you and grant roles at most one rank below your highest role.",
            },
        }

    def _role_rank(self, state: dict[str, Any], role_name: str) -> int:
        meta = state.get("roles", {}).get(role_name) or {}
        try:
            return int(meta.get("rank") or 0)
        except (TypeError, ValueError):
            return 0

    def _highest_rank_in_state(self, state: dict[str, Any], user_key: str) -> int:
        key = self._resolve_in_state(state, [_bare_key(user_key)] if user_key else [], user_key)
        user = state.get("users", {}).get(key) or {}
        ranks = [self._role_rank(state, r) for r in (user.get("roles") or [])]
        return max(ranks) if ranks else 0

    def highest_rank(self, user_key: str) -> int:
        with _LOCK:
            state = self._load()
            return self._highest_rank_in_state(state, user_key)

    def grant_ceiling(self, user_key: str) -> int:
        """Max rank the actor may assign to others (one below their highest)."""
        return max(0, self.highest_rank(user_key) - ROLE_GRANT_GAP)

    def grantable_roles(self, actor_key: str) -> list[str]:
        with _LOCK:
            state = self._load()
            ceiling = max(0, self._highest_rank_in_state(state, actor_key) - ROLE_GRANT_GAP)
            out = []
            for name, meta in (state.get("roles") or {}).items():
                if self._role_rank(state, name) <= ceiling:
                    out.append(name)
            return sorted(out, key=lambda n: (-self._role_rank(state, n), n))

    def _expand_permissions(self, perms: set[str]) -> set[str]:
        out = set(perms)
        if "read_infrastructure" in out:
            out |= {p for p in _INFRA_READ_EXPAND if p in PERMISSIONS}
        if "write_infrastructure" in out:
            out |= {p for p in _INFRA_WRITE_EXPAND if p in PERMISSIONS}
            out.add("read_infrastructure")
        # approve_jobs covers general job approval including playbook jobs.
        if "approve_jobs" in out:
            out.add("approve_playbooks")
        return {p for p in out if p in PERMISSIONS}

    def user_roles(self, user_key: str) -> list[str]:
        with _LOCK:
            state = self._load()
            key = self._resolve_in_state(state, [_bare_key(user_key)] if user_key else [], user_key)
            user = state["users"].get(key) or {}
            return [str(r) for r in (user.get("roles") or [])]

    def is_owner_or_admin(self, user_key: str) -> bool:
        """True for the Owner/admin ladder top (builtin admin role or rank >= 100)."""
        roles = self.user_roles(user_key)
        if "admin" in roles:
            return True
        return self.highest_rank(user_key) >= 100

    def user_permissions(self, user_key: str) -> set[str]:
        with _LOCK:
            state = self._load()
            key = self._resolve_in_state(state, [_bare_key(user_key)] if user_key else [], user_key)
            user = state["users"].get(key) or {}
            roles = list(user.get("roles") or [])
            perms: set[str] = set()
            for role_name in roles:
                meta = state["roles"].get(role_name) or {}
                for p in meta.get("permissions") or []:
                    if p in PERMISSIONS:
                        perms.add(str(p))
            return self._expand_permissions(perms)

    def has_permission(self, user_key: str, permission: str) -> bool:
        return permission in self.user_permissions(user_key)

    def create_role(
        self,
        *,
        actor_key: str,
        name: str,
        permissions: list[str] | None = None,
        rank: int | None = None,
        label: str = "",
    ) -> dict[str, Any]:
        slug = _role_slug(name)
        if not slug or not ROLE_NAME_RE.match(slug):
            return {"ok": False, "error": "invalid role name (use lowercase letters, numbers, underscore)", "code": "invalid_name"}
        if slug in BUILTIN_ROLE_META:
            return {"ok": False, "error": "cannot recreate a builtin role", "code": "builtin"}
        with _LOCK:
            state = self._load()
            if slug in (state.get("roles") or {}):
                return {"ok": False, "error": "role already exists", "code": "exists"}
            actor_rank = self._highest_rank_in_state(state, actor_key)
            if actor_rank <= 0:
                return {"ok": False, "error": "insufficient rank to create roles", "code": "forbidden"}
            ceiling = max(0, actor_rank - ROLE_GRANT_GAP)
            try:
                want_rank = int(rank) if rank is not None else min(10, ceiling)
            except (TypeError, ValueError):
                want_rank = min(10, ceiling)
            want_rank = max(0, min(ceiling, want_rank))
            perms = [str(p) for p in (permissions or []) if str(p) in PERMISSIONS]
            # Only Owner (top) may attach manage_rbac to a custom role.
            if "manage_rbac" in perms and actor_rank < 100:
                return {
                    "ok": False,
                    "error": "only the Owner can grant manage_rbac on a role",
                    "code": "forbidden_perm",
                }
            state["roles"][slug] = {
                "permissions": perms,
                "builtin": False,
                "rank": want_rank,
                "label": str(label or name or slug).strip()[:64] or slug,
            }
            self._save(state)
            return {"ok": True, "role": {"id": slug, **state["roles"][slug]}}

    def update_role(
        self,
        *,
        actor_key: str,
        name: str,
        permissions: list[str] | None = None,
        rank: int | None = None,
        label: str | None = None,
    ) -> dict[str, Any]:
        slug = _role_slug(name)
        with _LOCK:
            state = self._load()
            roles = state.get("roles") or {}
            if slug not in roles:
                return {"ok": False, "error": "role not found", "code": "not_found"}
            meta = self._normalize_role_meta(slug, roles.get(slug))
            actor_rank = self._highest_rank_in_state(state, actor_key)
            target_rank = int(meta.get("rank") or 0)
            if target_rank >= actor_rank:
                return {
                    "ok": False,
                    "error": "you can only modify roles ranked below yours",
                    "code": "forbidden",
                }
            if meta.get("builtin"):
                return {
                    "ok": False,
                    "error": "builtin roles cannot be edited — create a custom role instead",
                    "code": "builtin",
                }
            ceiling = max(0, actor_rank - ROLE_GRANT_GAP)
            if permissions is not None:
                perms = [str(p) for p in permissions if str(p) in PERMISSIONS]
                if "manage_rbac" in perms and actor_rank < 100:
                    return {
                        "ok": False,
                        "error": "only the Owner can grant manage_rbac on a role",
                        "code": "forbidden_perm",
                    }
                meta["permissions"] = perms
            if rank is not None:
                try:
                    want_rank = int(rank)
                except (TypeError, ValueError):
                    return {"ok": False, "error": "invalid rank", "code": "invalid_rank"}
                want_rank = max(0, min(ceiling, want_rank))
                meta["rank"] = want_rank
            if label is not None:
                meta["label"] = str(label or slug).strip()[:64] or slug
            meta["builtin"] = False
            state["roles"][slug] = meta
            self._save(state)
            return {"ok": True, "role": {"id": slug, **meta}}

    def delete_role(self, *, actor_key: str, name: str) -> dict[str, Any]:
        slug = _role_slug(name)
        with _LOCK:
            state = self._load()
            roles = state.get("roles") or {}
            if slug not in roles:
                return {"ok": False, "error": "role not found", "code": "not_found"}
            meta = self._normalize_role_meta(slug, roles.get(slug))
            if meta.get("builtin"):
                return {"ok": False, "error": "cannot delete builtin roles", "code": "builtin"}
            actor_rank = self._highest_rank_in_state(state, actor_key)
            if int(meta.get("rank") or 0) >= actor_rank:
                return {
                    "ok": False,
                    "error": "you can only delete roles ranked below yours",
                    "code": "forbidden",
                }
            roles.pop(slug, None)
            for u in (state.get("users") or {}).values():
                if not isinstance(u, dict):
                    continue
                u["roles"] = [r for r in (u.get("roles") or []) if r != slug]
                if not u["roles"]:
                    u["roles"] = ["visitor"]
            self._save(state)
            return {"ok": True, "deleted": slug}

    def reorder_roles(self, *, actor_key: str, order: list[str]) -> dict[str, Any]:
        """Persist a new hierarchy order (highest → lowest). Owner is pinned at rank 100.

        Ranks are reassigned evenly below the actor's grant ceiling. Roles at or above
        the actor's rank cannot be moved.
        """
        cleaned: list[str] = []
        seen: set[str] = set()
        for raw in order or []:
            slug = _role_slug(str(raw or ""))
            if not slug or slug in seen:
                continue
            seen.add(slug)
            cleaned.append(slug)
        if not cleaned:
            return {"ok": False, "error": "order list is empty", "code": "invalid"}

        with _LOCK:
            state = self._load()
            roles = state.get("roles") or {}
            actor_rank = self._highest_rank_in_state(state, actor_key)
            if actor_rank <= 0:
                return {"ok": False, "error": "insufficient rank to reorder roles", "code": "forbidden"}

            unknown = [r for r in cleaned if r not in roles]
            if unknown:
                return {
                    "ok": False,
                    "error": f"unknown roles: {', '.join(unknown[:5])}",
                    "code": "not_found",
                }

            # Roles the actor cannot move stay fixed at the top (by current rank).
            pinned = sorted(
                [n for n, m in roles.items() if int((m or {}).get("rank") or 0) >= actor_rank],
                key=lambda n: (-int((roles.get(n) or {}).get("rank") or 0), n),
            )
            # Ensure Owner/admin is always the absolute top when present.
            if "admin" in roles and "admin" not in pinned:
                pinned = ["admin"] + [p for p in pinned if p != "admin"]
            elif "admin" in pinned:
                pinned = ["admin"] + [p for p in pinned if p != "admin"]

            movable_requested = [r for r in cleaned if r not in pinned]
            # Include any movable roles omitted from the client payload (append by current rank).
            movable_all = [
                n
                for n, m in sorted(
                    roles.items(),
                    key=lambda kv: (-int((kv[1] or {}).get("rank") or 0), kv[0]),
                )
                if n not in pinned
            ]
            for name in movable_all:
                if name not in movable_requested:
                    movable_requested.append(name)

            ceiling = max(0, actor_rank - ROLE_GRANT_GAP)
            m = len(movable_requested)
            for i, name in enumerate(movable_requested):
                meta = self._normalize_role_meta(name, roles.get(name))
                if m <= 1:
                    new_rank = min(ceiling, 50)
                else:
                    new_rank = int(round(ceiling * (m - 1 - i) / (m - 1)))
                new_rank = max(0, min(ceiling, new_rank))
                meta["rank"] = new_rank
                # Keep builtin flag; permissions already normalized from seed for builtins.
                roles[name] = meta

            # Re-assert pinned ranks (Owner always 100).
            for name in pinned:
                meta = self._normalize_role_meta(name, roles.get(name))
                if name == "admin":
                    meta["rank"] = 100
                roles[name] = meta

            state["roles"] = roles
            self._save(state)
            ordered = pinned + movable_requested
            return {
                "ok": True,
                "order": ordered,
                "roles": {
                    n: {
                        "id": n,
                        "label": (roles[n] or {}).get("label") or n,
                        "rank": int((roles[n] or {}).get("rank") or 0),
                        "builtin": bool((roles[n] or {}).get("builtin")),
                        "permissions": list((roles[n] or {}).get("permissions") or []),
                    }
                    for n in ordered
                },
            }

    def upsert_user(
        self,
        *,
        username: str,
        email: str = "",
        sub: str = "",
        roles: list[str] | None = None,
        team_ids: list[str] | None = None,
        actor_key: str = "",
        user_key: str = "",
        provider: str = "",
    ) -> dict[str, Any]:
        with _LOCK:
            state = self._load()
            resolved = ""
            if user_key:
                resolved = self._resolve_in_state(state, [_bare_key(user_key)], email)
            if not resolved:
                resolved = self._resolve_in_state(
                    state,
                    [_bare_key(x) for x in (sub, username, email) if x],
                    email,
                )
            if resolved and resolved in (state.get("users") or {}):
                key = resolved
            else:
                key = _norm_user_key(username, email, sub)
            if not key or not USER_KEY_RE.match(key):
                return {"ok": False, "error": "invalid user key"}
            prev = state["users"].get(key) or {}
            requested = list(roles) if roles is not None else list(prev.get("roles") or ["viewer"])
            valid_roles = [r for r in requested if r in state["roles"]]
            if not valid_roles:
                valid_roles = list(prev.get("roles") or ["viewer"]) or ["viewer"]

            if actor_key:
                actor = self._resolve_in_state(state, [_bare_key(actor_key)], actor_key)
                actor_rank = self._highest_rank_in_state(state, actor)
                ceiling = max(0, actor_rank - ROLE_GRANT_GAP)
                # Cannot change users who outrank or equal you (except self soft update of metadata).
                target_prev_rank = max(
                    [self._role_rank(state, r) for r in (prev.get("roles") or [])] or [0]
                )
                if prev and key != actor and target_prev_rank >= actor_rank:
                    return {
                        "ok": False,
                        "error": "you cannot modify a user at your rank or higher",
                        "code": "forbidden",
                    }
                for r in valid_roles:
                    if self._role_rank(state, r) > ceiling:
                        return {
                            "ok": False,
                            "error": f"you can only assign roles at rank {ceiling} or below (role '{r}' is too high)",
                            "code": "forbidden_role",
                        }
                # Prevent removing your own Owner/admin role accidentally via self-edit.
                if key == actor and "admin" in list(prev.get("roles") or []) and "admin" not in valid_roles:
                    if actor_rank >= 100:
                        return {
                            "ok": False,
                            "error": "Owner cannot remove their own Owner role",
                            "code": "forbidden",
                        }

            valid_teams = [t for t in (team_ids or []) if t in state["teams"]]
            next_username = str(username or prev.get("username") or key)[:120]
            if _is_opaque_subject(next_username) and prev.get("username") and not _is_opaque_subject(str(prev.get("username") or "")):
                next_username = str(prev.get("username"))[:120]
            next_email = str(email or prev.get("email") or "")[:200]
            next_provider = str(provider or prev.get("provider") or "").strip().lower()[:32]
            state["users"][key] = {
                "user_key": key,
                "username": next_username,
                "email": next_email,
                "sub": str(sub or prev.get("sub") or "")[:200],
                "provider": next_provider,
                "roles": valid_roles,
                "team_ids": valid_teams if team_ids is not None else list(prev.get("team_ids") or []),
                "created_at": prev.get("created_at") or _now(),
                "updated_at": _now(),
                "last_seen_at": prev.get("last_seen_at"),
            }
            for tid, team in state["teams"].items():
                members = set(team.get("member_keys") or [])
                if tid in state["users"][key]["team_ids"]:
                    members.add(key)
                else:
                    members.discard(key)
                team["member_keys"] = sorted(members)
            self._save(state)
            return {"ok": True, "user": self._public_user(state["users"][key])}

    def create_team(self, *, name: str, member_keys: list[str] | None = None) -> dict[str, Any]:
        slug = re.sub(r"[^a-z0-9:-]+", "-", str(name or "").strip().lower()).strip("-")[:64]
        if not slug or not TEAM_KEY_RE.match(slug):
            return {"ok": False, "error": "invalid team name"}
        with _LOCK:
            state = self._load()
            if slug in state["teams"]:
                return {"ok": False, "error": "team already exists"}
            members = []
            for mk in member_keys or []:
                k = _norm_user_key(mk)
                if k in state["users"]:
                    members.append(k)
                    state["users"][k].setdefault("team_ids", [])
                    if slug not in state["users"][k]["team_ids"]:
                        state["users"][k]["team_ids"].append(slug)
            state["teams"][slug] = {
                "id": slug,
                "name": str(name or slug)[:120],
                "member_keys": sorted(set(members)),
                "created_at": _now(),
            }
            self._save(state)
            return {"ok": True, "team": state["teams"][slug]}

    def set_playbook_owner(
        self,
        path: str,
        *,
        owner_type: str,
        owner_id: str,
    ) -> dict[str, Any]:
        rel = str(path or "").strip().lstrip("/")
        if not rel or ".." in Path(rel).parts:
            return {"ok": False, "error": "invalid path"}
        owner_type = str(owner_type or "").strip().lower()
        owner_id = str(owner_id or "").strip()
        if owner_type not in {"user", "team"}:
            return {"ok": False, "error": "owner_type must be user or team"}
        with _LOCK:
            state = self._load()
            if owner_type == "user":
                owner_id = _norm_user_key(owner_id)
                if owner_id not in state["users"]:
                    return {"ok": False, "error": "unknown user"}
            else:
                if owner_id not in state["teams"]:
                    return {"ok": False, "error": "unknown team"}
            state["playbook_owners"][rel] = {
                "path": rel,
                "owner_type": owner_type,
                "owner_id": owner_id,
                "updated_at": _now(),
            }
            self._save(state)
            return {"ok": True, "owner": state["playbook_owners"][rel]}

    def playbook_owner(self, path: str) -> dict[str, Any] | None:
        rel = str(path or "").strip().lstrip("/")
        with _LOCK:
            state = self._load()
            own = state["playbook_owners"].get(rel)
            return dict(own) if isinstance(own, dict) else None

    def can_access_playbook(self, user_key: str, path: str, *, write: bool = False) -> bool:
        key = _norm_user_key(user_key)
        if not key:
            return False
        perms = self.user_permissions(key)
        if write and "write_all_playbooks" in perms:
            return True
        if (not write) and "read_all_playbooks" in perms:
            return True
        need = "write_playbooks" if write else "read_playbooks"
        if need not in perms and "write_playbooks" not in perms and "read_playbooks" not in perms:
            return False
        if write and "write_playbooks" not in perms and "write_all_playbooks" not in perms:
            return False
        rel = str(path or "").strip().lstrip("/")
        # Directory prefixes: allow if any owned child or exact owner on path / ancestor
        with _LOCK:
            state = self._load()
            user = state["users"].get(key) or {}
            team_ids = set(user.get("team_ids") or [])
            owners = state.get("playbook_owners") or {}
            # Unowned paths: only all_* or writers creating new under their tree
            def _owned(p: str) -> bool:
                meta = owners.get(p)
                if not isinstance(meta, dict):
                    # walk ancestors
                    parts = Path(p).parts
                    for i in range(len(parts), 0, -1):
                        cand = "/".join(parts[:i])
                        meta = owners.get(cand)
                        if isinstance(meta, dict):
                            break
                    else:
                        return False
                if meta.get("owner_type") == "user" and meta.get("owner_id") == key:
                    return True
                if meta.get("owner_type") == "team" and meta.get("owner_id") in team_ids:
                    return True
                return False

            if not rel:
                # list root: allowed if user has read/write playbooks
                return need in perms or "read_playbooks" in perms or "write_playbooks" in perms
            if rel in owners or any(rel.startswith(o + "/") for o in owners):
                return _owned(rel)
            # New file: writable if user has write_playbooks (will become owned on save)
            return (not write and "read_playbooks" in perms) or (write and "write_playbooks" in perms)

    def list_accessible_paths(self, user_key: str, *, write: bool = False) -> list[str]:
        key = _norm_user_key(user_key)
        with _LOCK:
            state = self._load()
            out = []
            for path in sorted((state.get("playbook_owners") or {}).keys()):
                if self.can_access_playbook(key, path, write=write):
                    out.append(path)
            return out

    def export_owned_files(
        self,
        user_key: str,
        *,
        read_file: Any,
        list_tree: Any,
        max_files: int = 400,
        max_bytes: int = 12_000_000,
    ) -> dict[str, Any]:
        """Collect playbook text the user may sync (secret names only — no vault values)."""
        key = _norm_user_key(user_key)
        if not self.has_permission(key, "sync_hayabusa") and not self.has_permission(key, "read_all_playbooks"):
            if "read_playbooks" not in self.user_permissions(key):
                return {"ok": False, "error": "missing sync_hayabusa or read_playbooks permission"}
        paths = self.list_accessible_paths(key, write=False)
        # Also include unowned defaults under Ansible/OpenTofu if user can read_playbooks
        files: list[dict[str, str]] = []
        total = 0
        seen: set[str] = set()

        def _add_file(rel: str) -> None:
            nonlocal total
            rel = str(rel or "").strip().lstrip("/")
            if not rel or rel in seen or len(files) >= max_files:
                return
            if not self.can_access_playbook(key, rel, write=False):
                # allow unowned if user has read_playbooks (defaults)
                perms = self.user_permissions(key)
                own = self.playbook_owner(rel)
                if own is not None or "read_all_playbooks" not in perms:
                    if own is None and "read_playbooks" not in perms and "read_all_playbooks" not in perms:
                        return
                    if own is not None and not self.can_access_playbook(key, rel, write=False):
                        return
            try:
                content = read_file(rel)
            except Exception:
                return
            if not isinstance(content, str):
                return
            nbytes = len(content.encode("utf-8", errors="replace"))
            if total + nbytes > max_bytes:
                return
            seen.add(rel)
            total += nbytes
            files.append({"path": rel, "content": content})

        def _entry_path(cur: str, ent: dict) -> str:
            ep = str(ent.get("path") or "").strip().lstrip("/")
            if ep:
                return ep
            name = str(ent.get("name") or "").strip()
            if not name:
                return ""
            base = str(cur or "").strip().lstrip("/")
            return f"{base}/{name}" if base else name

        # Only export explicitly owned playbook paths (and files under owned dirs).
        for p in paths:
            if len(files) >= max_files:
                break
            try:
                # Try as file first
                _add_file(p)
            except Exception:
                pass
            try:
                entries = list_tree(p) if callable(list_tree) else []
            except Exception:
                entries = []
            queue = [p]
            depth = 0
            while queue and len(files) < max_files and depth < 60:
                depth += 1
                cur = queue.pop(0)
                try:
                    ents = list_tree(cur)
                except Exception:
                    continue
                for ent in ents or []:
                    if not isinstance(ent, dict):
                        continue
                    ep = _entry_path(cur, ent)
                    if ent.get("type") == "dir":
                        queue.append(ep)
                    elif ent.get("type") == "file":
                        _add_file(ep)

        # Walk standard workspace roots so saves without explicit ownership still sync.
        perms = self.user_permissions(key)
        can_read_tree = (
            "read_playbooks" in perms
            or "write_playbooks" in perms
            or "read_all_playbooks" in perms
            or "write_all_playbooks" in perms
        )
        if can_read_tree:
            for root_dir in ("Ansible", "OpenTofu", "ztp", "bare-metal-ztp"):
                if len(files) >= max_files:
                    break
                queue = [root_dir]
                depth = 0
                while queue and len(files) < max_files and depth < 60:
                    depth += 1
                    cur = queue.pop(0)
                    try:
                        ents = list_tree(cur)
                    except Exception:
                        continue
                    for ent in ents or []:
                        if not isinstance(ent, dict):
                            continue
                        ep = _entry_path(cur, ent)
                        if ent.get("type") == "dir":
                            # Skip provider caches / VCS noise
                            base = os.path.basename(str(ep or "").rstrip("/")).lower()
                            if base in {".terraform", ".git", "__pycache__", "node_modules"}:
                                continue
                            queue.append(ep)
                        elif ent.get("type") == "file":
                            low = ep.lower()
                            base = os.path.basename(low)
                            if "/.terraform/" in f"/{low}/":
                                continue
                            # Primary OpenTofu state (JSON text) — lock/backup sidecars stay local.
                            if base == "terraform.tfstate" or low.endswith("/terraform.tfstate"):
                                _add_file(ep)
                                continue
                            if low.endswith(".tfstate") or ".tfstate." in low:
                                continue
                            if low.endswith(
                                (
                                    ".yml",
                                    ".yaml",
                                    ".ini",
                                    ".cfg",
                                    ".tf",
                                    ".hcl",
                                    ".tfvars",
                                    ".json",
                                    ".md",
                                    ".txt",
                                    ".j2",
                                    ".tpl",
                                    ".sh",
                                    ".py",
                                    ".vars",
                                )
                            ) or base in {"readme.txt", "readme.md", "hosts", "inventory"}:
                                _add_file(ep)

        return {
            "ok": True,
            "user_key": key,
            "files": files,
            "count": len(files),
            "bytes": total,
            "hayabusa_saw_secret_values": False,
        }

    def export_strictly_owned_files(
        self,
        user_key: str,
        *,
        read_file: Any,
        list_tree: Any,
        team_id: str | None = None,
        max_files: int = 400,
        max_bytes: int = 12_000_000,
    ) -> dict[str, Any]:
        """Export only paths owned by this user or a team they belong to (GitOps publish)."""
        key = _norm_user_key(user_key)
        if not key:
            return {"ok": False, "error": "user_key required", "files": []}
        with _LOCK:
            state = self._load()
            user = state["users"].get(key) or {}
            team_ids = set(user.get("team_ids") or [])
            owners = dict(state.get("playbook_owners") or {})
        if team_id:
            tid = str(team_id).strip()
            if tid not in team_ids:
                return {
                    "ok": False,
                    "error": "not a member of the binding team",
                    "code": "not_team_member",
                    "files": [],
                }
            allowed_teams = {tid}
        else:
            allowed_teams = team_ids

        def _owned(rel: str) -> bool:
            parts = str(rel or "").strip().lstrip("/").split("/")
            for i in range(len(parts), 0, -1):
                cand = "/".join(parts[:i])
                meta = owners.get(cand)
                if not isinstance(meta, dict):
                    continue
                if meta.get("owner_type") == "user" and meta.get("owner_id") == key:
                    return True
                if meta.get("owner_type") == "team" and meta.get("owner_id") in allowed_teams:
                    return True
                return False
            return False

        files: list[dict[str, str]] = []
        total = 0
        seen: set[str] = set()

        def _add_file(rel: str) -> None:
            nonlocal total
            rel = str(rel or "").strip().lstrip("/")
            if not rel or rel in seen or len(files) >= max_files:
                return
            if not _owned(rel):
                return
            try:
                content = read_file(rel)
            except Exception:
                return
            if not isinstance(content, str):
                return
            nbytes = len(content.encode("utf-8", errors="replace"))
            if total + nbytes > max_bytes:
                return
            seen.add(rel)
            total += nbytes
            files.append({"path": rel, "content": content})

        def _entry_path(cur: str, ent: dict) -> str:
            ep = str(ent.get("path") or "").strip().lstrip("/")
            if ep:
                return ep
            name = str(ent.get("name") or "").strip()
            if not name:
                return ""
            base = str(cur or "").strip().lstrip("/")
            return f"{base}/{name}" if base else name

        roots: list[str] = []
        for path, meta in owners.items():
            if not isinstance(meta, dict):
                continue
            if meta.get("owner_type") == "user" and meta.get("owner_id") == key:
                roots.append(str(path))
            elif meta.get("owner_type") == "team" and meta.get("owner_id") in allowed_teams:
                roots.append(str(path))

        for path in sorted(set(roots)):
            _add_file(path)
            queue = [path]
            depth = 0
            while queue and len(files) < max_files and depth < 60:
                depth += 1
                cur = queue.pop(0)
                try:
                    ents = list_tree(cur) or []
                except Exception:
                    continue
                for ent in ents:
                    if not isinstance(ent, dict):
                        continue
                    ep = _entry_path(cur, ent)
                    if not ep:
                        continue
                    if ent.get("type") == "dir":
                        queue.append(ep)
                    elif ent.get("type") == "file":
                        _add_file(ep)

        return {
            "ok": True,
            "files": files,
            "count": len(files),
            "bytes": total,
            "owned_only": True,
            "team_id": str(team_id or ""),
            "user_key": key,
            "hayabusa_saw_secret_values": False,
        }
