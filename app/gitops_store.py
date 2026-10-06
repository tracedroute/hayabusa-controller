"""Opt-in GitOps settings for Ansible/OpenTofu (GitHub / GitLab).

When enabled, Hayabusa pulls the configured repository; the controller keeps
secrets + LAN approve/hydrate. Local workspace editing is disabled.
Credentials stay in the vault — only secret *key names* are stored here.
"""

from __future__ import annotations

import ipaddress
import json
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_LOCK = threading.RLock()

PROVIDERS = frozenset({"github", "gitlab"})
DEFAULT_BASE_URLS = {
    "github": "https://github.com",
    "gitlab": "https://gitlab.com",
}
REPO_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+$")
SECRET_KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
# Self-hosted Git on LAN (RFC1918) is allowed; block loopback / link-local / metadata-style targets.
_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "metadata",
        "metadata.google.internal",
        "instance-data",
    }
)


def _now() -> float:
    return time.time()


def _safe_host(url: str) -> str:
    try:
        p = urlparse((url or "").strip())
    except Exception:
        return ""
    if p.scheme not in {"http", "https"}:
        return ""
    host = (p.hostname or "").strip().lower()
    return host


def _host_blocked_for_ssrf(host: str) -> bool:
    """Return True if host must not be used as a Git instance base URL."""
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return True
    if h in _BLOCKED_HOSTNAMES or h.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast or ip.is_reserved:
        return True
    # IPv4 link-local / AWS IMDS style already covered by is_link_local; keep explicit.
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("169.254.0.0/16"):
        return True
    return False


class GitOpsStore:
    def __init__(self, data_dir: Path) -> None:
        self.path = Path(data_dir) / "state" / "gitops.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _empty(self) -> dict[str, Any]:
        return {
            "version": 1,
            "enabled": False,
            "provider": "github",
            "base_url": DEFAULT_BASE_URLS["github"],
            "repo": "",
            "ref": "main",
            "path_prefix": "",
            # ZTP scripts (vendor ZTP + bare-metal ZTP). Required when GitOps/advanced is on.
            "ztp_repo": "",
            "ztp_ref": "",
            "ztp_path_prefix": "",
            "auth_secret_key": "",
            "webhook_secret_key": "",
            "poll_seconds": 600,
            # Admin-assigned GitHub/GitLab instances per controller team.
            # Users may only publish owned paths into a binding for a team they belong to,
            # and only when their sign-in has that provider linked.
            "team_bindings": [],
            # user_key -> { github: {login,id,sub,linked_at}, gitlab: {...} }
            "linked_accounts": {},
            "last_sync": {
                "ok": None,
                "sha": "",
                "error": "",
                "at": 0,
                "source": "",
            },
            "updated_at": 0,
            "updated_by": "",
            "audit": [],
        }

    def _load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return self._empty()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return self._empty()
        if not isinstance(raw, dict):
            return self._empty()
        out = self._empty()
        out.update({k: raw.get(k, out[k]) for k in out.keys() if k in raw or k in out})
        if not isinstance(out.get("last_sync"), dict):
            out["last_sync"] = self._empty()["last_sync"]
        if not isinstance(out.get("audit"), list):
            out["audit"] = []
        if not isinstance(out.get("team_bindings"), list):
            out["team_bindings"] = []
        if not isinstance(out.get("linked_accounts"), dict):
            out["linked_accounts"] = {}
        return out

    def _save(self, data: dict[str, Any]) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(self.path)

    def get(self) -> dict[str, Any]:
        with _LOCK:
            return self._load()

    def enabled(self) -> bool:
        return bool(self.get().get("enabled"))

    def public_config(self) -> dict[str, Any]:
        """Safe for API responses — no secret values."""
        cfg = self.get()
        ztp_repo = str(cfg.get("ztp_repo") or "").strip()
        ztp_ref = str(cfg.get("ztp_ref") or "").strip() or str(cfg.get("ref") or "main")
        return {
            "ok": True,
            "enabled": bool(cfg.get("enabled")),
            "provider": str(cfg.get("provider") or "github"),
            "base_url": str(cfg.get("base_url") or ""),
            "repo": str(cfg.get("repo") or ""),
            "ref": str(cfg.get("ref") or "main"),
            "path_prefix": str(cfg.get("path_prefix") or ""),
            "ztp_repo": ztp_repo,
            "ztp_ref": ztp_ref,
            "ztp_path_prefix": str(cfg.get("ztp_path_prefix") or ""),
            "auth_secret_key": str(cfg.get("auth_secret_key") or ""),
            "webhook_secret_key": str(cfg.get("webhook_secret_key") or ""),
            "poll_seconds": int(cfg.get("poll_seconds") or 600),
            "last_sync": dict(cfg.get("last_sync") or {}),
            "updated_at": cfg.get("updated_at") or 0,
            "updated_by": str(cfg.get("updated_by") or ""),
            "defaults": {
                "github_base_url": DEFAULT_BASE_URLS["github"],
                "gitlab_base_url": DEFAULT_BASE_URLS["gitlab"],
            },
            "local_workspace_writable": not bool(cfg.get("enabled")),
            "ztp_source": "gitops" if bool(cfg.get("enabled")) and ztp_repo else "controller",
            "team_bindings": [
                self._public_binding(b)
                for b in (cfg.get("team_bindings") or [])
                if isinstance(b, dict)
            ],
            "linked_accounts_count": len(cfg.get("linked_accounts") or {}),
        }

    def validate_payload(self, body: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
        enabled = bool(body.get("enabled"))
        provider = str(body.get("provider") or "github").strip().lower()
        if provider not in PROVIDERS:
            return None, "provider must be github or gitlab"
        base_url = str(body.get("base_url") or DEFAULT_BASE_URLS[provider]).strip().rstrip("/")
        if not base_url:
            base_url = DEFAULT_BASE_URLS[provider]
        host = _safe_host(base_url)
        if not host:
            return None, "base_url must be http(s) with a hostname"
        # Block loopback / link-local / cloud-metadata; RFC1918 self-hosted Git remains allowed.
        if _host_blocked_for_ssrf(host):
            return None, "base_url host is not allowed"
        repo = str(body.get("repo") or "").strip().strip("/")
        if enabled and not REPO_RE.match(repo):
            return None, "repo must look like org/name"
        ref = str(body.get("ref") or "main").strip() or "main"
        if len(ref) > 200 or any(c in ref for c in ("\n", "\r", " ", "\t")):
            return None, "invalid ref"
        path_prefix = str(body.get("path_prefix") or "").strip().strip("/")
        if ".." in path_prefix.split("/"):
            return None, "invalid path_prefix"
        ztp_repo = str(body.get("ztp_repo") or "").strip().strip("/")
        # Default ZTP repo to IaC repo only when explicitly omitted and disabling;
        # when enabling, require an explicit ZTP scripts repository.
        if "ztp_repo" not in body and not enabled:
            ztp_repo = ""
        ztp_ref = str(body.get("ztp_ref") or "").strip() or ref
        if len(ztp_ref) > 200 or any(c in ztp_ref for c in ("\n", "\r", " ", "\t")):
            return None, "invalid ztp_ref"
        ztp_path_prefix = str(body.get("ztp_path_prefix") or "").strip().strip("/")
        if ".." in ztp_path_prefix.split("/"):
            return None, "invalid ztp_path_prefix"
        if enabled:
            if not ztp_repo:
                return None, "ztp_repo is required when GitOps/advanced is enabled (vendor ZTP + bare-metal ZTP scripts)"
            if not REPO_RE.match(ztp_repo):
                return None, "ztp_repo must look like org/name"
        elif ztp_repo and not REPO_RE.match(ztp_repo):
            return None, "ztp_repo must look like org/name"
        auth_key = str(body.get("auth_secret_key") or "").strip()
        webhook_key = str(body.get("webhook_secret_key") or "").strip()
        if auth_key and not SECRET_KEY_RE.match(auth_key):
            return None, "invalid auth_secret_key"
        if webhook_key and not SECRET_KEY_RE.match(webhook_key):
            return None, "invalid webhook_secret_key"
        if enabled and not auth_key:
            return None, "auth_secret_key is required when GitOps is enabled"
        if enabled and not webhook_key:
            return None, "webhook_secret_key is required when GitOps is enabled"
        try:
            poll_seconds = int(body.get("poll_seconds") if body.get("poll_seconds") is not None else 600)
        except (TypeError, ValueError):
            return None, "poll_seconds must be an integer"
        poll_seconds = max(60, min(poll_seconds, 86400))
        return {
            "enabled": enabled,
            "provider": provider,
            "base_url": base_url,
            "repo": repo,
            "ref": ref,
            "path_prefix": path_prefix,
            "ztp_repo": ztp_repo,
            "ztp_ref": ztp_ref,
            "ztp_path_prefix": ztp_path_prefix,
            "auth_secret_key": auth_key,
            "webhook_secret_key": webhook_key,
            "poll_seconds": poll_seconds,
        }, ""

    def update(self, body: dict[str, Any], *, updated_by: str = "") -> dict[str, Any]:
        cleaned, err = self.validate_payload(body if isinstance(body, dict) else {})
        if not cleaned:
            return {"ok": False, "error": err or "invalid config"}
        with _LOCK:
            data = self._load()
            prev_enabled = bool(data.get("enabled"))
            data.update(cleaned)
            data["updated_at"] = _now()
            data["updated_by"] = (updated_by or "")[:128]
            audit = list(data.get("audit") or [])
            audit.append(
                {
                    "at": data["updated_at"],
                    "by": data["updated_by"],
                    "enabled": cleaned["enabled"],
                    "provider": cleaned["provider"],
                    "repo": cleaned["repo"],
                    "ref": cleaned["ref"],
                    "was_enabled": prev_enabled,
                }
            )
            data["audit"] = audit[-50:]
            self._save(data)
        out = self.public_config()
        out["ok"] = True
        out["message"] = "GitOps config saved"
        return out

    def record_sync(
        self,
        *,
        ok: bool,
        sha: str = "",
        error: str = "",
        source: str = "",
    ) -> dict[str, Any]:
        with _LOCK:
            data = self._load()
            data["last_sync"] = {
                "ok": bool(ok),
                "sha": str(sha or "")[:64],
                "error": str(error or "")[:500],
                "at": _now(),
                "source": str(source or "")[:64],
            }
            self._save(data)
        return dict(data["last_sync"])

    def bridge_config_payload(self) -> dict[str, Any]:
        """Config pushed to Hayabusa (no secret values)."""
        cfg = self.get()
        ztp_repo = str(cfg.get("ztp_repo") or "").strip()
        ztp_ref = str(cfg.get("ztp_ref") or "").strip() or str(cfg.get("ref") or "main")
        return {
            "enabled": bool(cfg.get("enabled")),
            "provider": str(cfg.get("provider") or "github"),
            "base_url": str(cfg.get("base_url") or ""),
            "repo": str(cfg.get("repo") or ""),
            "ref": str(cfg.get("ref") or "main"),
            "path_prefix": str(cfg.get("path_prefix") or ""),
            "ztp_repo": ztp_repo,
            "ztp_ref": ztp_ref,
            "ztp_path_prefix": str(cfg.get("ztp_path_prefix") or ""),
            "poll_seconds": int(cfg.get("poll_seconds") or 600),
            "auth_secret_key": str(cfg.get("auth_secret_key") or ""),
            "webhook_secret_key": str(cfg.get("webhook_secret_key") or ""),
            "allowed_host": _safe_host(str(cfg.get("base_url") or "")),
            "ztp_source": "gitops" if bool(cfg.get("enabled")) and ztp_repo else "controller",
            "team_bindings": [
                self._public_binding(b)
                for b in (cfg.get("team_bindings") or [])
                if isinstance(b, dict)
            ],
        }

    def clone_https_url(self, *, kind: str = "iac") -> str:
        cfg = self.get()
        base = str(cfg.get("base_url") or "").rstrip("/")
        if str(kind or "iac").strip().lower() == "ztp":
            repo = str(cfg.get("ztp_repo") or cfg.get("repo") or "").strip("/")
        else:
            repo = str(cfg.get("repo") or "").strip("/")
        provider = str(cfg.get("provider") or "github")
        if provider == "gitlab":
            # GitLab clone path is the same org/group/project form
            return f"{base}/{repo}.git"
        return f"{base}/{repo}.git"

    @staticmethod
    def _public_binding(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": str(row.get("id") or ""),
            "team_id": str(row.get("team_id") or ""),
            "provider": str(row.get("provider") or "github"),
            "base_url": str(row.get("base_url") or ""),
            "repo": str(row.get("repo") or ""),
            "ref": str(row.get("ref") or "main"),
            "path_prefix": str(row.get("path_prefix") or ""),
            "auth_secret_key": str(row.get("auth_secret_key") or ""),
            "require_linked_provider": bool(row.get("require_linked_provider", True)),
            "updated_at": float(row.get("updated_at") or 0),
            "updated_by": str(row.get("updated_by") or ""),
        }

    def list_team_bindings(self) -> list[dict[str, Any]]:
        cfg = self.get()
        return [
            self._public_binding(b)
            for b in (cfg.get("team_bindings") or [])
            if isinstance(b, dict) and str(b.get("id") or "").strip()
        ]

    def get_team_binding(self, binding_id: str) -> dict[str, Any] | None:
        bid = str(binding_id or "").strip()
        if not bid:
            return None
        for b in self.get().get("team_bindings") or []:
            if isinstance(b, dict) and str(b.get("id") or "") == bid:
                return dict(b)
        return None

    def upsert_team_binding(
        self,
        body: dict[str, Any],
        *,
        updated_by: str = "",
        known_team_ids: set[str] | None = None,
    ) -> dict[str, Any]:
        """Admin: attach a GitHub/GitLab instance+repo to a controller team."""
        body = body if isinstance(body, dict) else {}
        team_id = str(body.get("team_id") or "").strip()
        if not team_id:
            return {"ok": False, "error": "team_id required", "code": "missing_team"}
        if known_team_ids is not None and team_id not in known_team_ids:
            return {"ok": False, "error": "unknown team_id", "code": "unknown_team"}
        provider = str(body.get("provider") or "github").strip().lower()
        if provider not in PROVIDERS:
            return {"ok": False, "error": "provider must be github or gitlab"}
        base_url = str(body.get("base_url") or DEFAULT_BASE_URLS[provider]).strip().rstrip("/")
        host = _safe_host(base_url)
        if not host or _host_blocked_for_ssrf(host):
            return {"ok": False, "error": "base_url host is not allowed"}
        repo = str(body.get("repo") or "").strip().strip("/")
        if not REPO_RE.match(repo):
            return {"ok": False, "error": "repo must look like org/name"}
        ref = str(body.get("ref") or "main").strip() or "main"
        path_prefix = str(body.get("path_prefix") or "").strip().strip("/")
        if ".." in path_prefix.split("/"):
            return {"ok": False, "error": "invalid path_prefix"}
        auth_key = str(body.get("auth_secret_key") or "").strip()
        if not auth_key or not SECRET_KEY_RE.match(auth_key):
            return {"ok": False, "error": "auth_secret_key required (vault key for team PAT)"}
        bid = str(body.get("id") or "").strip() or secrets.token_hex(8)
        row = {
            "id": bid,
            "team_id": team_id,
            "provider": provider,
            "base_url": base_url,
            "repo": repo,
            "ref": ref,
            "path_prefix": path_prefix,
            "auth_secret_key": auth_key,
            "require_linked_provider": bool(body.get("require_linked_provider", True)),
            "updated_at": _now(),
            "updated_by": (updated_by or "")[:128],
        }
        with _LOCK:
            data = self._load()
            bindings = [b for b in (data.get("team_bindings") or []) if isinstance(b, dict)]
            replaced = False
            for i, b in enumerate(bindings):
                if str(b.get("id") or "") == bid:
                    bindings[i] = row
                    replaced = True
                    break
            if not replaced:
                # One binding per team+provider+repo to avoid duplicates.
                for i, b in enumerate(bindings):
                    if (
                        str(b.get("team_id") or "") == team_id
                        and str(b.get("provider") or "") == provider
                        and str(b.get("repo") or "") == repo
                    ):
                        row["id"] = str(b.get("id") or bid)
                        bindings[i] = row
                        replaced = True
                        break
            if not replaced:
                bindings.append(row)
            data["team_bindings"] = bindings
            data["updated_at"] = _now()
            data["updated_by"] = (updated_by or "")[:128]
            self._save(data)
        return {"ok": True, "binding": self._public_binding(row)}

    def delete_team_binding(self, binding_id: str, *, updated_by: str = "") -> dict[str, Any]:
        bid = str(binding_id or "").strip()
        if not bid:
            return {"ok": False, "error": "binding id required"}
        with _LOCK:
            data = self._load()
            before = list(data.get("team_bindings") or [])
            after = [b for b in before if isinstance(b, dict) and str(b.get("id") or "") != bid]
            if len(after) == len(before):
                return {"ok": False, "error": "binding not found", "code": "not_found"}
            data["team_bindings"] = after
            data["updated_at"] = _now()
            data["updated_by"] = (updated_by or "")[:128]
            self._save(data)
        return {"ok": True, "deleted": bid}

    def link_account(
        self,
        user_key: str,
        *,
        provider: str,
        login: str = "",
        oauth_id: str = "",
        sub: str = "",
        email: str = "",
    ) -> dict[str, Any]:
        """Record that this controller user signed in with GitHub/GitLab (identity link)."""
        key = str(user_key or "").strip()
        provider_n = str(provider or "").strip().lower()
        if provider_n == "teams":
            provider_n = "microsoft"
        if provider_n not in PROVIDERS:
            return {"ok": False, "error": "only github/gitlab can be linked for GitOps publish", "code": "bad_provider"}
        if not key:
            return {"ok": False, "error": "user_key required"}
        login_n = str(login or email or oauth_id or sub or "").strip()[:200]
        if not login_n and not str(oauth_id or sub or "").strip():
            return {"ok": False, "error": "linked identity missing login/id", "code": "missing_identity"}
        entry = {
            "provider": provider_n,
            "login": login_n,
            "id": str(oauth_id or sub or "")[:200],
            "sub": str(sub or oauth_id or "")[:200],
            "email": str(email or "")[:200],
            "linked_at": _now(),
        }
        with _LOCK:
            data = self._load()
            linked = dict(data.get("linked_accounts") or {})
            user_links = dict(linked.get(key) or {})
            user_links[provider_n] = entry
            linked[key] = user_links
            data["linked_accounts"] = linked
            self._save(data)
        return {"ok": True, "user_key": key, "link": {k: v for k, v in entry.items()}}

    def linked_accounts_for(self, user_key: str) -> dict[str, Any]:
        key = str(user_key or "").strip()
        with _LOCK:
            data = self._load()
            row = (data.get("linked_accounts") or {}).get(key) or {}
        out = {}
        for prov in PROVIDERS:
            ent = row.get(prov) if isinstance(row, dict) else None
            if isinstance(ent, dict) and (ent.get("login") or ent.get("id") or ent.get("sub")):
                out[prov] = {
                    "provider": prov,
                    "login": str(ent.get("login") or ""),
                    "id": str(ent.get("id") or ""),
                    "linked_at": float(ent.get("linked_at") or 0),
                }
        return out

    def user_has_provider_link(self, user_key: str, provider: str) -> bool:
        links = self.linked_accounts_for(user_key)
        return str(provider or "").strip().lower() in links

    def bindings_for_user_teams(self, team_ids: list[str] | set[str]) -> list[dict[str, Any]]:
        wanted = {str(t).strip() for t in (team_ids or []) if str(t).strip()}
        if not wanted:
            return []
        return [b for b in self.list_team_bindings() if str(b.get("team_id") or "") in wanted]

    def authorize_publish(
        self,
        *,
        user_key: str,
        binding_id: str,
        user_team_ids: list[str] | set[str],
    ) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        """Return (binding, error_dict). binding includes auth_secret_key for vault resolve."""
        binding = self.get_team_binding(binding_id)
        if not binding:
            return None, {"ok": False, "error": "binding not found", "code": "not_found"}
        team_id = str(binding.get("team_id") or "")
        teams = {str(t).strip() for t in (user_team_ids or []) if str(t).strip()}
        if team_id not in teams:
            return None, {
                "ok": False,
                "error": "you are not a member of the team that owns this Git binding",
                "code": "not_team_member",
                "team_id": team_id,
            }
        provider = str(binding.get("provider") or "github")
        if bool(binding.get("require_linked_provider", True)) and not self.user_has_provider_link(
            user_key, provider
        ):
            return None, {
                "ok": False,
                "error": (
                    f"link a {provider} account to your controller sign-in before publishing "
                    f"to this team binding"
                ),
                "code": "provider_not_linked",
                "provider": provider,
            }
        return binding, {"ok": True}
