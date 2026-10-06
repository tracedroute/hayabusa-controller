"""Controller sign-in allowlist — default deny per platform.

Admins whitelist identities (email / username / oauth user id) for each
provider. Empty lists for a platform mean nobody may sign in via that
platform (except break-glass manual password login handled by the caller).
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger("hayabusa-controller.signin_allowlist")

_LOCK = threading.RLock()

PLATFORMS = ("google", "github", "discord", "slack", "microsoft", "totp", "manual")

_PLATFORM_ALIASES = {
    "teams": "microsoft",
    "ms": "microsoft",
    "azure": "microsoft",
    "hayabusa": "totp",
    "hayabusa_auth": "totp",
}


def _norm_platform(provider: str) -> str:
    p = str(provider or "").strip().lower()
    return _PLATFORM_ALIASES.get(p, p)


def _norm_token(value: str) -> str:
    return str(value or "").strip().lower()


def _split_list(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        parts = []
        for chunk in raw.replace(";", ",").replace("\n", ",").split(","):
            t = chunk.strip()
            if t:
                parts.append(t)
        return parts
    if isinstance(raw, (list, tuple, set)):
        out: list[str] = []
        for item in raw:
            t = str(item or "").strip()
            if t:
                out.append(t)
        return out
    t = str(raw).strip()
    return [t] if t else []


def _uniq_preserve(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = _norm_token(item)
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(item.strip())
    return out


def default_allowlist() -> dict[str, Any]:
    return {
        "version": 1,
        "default_deny": True,
        "platforms": {
            name: {"emails": [], "usernames": [], "user_ids": []} for name in PLATFORMS
        },
        "notes": (
            "Default deny: a platform with empty emails/usernames/user_ids rejects all "
            "sign-ins for that provider. Manual bootstrap password login is break-glass."
        ),
    }


class SignInAllowlistStore:
    def __init__(self, data_dir: Path | str) -> None:
        self.path = Path(data_dir) / "signin_allowlist.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _load_unlocked(self) -> dict[str, Any]:
        base = default_allowlist()
        if not self.path.is_file():
            return base
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("signin allowlist read failed: %s", exc)
            return base
        if not isinstance(raw, dict):
            return base
        platforms_in = raw.get("platforms") if isinstance(raw.get("platforms"), dict) else {}
        platforms = base["platforms"]
        for name in PLATFORMS:
            src = platforms_in.get(name) if isinstance(platforms_in.get(name), dict) else {}
            # Also accept top-level legacy keys
            if not src and isinstance(raw.get(name), dict):
                src = raw.get(name) or {}
            platforms[name] = {
                "emails": _uniq_preserve(_split_list(src.get("emails"))),
                "usernames": _uniq_preserve(_split_list(src.get("usernames"))),
                "user_ids": _uniq_preserve(_split_list(src.get("user_ids"))),
            }
        # Map teams → microsoft if present as its own key
        teams = platforms_in.get("teams") if isinstance(platforms_in.get("teams"), dict) else None
        if teams:
            ms = platforms["microsoft"]
            ms["emails"] = _uniq_preserve(ms["emails"] + _split_list(teams.get("emails")))
            ms["usernames"] = _uniq_preserve(ms["usernames"] + _split_list(teams.get("usernames")))
            ms["user_ids"] = _uniq_preserve(ms["user_ids"] + _split_list(teams.get("user_ids")))
        return {
            "version": 1,
            "default_deny": True,
            "platforms": platforms,
            "notes": str(raw.get("notes") or base["notes"]),
            "updated_at": raw.get("updated_at"),
            "updated_by": raw.get("updated_by"),
        }

    def _write_unlocked(self, data: dict[str, Any]) -> None:
        tmp = self.path.with_suffix(".json.tmp")
        payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def get(self) -> dict[str, Any]:
        with _LOCK:
            return self._load_unlocked()

    def save(
        self,
        platforms: dict[str, Any] | None = None,
        *,
        updated_by: str = "",
    ) -> dict[str, Any]:
        import time

        with _LOCK:
            cur = self._load_unlocked()
            plats = cur["platforms"]
            incoming = platforms if isinstance(platforms, dict) else {}
            for name in PLATFORMS:
                src = incoming.get(name)
                if not isinstance(src, dict):
                    continue
                plats[name] = {
                    "emails": _uniq_preserve(_split_list(src.get("emails"))),
                    "usernames": _uniq_preserve(_split_list(src.get("usernames"))),
                    "user_ids": _uniq_preserve(_split_list(src.get("user_ids"))),
                }
            cur["platforms"] = plats
            cur["default_deny"] = True
            cur["updated_at"] = int(time.time())
            if updated_by:
                cur["updated_by"] = str(updated_by)[:200]
            self._write_unlocked(cur)
            return cur

    def add_identity(
        self,
        *,
        provider: str,
        email: str = "",
        username: str = "",
        oauth_id: str = "",
        updated_by: str = "",
    ) -> dict[str, Any]:
        """Append an identity to a platform allowlist (used for first SSO admin claim)."""
        import time

        plat = _norm_platform(provider)
        if plat not in PLATFORMS:
            return {"ok": False, "error": f"unknown platform {provider}"}
        with _LOCK:
            cur = self._load_unlocked()
            entry = dict((cur.get("platforms") or {}).get(plat) or {})
            emails = list(entry.get("emails") or [])
            usernames = list(entry.get("usernames") or [])
            user_ids = list(entry.get("user_ids") or [])
            if str(email or "").strip():
                emails.append(str(email).strip())
            if str(username or "").strip():
                usernames.append(str(username).strip())
            if str(oauth_id or "").strip():
                user_ids.append(str(oauth_id).strip())
            cur.setdefault("platforms", {})[plat] = {
                "emails": _uniq_preserve(emails),
                "usernames": _uniq_preserve(usernames),
                "user_ids": _uniq_preserve(user_ids),
            }
            cur["updated_at"] = int(time.time())
            if updated_by:
                cur["updated_by"] = str(updated_by)[:200]
            self._write_unlocked(cur)
            return {"ok": True, "platforms": cur.get("platforms")}

    def is_allowed(
        self,
        *,
        provider: str,
        email: str = "",
        username: str = "",
        oauth_id: str = "",
    ) -> tuple[bool, str]:
        """Return (allowed, reason). Default deny when platform lists are empty."""
        plat = _norm_platform(provider)
        if plat not in PLATFORMS:
            return False, f"Unknown sign-in platform '{provider or 'unknown'}'"

        data = self.get()
        entry = (data.get("platforms") or {}).get(plat) or {}
        emails = {_norm_token(x) for x in (entry.get("emails") or []) if str(x).strip()}
        usernames = {_norm_token(x) for x in (entry.get("usernames") or []) if str(x).strip()}
        user_ids = {_norm_token(x) for x in (entry.get("user_ids") or []) if str(x).strip()}

        if not emails and not usernames and not user_ids:
            return (
                False,
                f"Sign-in denied: no identities are whitelisted for {plat}. "
                "An administrator must add you under Administration → Sign-in.",
            )

        email_n = _norm_token(email)
        user_n = _norm_token(username)
        sub_n = _norm_token(oauth_id)

        if email_n and email_n in emails:
            return True, "email allowlisted"
        if user_n and user_n in usernames:
            return True, "username allowlisted"
        if sub_n and sub_n in user_ids:
            return True, "user id allowlisted"

        # GitHub sometimes uses login without email
        if plat == "github" and user_n and user_n in usernames:
            return True, "github username allowlisted"

        return (
            False,
            f"Sign-in denied: your {plat} identity is not on the administrator allowlist.",
        )


def platform_has_entries(entry: dict[str, Any] | None) -> bool:
    if not isinstance(entry, dict):
        return False
    for key in ("emails", "usernames", "user_ids"):
        if any(str(x).strip() for x in (entry.get(key) or [])):
            return True
    return False
