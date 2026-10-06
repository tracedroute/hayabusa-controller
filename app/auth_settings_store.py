"""Local manual-password login settings (admin-controlled).

Default: enabled (break-glass first login). Owner/admin may disable after
other sign-in methods are configured.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("hayabusa-controller.auth_settings")

_LOCK = threading.RLock()


def _default() -> dict[str, Any]:
    return {
        "version": 1,
        "local_password_login_enabled": True,
        # Legacy: forced local password change. Prefer needs_sso_admin flow.
        "must_change_password": False,
        # True after first-boot password is minted until an SSO identity
        # (GitHub/Google/Discord with 2FA) is claimed as Owner/admin.
        "needs_sso_admin": False,
        # After SSO admin is claimed, require provider 2FA for subsequent
        # GitHub/Google/Discord sign-ins (admin can disable on Sign-in page).
        "require_2fa": True,
        "updated_at": None,
        "updated_by": "",
    }


class AuthSettingsStore:
    def __init__(self, data_dir: Path | str) -> None:
        self.path = Path(data_dir) / "state" / "auth_settings.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _load_unlocked(self) -> dict[str, Any]:
        base = _default()
        if not self.path.is_file():
            return base
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("auth settings read failed: %s", exc)
            return base
        if not isinstance(raw, dict):
            return base
        base["local_password_login_enabled"] = bool(
            raw.get("local_password_login_enabled", True)
        )
        if "must_change_password" in raw:
            base["must_change_password"] = bool(raw.get("must_change_password"))
        if "needs_sso_admin" in raw:
            base["needs_sso_admin"] = bool(raw.get("needs_sso_admin"))
        elif base.get("must_change_password"):
            # Migrate unfinished first-boot password-change sites → SSO claim.
            base["needs_sso_admin"] = True
        if "require_2fa" in raw:
            base["require_2fa"] = bool(raw.get("require_2fa"))
        base["updated_at"] = raw.get("updated_at")
        base["updated_by"] = str(raw.get("updated_by") or "")[:200]
        return base

    def _write_unlocked(self, data: dict[str, Any]) -> None:
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def get(self) -> dict[str, Any]:
        with _LOCK:
            return self._load_unlocked()

    def local_password_enabled(self) -> bool:
        return bool(self.get().get("local_password_login_enabled", True))

    def must_change_password(self) -> bool:
        return bool(self.get().get("must_change_password", False))

    def needs_sso_admin(self) -> bool:
        return bool(self.get().get("needs_sso_admin", False))

    def require_2fa(self) -> bool:
        return bool(self.get().get("require_2fa", True))

    def set_must_change_password(
        self,
        required: bool,
        *,
        updated_by: str = "",
    ) -> dict[str, Any]:
        with _LOCK:
            cur = self._load_unlocked()
            cur["must_change_password"] = bool(required)
            cur["updated_at"] = int(time.time())
            if updated_by:
                cur["updated_by"] = str(updated_by)[:200]
            self._write_unlocked(cur)
            return cur

    def set_needs_sso_admin(
        self,
        required: bool,
        *,
        updated_by: str = "",
    ) -> dict[str, Any]:
        with _LOCK:
            cur = self._load_unlocked()
            cur["needs_sso_admin"] = bool(required)
            if required:
                # Prefer SSO claim over legacy local password change.
                cur["must_change_password"] = False
            cur["updated_at"] = int(time.time())
            if updated_by:
                cur["updated_by"] = str(updated_by)[:200]
            self._write_unlocked(cur)
            return cur

    def set_require_2fa(
        self,
        required: bool,
        *,
        updated_by: str = "",
    ) -> dict[str, Any]:
        with _LOCK:
            cur = self._load_unlocked()
            cur["require_2fa"] = bool(required)
            cur["updated_at"] = int(time.time())
            if updated_by:
                cur["updated_by"] = str(updated_by)[:200]
            self._write_unlocked(cur)
            logger.info(
                "require_2fa %s by %s",
                "enabled" if required else "disabled",
                updated_by or "admin",
            )
            return cur

    def mark_sso_admin_claimed(self, *, updated_by: str = "") -> dict[str, Any]:
        with _LOCK:
            cur = self._load_unlocked()
            cur["needs_sso_admin"] = False
            cur["must_change_password"] = False
            cur["local_password_login_enabled"] = False
            # Default: keep 2FA required for later allowlisted accounts.
            if "require_2fa" not in cur:
                cur["require_2fa"] = True
            cur["updated_at"] = int(time.time())
            if updated_by:
                cur["updated_by"] = str(updated_by)[:200]
            self._write_unlocked(cur)
            return cur

    def set_local_password_enabled(
        self,
        enabled: bool,
        *,
        updated_by: str = "",
    ) -> dict[str, Any]:
        with _LOCK:
            cur = self._load_unlocked()
            cur["local_password_login_enabled"] = bool(enabled)
            cur["updated_at"] = int(time.time())
            if updated_by:
                cur["updated_by"] = str(updated_by)[:200]
            self._write_unlocked(cur)
            logger.info(
                "local password login %s by %s",
                "enabled" if enabled else "disabled",
                updated_by or "admin",
            )
            return cur
