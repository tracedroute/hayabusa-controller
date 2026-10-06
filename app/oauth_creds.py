"""Sealed OAuth provider credentials for Hayabusa Controller.

Credentials are stored only under reserved vault keys (`__hayabusa_oauth_*`).
They are never listed or readable via `/api/secrets`. Users can sign in with the
providers; they cannot view or edit client secrets through the controller UI/API.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from .secrets_vault import SecretsVault, is_reserved_secret_key

logger = logging.getLogger("hayabusa-controller.oauth_creds")

PROVIDERS = ("google", "github", "gitlab", "discord", "slack", "microsoft")


def vault_key(provider: str) -> str:
    return f"__hayabusa_oauth_{provider.strip().lower()}"


class OAuthCredentialStore:
    def __init__(self, vault: SecretsVault) -> None:
        self.vault = vault

    def get(self, provider: str) -> dict[str, str]:
        p = (provider or "").strip().lower()
        if p in {"teams", "azure", "entra"}:
            p = "microsoft"
        raw = self.vault.get(vault_key(p), allow_reserved=True)
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if not isinstance(data, dict):
            return {}
        return {
            "client_id": str(data.get("client_id") or "").strip(),
            "client_secret": str(data.get("client_secret") or "").strip(),
            "tenant_id": str(data.get("tenant_id") or "common").strip() or "common",
            "base_url": str(data.get("base_url") or "").strip().rstrip("/"),
        }

    def put(
        self,
        provider: str,
        *,
        client_id: str,
        client_secret: str,
        tenant_id: str = "",
        base_url: str = "",
    ) -> None:
        p = (provider or "").strip().lower()
        if p in {"teams", "azure", "entra"}:
            p = "microsoft"
        if p not in PROVIDERS:
            raise ValueError("unsupported provider")
        payload = {
            "client_id": (client_id or "").strip(),
            "client_secret": (client_secret or "").strip(),
            "tenant_id": (tenant_id or "common").strip() or "common",
            "base_url": (base_url or "").strip().rstrip("/"),
        }
        if not payload["client_id"] or not payload["client_secret"]:
            raise ValueError("client_id and client_secret required")
        self.vault.put(vault_key(p), json.dumps(payload), allow_reserved=True)

    def configured(self, provider: str) -> bool:
        c = self.get(provider)
        return bool(c.get("client_id") and c.get("client_secret"))

    def public_status(self) -> dict[str, Any]:
        """Presence flags only — never secrets or previews."""
        out: dict[str, Any] = {}
        for p in PROVIDERS:
            out[p] = {"configured": self.configured(p)}
        return out

    def purge_all(self) -> int:
        """Remove any sealed IdP credentials from this appliance (broker mode)."""
        removed = 0
        for p in PROVIDERS:
            if self.vault.delete(vault_key(p), allow_reserved=True):
                removed += 1
        return removed

    def seal_from_env_map(self, env: dict[str, str]) -> list[str]:
        """Installer-only bootstrap for CONTROLLER_OAUTH_MODE=local.

        Broker mode must not call this — IdP secrets stay on Hayabusa, not the
        customer host.
        """
        sealed: list[str] = []
        mapping = {
            "google": ("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", None),
            "github": ("GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET", None),
            "discord": ("DISCORD_CLIENT_ID", "DISCORD_CLIENT_SECRET", None),
            "slack": ("SLACK_CLIENT_ID", "SLACK_CLIENT_SECRET", None),
            "microsoft": (
                ("MICROSOFT_CLIENT_ID", "TEAMS_CLIENT_ID"),
                ("MICROSOFT_CLIENT_SECRET", "TEAMS_CLIENT_SECRET"),
                ("MICROSOFT_TENANT_ID", "TEAMS_TENANT_ID"),
            ),
        }

        def _first(keys: str | tuple[str, ...]) -> str:
            if isinstance(keys, str):
                return (env.get(keys) or "").strip()
            for k in keys:
                v = (env.get(k) or "").strip()
                if v:
                    return v
            return ""

        for provider, (id_keys, sec_keys, tenant_keys) in mapping.items():
            cid = _first(id_keys)
            csec = _first(sec_keys)
            tenant = _first(tenant_keys) if tenant_keys else "common"
            if not cid or not csec:
                continue
            if self.configured(provider):
                sealed.append(f"{provider}:kept")
                continue
            self.put(provider, client_id=cid, client_secret=csec, tenant_id=tenant or "common")
            sealed.append(f"{provider}:sealed")
            logger.info("sealed oauth credentials for provider=%s", provider)
        return sealed


def assert_not_user_oauth_key(key: str) -> None:
    if is_reserved_secret_key(key) and "oauth" in key:
        raise PermissionError("oauth credentials are not user-accessible")
