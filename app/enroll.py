"""SD-WAN-style phone-home enrollment with Hayabusa (vBond-like introducer)."""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from .config import Settings
from .secrets_vault import SecretsVault

logger = logging.getLogger("hayabusa-controller.enroll")

# Vault key for controller-only mesh join material. Never expose via /api/secrets.
MESH_PREAUTH_VAULT_KEY = "__hayabusa_mesh_preauth"


def public_enroll_view(data: dict[str, Any] | None) -> dict[str, Any]:
    """Strip join secrets so browser/API clients cannot reuse controller VPN credentials."""
    if not isinstance(data, dict):
        return {"enrolled": False}
    out = {k: v for k, v in data.items() if k not in {"preauth_key", "auth_key", "preauth", "mesh_auth_key"}}
    # Never echo the raw key; only a presence flag.
    if "preauth_key_set" not in out:
        out["preauth_key_set"] = bool(data.get("preauth_key") or data.get("preauth_key_set"))
    out.pop("preauth_key", None)
    return out


def _normalize_owner_identity(user: dict[str, Any] | None) -> dict[str, str] | None:
    """Return a durable Hayabusa owner identity, or None for anonymous/boot placeholders."""
    if not isinstance(user, dict):
        return None
    sub = str(user.get("sub") or user.get("oauth_id") or "").strip()
    username = str(user.get("username") or user.get("login") or "").strip()
    email = str(user.get("email") or "").strip()
    provider = str(user.get("provider") or user.get("oauth_provider") or "").strip().lower()
    owner = (sub or username or email).strip().lower()
    if not owner or owner in {"boot", "controller", "anon"} or provider == "boot":
        return None
    return {
        "username": username[:120],
        "email": email[:200],
        "provider": provider[:64],
        "sub": (sub or username or email)[:200],
    }


class HayabusaEnroller:
    def __init__(self, settings: Settings, vault: SecretsVault | None = None) -> None:
        self.settings = settings
        self.vault = vault
        self.state_path = settings.state_dir / "enrollment.json"
        self._key_path = settings.state_dir / "mesh_preauth.key"

    def status(self) -> dict[str, Any]:
        if not self.state_path.is_file():
            return {"enrolled": False, "preauth_key_set": bool(self.load_preauth())}
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return {"enrolled": False, "preauth_key_set": bool(self.load_preauth())}
            view = public_enroll_view(data)
            view["preauth_key_set"] = bool(self.load_preauth())
            return view
        except (OSError, json.JSONDecodeError):
            return {"enrolled": False, "preauth_key_set": bool(self.load_preauth())}

    def load_owner_identity(self) -> dict[str, str] | None:
        """Last authenticated Hayabusa owner used for boot reconnect / map ownership."""
        st = self.status()
        ident = st.get("owner_identity") if isinstance(st.get("owner_identity"), dict) else None
        return _normalize_owner_identity(ident)

    def save_owner_identity(self, user: dict[str, Any] | None) -> dict[str, str] | None:
        """Persist a real owner identity into enrollment.json (never boot placeholders)."""
        ident = _normalize_owner_identity(user)
        if not ident:
            return None
        data: dict[str, Any] = {}
        if self.state_path.is_file():
            try:
                loaded = json.loads(self.state_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    data = loaded
            except (OSError, json.JSONDecodeError):
                data = {}
        data["owner_identity"] = ident
        self._save(data)
        return ident

    def _save(self, data: dict[str, Any]) -> None:
        self.settings.state_dir.mkdir(parents=True, exist_ok=True)
        payload = public_enroll_view(data)
        # Never clobber a good enrollment with a failed phone-home result.
        if not payload.get("enrolled") and self.state_path.is_file():
            try:
                existing = json.loads(self.state_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                existing = None
            if isinstance(existing, dict) and existing.get("enrolled"):
                logger.warning(
                    "enrollment phone-home failed (%s) — keeping prior enrollment on disk",
                    str(payload.get("error") or "unknown")[:200],
                )
                return
        self.state_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _store_preauth(self, preauth: str) -> None:
        """Keep join key in process memory + encrypted vault only (never in API JSON)."""
        preauth = (preauth or "").strip()
        if not preauth:
            return
        self.settings.hayabusa_preauth_key = preauth
        if self.vault is not None:
            try:
                self.vault.put(MESH_PREAUTH_VAULT_KEY, preauth, allow_reserved=True)
            except ValueError:
                pass
        # Remove legacy plaintext file if present
        try:
            if self._key_path.is_file():
                self._key_path.unlink()
        except OSError:
            pass

    def load_preauth(self) -> str:
        if self.vault is not None:
            val = self.vault.get(MESH_PREAUTH_VAULT_KEY, allow_reserved=True)
            if val:
                return val.strip()
        if self._key_path.is_file():
            try:
                legacy = self._key_path.read_text(encoding="utf-8").strip()
            except OSError:
                legacy = ""
            if legacy:
                # Migrate off plaintext disk
                self._store_preauth(legacy)
                return legacy
        return (self.settings.hayabusa_preauth_key or "").strip()

    async def enroll(self, user: dict[str, Any] | None = None) -> dict[str, Any]:
        """Contact Hayabusa introducer and obtain mesh + control-plane credentials.

        Returns a *public* status dict only. The preauth key is stored for the
        controller process via ``load_preauth()`` and is never included here.
        """
        base = (self.settings.hayabusa_public_url or "https://hayabusa.tracedroute.net").rstrip("/")
        url = f"{base}/api/controller/enroll"
        payload = {
            "hostname": self.settings.controller_mesh_hostname,
            "peer_type": "controller",
            "user": user or {},
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        # Legacy optional shared token — not required (mesh + user OAuth are the trust).
        token = (self.settings.controller_bridge_token or "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            async with httpx.AsyncClient(timeout=45.0, follow_redirects=True) as client:
                resp = await client.post(url, json=payload, headers=headers)
            data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            if resp.status_code >= 400 or not isinstance(data, dict) or not data.get("ok"):
                err = (data.get("error") if isinstance(data, dict) else None) or f"HTTP {resp.status_code}"
                out = {"ok": False, "error": err, "enrolled": False, "status_code": resp.status_code}
                self._save(out)
                return public_enroll_view(out)

            mesh = str(data.get("mesh_server_url") or "").strip()
            preauth = str(data.get("preauth_key") or "").strip()
            ws_url = str(data.get("ws_url") or "").strip()
            ws_url_mesh = str(data.get("ws_url_mesh") or "").strip()
            if mesh:
                self.settings.hayabusa_mesh_server_url = mesh
            if ws_url_mesh:
                # Prefer mesh control URL once VPN is up.
                self.settings.hayabusa_ws_url = ws_url_mesh
            elif ws_url:
                self.settings.hayabusa_ws_url = ws_url
            if preauth:
                self._store_preauth(preauth)

            caps = data.get("capabilities") if isinstance(data.get("capabilities"), dict) else {}
            cp = data.get("control_plane") if isinstance(data.get("control_plane"), dict) else {}
            if isinstance(cp, dict) and ws_url_mesh and not cp.get("websocket_mesh"):
                cp = {**cp, "websocket_mesh": ws_url_mesh}
            out = {
                "ok": True,
                "enrolled": True,
                "mesh_server_url": mesh,
                "preauth_key_set": bool(preauth),
                "ws_url": ws_url,
                "ws_url_mesh": ws_url_mesh,
                "public_url": data.get("public_url"),
                "organization": data.get("organization"),
                "site_id": data.get("site_id"),
                "control_plane": cp or data.get("control_plane") or {},
                "hostname": data.get("hostname") or self.settings.controller_mesh_hostname,
                "control_node_ip": str(data.get("control_node_ip") or "").strip(),
                "control_node_subnet": str(data.get("control_node_subnet") or "").strip(),
                "private_realm_cidr": str(data.get("private_realm_cidr") or "").strip(),
                "tenant": str(data.get("tenant") or "").strip(),
                "node_key": str(data.get("node_key") or "").strip(),
                "capabilities": caps,
            }
            # Prefer Hayabusa-assigned unique hostname. Display may include #N;
            # Tailscale/Headscale needs the DNS-safe mesh_hostname (name-2).
            display_host = str(
                data.get("display_hostname") or data.get("hostname") or ""
            ).strip()
            mesh_host = str(data.get("mesh_hostname") or "").strip()
            if not mesh_host and display_host:
                mesh_host = display_host.replace("#", "-")
            if mesh_host:
                self.settings.controller_mesh_hostname = mesh_host
            if display_host:
                out["hostname"] = display_host
                out["display_hostname"] = display_host
            if mesh_host:
                out["mesh_hostname"] = mesh_host
            owner = _normalize_owner_identity(user)
            if owner:
                out["owner_identity"] = owner
            else:
                # Preserve previously claimed owner across anonymous/boot enrolls.
                prev = self.load_owner_identity()
                if prev:
                    out["owner_identity"] = prev
            self._save(out)
            logger.info("enrolled with Hayabusa introducer %s mesh=%s", base, mesh)
            return public_enroll_view(out)
        except Exception as exc:  # noqa: BLE001
            logger.warning("enrollment failed: %s", exc)
            out = {"ok": False, "error": str(exc)[:500], "enrolled": False}
            self._save(out)
            return public_enroll_view(out)
