"""Controller configuration from environment."""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from pathlib import Path

from .lan import resolve_public_base_url, tls_paths

logger = logging.getLogger("hayabusa-controller.config")

_DEV_SECRET_FALLBACK = "hayabusa-controller-dev-secret-key-change-me!!"
_WEAK_SECRET_MARKERS = (
    "change-me",
    "changeme",
    "change_me",
    "dev-secret",
    "insecure",
    "default",
)


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _env_truthy(name: str) -> bool:
    return _env(name).lower() in {"1", "true", "yes", "on"}


def _secret_is_weak(value: str) -> bool:
    v = (value or "").strip()
    if not v or len(v) < 32:
        return True
    low = v.lower()
    if low == _DEV_SECRET_FALLBACK.lower():
        return True
    return any(marker in low for marker in _WEAK_SECRET_MARKERS)


class Settings:
    def __init__(self) -> None:
        self.secret_key = _env("CONTROLLER_SECRET_KEY") or _env("SECRET_KEY")
        allow_insecure = _env_truthy("CONTROLLER_ALLOW_INSECURE_DEFAULTS")
        if _secret_is_weak(self.secret_key):
            if allow_insecure:
                self.secret_key = _DEV_SECRET_FALLBACK
            else:
                raise RuntimeError(
                    "CONTROLLER_SECRET_KEY must be set to a strong value "
                    "(≥32 chars, not a placeholder). "
                    "For local tests only: CONTROLLER_ALLOW_INSECURE_DEFAULTS=1"
                )

        self.data_dir = Path(_env("CONTROLLER_DATA_DIR", "/var/lib/hayabusa-controller"))
        # Site appliance default is LAN-facing; require explicit opt-in for all-interfaces.
        self.listen_host = _env("CONTROLLER_LISTEN_HOST", "127.0.0.1")
        self.listen_port = int(_env("CONTROLLER_LISTEN_PORT", "8790") or "8790")
        if self.listen_host in {"0.0.0.0", "::", "[::]"} and not _env_truthy("CONTROLLER_ALLOW_LAN_BIND"):
            raise RuntimeError(
                "CONTROLLER_LISTEN_HOST is all-interfaces; "
                "set CONTROLLER_ALLOW_LAN_BIND=1 for LAN appliance installs, "
                "or bind 127.0.0.1 for loopback-only"
            )

        tls = tls_paths(self.data_dir)
        self.tls_enabled = bool(tls["enabled"])
        self.tls_cert = tls["cert"]
        self.tls_key = tls["key"]
        self.tls_auto = bool(tls["auto"])

        configured = _env("CONTROLLER_PUBLIC_BASE_URL")
        self.public_base_url, self.public_base_auto = resolve_public_base_url(
            listen_port=self.listen_port,
            tls_enabled=self.tls_enabled,
            configured=configured,
        )
        # If TLS is on but URL was an explicit http://, upgrade scheme for cookies/links.
        if self.tls_enabled and self.public_base_url.lower().startswith("http://"):
            self.public_base_url = "https://" + self.public_base_url[7:]

        # Secure cookies: follow PUBLIC_BASE_URL scheme, but allow explicit override.
        _sess_override = _env("CONTROLLER_SESSION_HTTPS_ONLY")
        if _sess_override:
            self.session_https_only = _sess_override.lower() in {"1", "true", "yes", "on"}
        else:
            self.session_https_only = self.public_base_url.lower().startswith("https://")
        # Empty / * => no Host header enforcement (typical LAN appliance).
        self.allowed_hosts = _env("CONTROLLER_ALLOWED_HOSTS")
        self.csrf_protect = _env("CONTROLLER_CSRF_PROTECT", "1").lower() not in {
            "0",
            "false",
            "no",
            "off",
        }
        self.trust_x_forwarded_for = _env_truthy("CONTROLLER_TRUST_X_FORWARDED_FOR")

        self.manual_username = _env("CONTROLLER_MANUAL_USERNAME", "admin")
        self.manual_password = _env("CONTROLLER_MANUAL_PASSWORD")

        self.secrets_dir = self.data_dir / "secrets"
        self.iac_dir = self.data_dir / "iac"
        self.devops_workspace = Path(
            _env("CONTROLLER_DEVOPS_WORKSPACE", str(self.iac_dir / "workspace"))
        )
        self.devops_defaults = Path(
            _env(
                "CONTROLLER_DEVOPS_DEFAULTS",
                "/opt/hayabusa-controller/devops_iac_defaults",
            )
        )
        # Hayabusa master layout uses capital-A Ansible/ and OpenTofu/
        self.ansible_dir = self.devops_workspace / "Ansible"
        self.opentofu_dir = self.devops_workspace / "OpenTofu"
        self.state_dir = self.data_dir / "state"
        self.controller_bridge_token = _env("HAYABUSA_CONTROLLER_BRIDGE_TOKEN")
        self.tailscale_state_dir = Path(
            _env("TAILSCALE_STATE_DIR", str(self.data_dir / "tailscale"))
        )

        self.hayabusa_public_url = _env(
            "HAYABUSA_PUBLIC_URL", "https://hayabusa.tracedroute.net"
        ).rstrip("/")
        self.orders_public_url = _env(
            "ORDERS_PUBLIC_URL", "https://service.tracedroute.net"
        ).rstrip("/")
        self.hayabusa_mesh_server_url = _env(
            "HAYABUSA_MESH_SERVER_URL", "https://hayabusa.tracedroute.net:8443"
        )
        self.hayabusa_preauth_key = _env("HAYABUSA_PREAUTH_KEY")
        self.hayabusa_ws_url = _env(
            "HAYABUSA_WS_URL", "wss://hayabusa.tracedroute.net/ws/controller"
        )
        self.controller_mesh_hostname = _env("CONTROLLER_MESH_HOSTNAME", "hayabusa-controller")

        self.oauth = {
            "google": {
                "client_id": _env("GOOGLE_CLIENT_ID"),
                "client_secret": _env("GOOGLE_CLIENT_SECRET"),
                "redirect_uri": _env(
                    "GOOGLE_REDIRECT_URI", f"{self.public_base_url}/auth/google/callback"
                ),
                "authorize": "https://accounts.google.com/o/oauth2/v2/auth",
                "token": "https://oauth2.googleapis.com/token",
                "userinfo": "https://openidconnect.googleapis.com/v1/userinfo",
                "scope": "openid email profile",
            },
            "github": {
                "client_id": _env("GITHUB_CLIENT_ID"),
                "client_secret": _env("GITHUB_CLIENT_SECRET"),
                "redirect_uri": _env(
                    "GITHUB_REDIRECT_URI", f"{self.public_base_url}/auth/github/callback"
                ),
                "authorize": "https://github.com/login/oauth/authorize",
                "token": "https://github.com/login/oauth/access_token",
                "userinfo": "https://api.github.com/user",
                "scope": "read:user user:email",
            },
            "gitlab": {
                # Self-hosted or gitlab.com — set GITLAB_BASE_URL for Advanced GitOps identity link.
                "client_id": _env("GITLAB_CLIENT_ID"),
                "client_secret": _env("GITLAB_CLIENT_SECRET"),
                "base_url": (_env("GITLAB_BASE_URL") or "https://gitlab.com").rstrip("/"),
                "redirect_uri": _env(
                    "GITLAB_REDIRECT_URI", f"{self.public_base_url}/auth/gitlab/callback"
                ),
                "scope": "read_user",
            },
            "discord": {
                "client_id": _env("DISCORD_CLIENT_ID"),
                "client_secret": _env("DISCORD_CLIENT_SECRET"),
                "redirect_uri": _env(
                    "DISCORD_REDIRECT_URI", f"{self.public_base_url}/auth/discord/callback"
                ),
                "authorize": "https://discord.com/api/oauth2/authorize",
                "token": "https://discord.com/api/oauth2/token",
                "userinfo": "https://discord.com/api/users/@me",
                "scope": "identify email",
            },
            "slack": {
                "client_id": _env("SLACK_CLIENT_ID"),
                "client_secret": _env("SLACK_CLIENT_SECRET"),
                "redirect_uri": _env(
                    "SLACK_REDIRECT_URI", f"{self.public_base_url}/auth/slack/callback"
                ),
                "authorize": "https://slack.com/openid/connect/authorize",
                "token": "https://slack.com/api/openid.connect.token",
                "userinfo": "https://slack.com/api/openid.connect.userInfo",
                "scope": "openid profile email",
            },
            "microsoft": {
                "client_id": _env("MICROSOFT_CLIENT_ID") or _env("TEAMS_CLIENT_ID"),
                "client_secret": _env("MICROSOFT_CLIENT_SECRET") or _env("TEAMS_CLIENT_SECRET"),
                "tenant_id": _env("MICROSOFT_TENANT_ID") or _env("TEAMS_TENANT_ID") or "common",
                "redirect_uri": _env(
                    "MICROSOFT_REDIRECT_URI",
                    f"{self.public_base_url}/auth/microsoft/callback",
                ),
                "scope": "openid profile email User.Read",
            },
        }

    def ensure_dirs(self) -> None:
        for d in (
            self.data_dir,
            self.secrets_dir,
            self.iac_dir,
            self.devops_workspace,
            self.state_dir,
            self.tailscale_state_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(d, 0o700)
            except OSError:
                pass

    def provider_configured(self, name: str) -> bool:
        p = self.oauth.get(name) or {}
        return bool(p.get("client_id") and p.get("client_secret"))


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.ensure_dirs()
    return s
