from __future__ import annotations

from typing import Any

from verizon_router_client.cr1000a import VerizonRouterClient

from .config import settings


class CR1000AClient(VerizonRouterClient):
    """Verizon Fios CR1000A/CR1000B router client."""

    def __init__(self) -> None:
        super().__init__(
            base_url=settings.router_host,
            tls_hostname=settings.router_tls_hostname,
            verify_tls=settings.router_verify_tls,
        )

    def ensure_logged_in(self) -> None:
        status = self.login_status()
        if status.get("islogin") == "1":
            return
        if not settings.router_password:
            raise RuntimeError(
                "Router password not configured. Set ROUTER_PASSWORD in .env"
            )
        self.login(settings.router_username, settings.router_password, keep_login=True)
        status = self.login_status()
        if status.get("islogin") != "1":
            raise RuntimeError("Router login failed.")

    def logout_session(self) -> None:
        status = self.login_status()
        token = status.get("token") or ""
        if token:
            self._post_form("/logout.cgi", {"token": token})

    def status_summary(self) -> dict[str, Any]:
        rod, cfg = self.fetch_status()
        return {
            "uptime_seconds": self.get_uptime_seconds(),
            "wan_ipv4": self.get_wan_ipv4(),
            "wan_ipv6": self.get_wan_ipv6(),
            "wan_dns": self.get_wan_dns_servers(),
            "rod": rod,
            "cfg": {k: v.val for k, v in cfg.items()},
        }

    def is_reachable(self) -> bool:
        try:
            self.login_status()
            return True
        except Exception:
            return False
