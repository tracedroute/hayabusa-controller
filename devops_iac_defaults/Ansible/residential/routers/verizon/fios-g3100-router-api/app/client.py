from __future__ import annotations

import json
from typing import Any

from verizon_router_client.cr1000a import VerizonRouterClient

from .config import settings

# All CGI modules exposed by the G3100 web UI (from routeInfo in firmware JS).
AVAILABLE_CGIS = sorted(
    {
        "arp",
        "bandwith",
        "basic",
        "bh_log",
        "cellular_signal",
        "diagnostics",
        "dmz",
        "dns_server",
        "dynamic_dns",
        "eng",
        "firewall_access_control",
        "firewall_general",
        "firewall_pinholes",
        "firewall_port_forward",
        "firewall_port_trigger",
        "firewall_static_nat",
        "firmware",
        "home",
        "ip_distribution",
        "ipv6",
        "ipv6_distribution",
        "known_devices",
        "lan_restore",
        "log",
        "ndp",
        "net_connections",
        "network_object",
        "network_slice",
        "ntp",
        "odm",
        "owl",
        "parental",
        "port_conf",
        "port_rule",
        "router_led",
        "routing",
        "scheduler",
        "sipalg",
        "status",
        "ui_admin",
        "ui_remote_admin",
        "upnp",
        "wan_mac_clone",
        "wifi_add_dev_modal",
        "wifi_airtime",
        "wifi_captive",
        "wifi_channel",
        "wifi_channel_history",
        "wifi_channel_settings",
        "wifi_guest",
        "wifi_iot",
        "wifi_primary",
        "wifi_qos",
        "wifi_wfh",
        "wifi_wps",
        "zenreach",
    }
)


class G3100Client(VerizonRouterClient):
    """Verizon Fios G3100 router client with generic CGI helpers."""

    def __init__(self) -> None:
        super().__init__(
            base_url=settings.router_host,
            tls_hostname=settings.router_tls_hostname,
            verify_tls=settings.router_verify_tls,
        )

    def router_info(self) -> dict[str, Any]:
        """Public router metadata (available before login)."""
        r = self.session.get(
            self._url("/cgi/cgi_login.js"),
            timeout=self.timeout_s,
            verify=self.verify_tls,
            headers=self._request_headers(),
        )
        try:
            data = r.json()
            if isinstance(data, dict):
                return data
        except ValueError:
            pass
        # cgi_login.js returns 500 once authenticated; fall back to loginStatus.
        if r.status_code >= 400:
            status = self.login_status()
            if isinstance(status, dict):
                return {
                    "model": "G3100",
                    "routerip": settings.router_host.rsplit("/", 1)[-1],
                    "routername": "Fios Router",
                    "islogin": status.get("islogin"),
                }
        raise RuntimeError(f"Unexpected router info response ({r.status_code})")

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
            raise RuntimeError("Router login failed. Check ROUTER_USERNAME and ROUTER_PASSWORD.")

    def logout_session(self) -> None:
        status = self.login_status()
        token = status.get("token") or ""
        if token:
            self._post_form("/logout.cgi", {"token": token})

    def fetch_cgi(self, name: str) -> dict[str, Any]:
        if name not in AVAILABLE_CGIS:
            raise ValueError(f"Unknown CGI module: {name}")
        text = self._get(f"/cgi/cgi_{name}.js").text
        rod = self._parse_addrod(text)
        cfg = self._parse_addcfg(text)
        return {
            "cgi": name,
            "rod": rod,
            "cfg": {k: {"value": v.val, "field": v.enc_name} for k, v in cfg.items()},
        }

    def fetch_wifi_primary(self) -> dict[str, Any]:
        return self.fetch_cgi("wifi_primary")

    def fetch_network_connections(self) -> dict[str, Any]:
        return self.fetch_cgi("net_connections")

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

    # ---- generic UI write helpers (db.cgi / apply_abstract.cgi) ----
    # These are intentionally low-level so we can expose the full capability surface
    # of the router UI once we have an exact payload/command.
    def get_ui_apply_token(self) -> str:
        self.ensure_logged_in()
        return self.get_apply_token()

    def db(self, payload: dict[str, Any], *, token: str | None = None) -> Any:
        """
        POST payload to /db.cgi.

        Payload format is whatever the router UI sends (e.g. {type,to,body}).
        """
        self.ensure_logged_in()
        if token is None:
            token = self.get_ui_apply_token()
        # _post_db exists in the upstream client; it returns json/text.
        return self._post_db(payload, token=token)  # type: ignore[attr-defined]

    def apply_abstract(
        self,
        form: dict[str, Any],
        *,
        token: str | None = None,
    ) -> Any:
        """
        POST form fields to /apply_abstract.cgi.

        The router UI sends token + command fields (cmd/cmdparam/wait/etc).
        """
        self.ensure_logged_in()
        if token is None:
            token = self.get_ui_apply_token()

        data = {k: str(v) for k, v in form.items()}
        data.setdefault("token", token)

        r = self._post_form("/apply_abstract.cgi", data)  # type: ignore[attr-defined]
        try:
            return r.json()
        except Exception:
            return r.text
