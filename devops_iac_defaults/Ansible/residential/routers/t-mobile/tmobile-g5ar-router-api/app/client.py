from __future__ import annotations

from typing import Any

import requests

from .config import settings


class DeviceClient:
    """T-Mobile 5G Gateway G5AR/G5SE — scaffold client (generic_gateway)."""

    def is_reachable(self) -> bool:
        if not settings.api_supported:
            try:
                import socket
                host = settings.device_host.replace("https://", "").replace("http://", "").split("/")[0]
                s = socket.create_connection((host, 80), timeout=3)
                s.close()
                return True
            except OSError:
                return False
        try:
            url = settings.router_host or settings.switch_host or settings.unifi_host or settings.device_host
            if not url.startswith("http"):
                url = f"http://{url}"
            r = requests.get(url, timeout=5, verify=settings.unifi_verify_tls)
            return r.status_code < 500
        except requests.RequestException:
            return False

    def ensure_logged_in(self) -> None:
        if not settings.api_supported:
            raise RuntimeError("This device has no programmable local API (unmanaged or unsupported).")
        pwd = (
            settings.router_password
            or settings.switch_password
            or settings.device_password
            or settings.unifi_api_key
        )
        if not pwd:
            raise RuntimeError("Credentials not configured. Set password/API key in .env")

    def status(self) -> dict[str, Any]:
        self.ensure_logged_in()
        return {
            "device": "T-Mobile 5G Gateway G5AR/G5SE",
            "client_type": "generic_gateway",
            "tested": False,
            "note": "Implement device-specific client when hardware is available",
        }
