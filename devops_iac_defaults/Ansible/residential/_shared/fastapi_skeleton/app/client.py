from __future__ import annotations

from typing import Any

import requests

from .config import settings


class DeviceClient:
    """Minimal reachability client — replace probe/status with vendor API calls."""

    def __init__(self) -> None:
        self.base = settings.device_host.rstrip("/")
        self.session = requests.Session()
        self.session.verify = False

    def is_reachable(self) -> bool:
        try:
            r = self.session.get(self.base + "/", timeout=3)
            return r.status_code < 500
        except requests.RequestException:
            return False

    def status(self) -> dict[str, Any]:
        return {
            "reachable": self.is_reachable(),
            "host": self.base,
            "api_supported": settings.api_supported,
        }
