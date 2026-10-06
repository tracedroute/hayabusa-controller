from __future__ import annotations

from typing import Any

import requests

from .config import settings


class UniFiClient:
    """UniFi Network Integration API v1 client (UDR/UDM/UCG)."""

    def __init__(self) -> None:
        self.session = requests.Session()
        self.base = settings.unifi_host.rstrip("/")
        self.site = settings.unifi_site_id

    def _headers(self) -> dict[str, str]:
        if not settings.unifi_api_key:
            raise RuntimeError("UniFi API key not configured. Set UNIFI_API_KEY in .env")
        return {
            "X-API-KEY": settings.unifi_api_key,
            "Accept": "application/json",
        }

    def _url(self, path: str) -> str:
        return f"{self.base}/proxy/network/integration/v1/sites/{self.site}/{path.lstrip('/')}"

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        r = self.session.get(
            self._url(path),
            headers=self._headers(),
            params=params,
            timeout=15,
            verify=settings.unifi_verify_tls,
        )
        r.raise_for_status()
        return r.json()

    def is_reachable(self) -> bool:
        try:
            r = self.session.get(
                f"{self.base}/",
                timeout=5,
                verify=settings.unifi_verify_tls,
            )
            return r.status_code < 500
        except requests.RequestException:
            return False

    def has_api_key(self) -> bool:
        return bool(settings.unifi_api_key)

    def list_devices(self, offset: int = 0, limit: int = 200) -> Any:
        return self._get("devices", params={"offset": offset, "limit": limit})

    def list_clients(self, offset: int = 0, limit: int = 200) -> Any:
        return self._get("clients", params={"offset": offset, "limit": limit})

    def list_networks(self, offset: int = 0, limit: int = 200) -> Any:
        return self._get("networks", params={"offset": offset, "limit": limit})

    def list_wlans(self, offset: int = 0, limit: int = 200) -> Any:
        return self._get("wlans", params={"offset": offset, "limit": limit})

    def site_health(self) -> Any:
        # Legacy stat API still useful on UniFi OS
        url = f"{self.base}/proxy/network/api/s/{self.site}/stat/health"
        r = self.session.get(
            url,
            headers=self._headers(),
            timeout=15,
            verify=settings.unifi_verify_tls,
        )
        r.raise_for_status()
        return r.json()
