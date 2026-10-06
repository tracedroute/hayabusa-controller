"""Discover this controller's real WAN / VPN-edge public IPv4 for map geolocation.

Mesh peers are addressed as 100.64/10 CGNAT, so Hayabusa's map cannot geocode them.
The datacenter pin also defaults to Hayabusa's own public IP (the VPN hub). Controllers
report the site's egress public IP (and Tailscale STUN endpoint when available) so the
map can place the appliance at an estimated real-world location.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger("hayabusa-controller.wan_public_ip")

_CACHE: dict[str, Any] = {"ts": 0.0, "data": {}}
_CACHE_TTL_SEC = float(os.environ.get("CONTROLLER_WAN_PUBLIC_IP_TTL_SEC") or "300")
_IPIFY = (os.environ.get("CONTROLLER_WAN_PUBLIC_IP_URL") or "https://api.ipify.org?format=json").strip()


_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")


def _is_public_ipv4(value: str) -> bool:
    try:
        addr = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return False
    if addr.version != 4:
        return False
    # Prefer is_global: CGNAT 100.64/10 is not is_private on some Python builds.
    if addr in _CGNAT_NET:
        return False
    return bool(getattr(addr, "is_global", False))


def sanitize_reported_public_ip(value: str) -> str:
    """Return value only when it is a real public IPv4 (never mesh CGNAT / private)."""
    cand = (value or "").strip()
    return cand if _is_public_ipv4(cand) else ""


def _extract_ipv4(text: str) -> str:
    m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text or "")
    if not m:
        return ""
    cand = m.group(1)
    return cand if _is_public_ipv4(cand) else ""


def _ipify_wan() -> str:
    """Public IPv4 via default route (not Tailscale exit unless one is configured)."""
    try:
        req = urllib.request.Request(_IPIFY, headers={"User-Agent": "hayabusa-controller/0.1"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        try:
            data = json.loads(raw)
            ip = str(data.get("ip") or "").strip()
        except json.JSONDecodeError:
            ip = _extract_ipv4(raw)
        return ip if _is_public_ipv4(ip) else ""
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        logger.debug("wan ipify failed: %s", exc)
        return ""


def _tailscale_socket() -> str:
    # Prefer controller.sock so collocated hub (peregrine-main) can own the
    # default tailscaled.sock path without stealing status/IP probes.
    return (
        os.environ.get("TS_SOCKET")
        or os.environ.get("TAILSCALE_SOCKET")
        or "/var/run/tailscale/controller.sock"
    ).strip()


def _tailscale_self_json() -> dict[str, Any]:
    sock = _tailscale_socket()
    ts = "tailscale"
    try:
        proc = subprocess.run(
            [ts, "--socket", sock, "status", "--json"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.debug("tailscale status --json failed: %s", exc)
        return {}
    if proc.returncode != 0 or not (proc.stdout or "").strip():
        return {}
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _vpn_endpoint_from_status(status: dict[str, Any]) -> str:
    """Best public UDP endpoint Tailscale advertised for this node (STUN / DERP edge)."""
    self_obj = status.get("Self") if isinstance(status.get("Self"), dict) else {}
    candidates: list[str] = []
    for key in ("Addrs", "AllowedIPs", "PrimaryRoutes"):
        raw = self_obj.get(key)
        if isinstance(raw, list):
            for item in raw:
                s = str(item or "").strip()
                if not s:
                    continue
                host = s.split("%", 1)[0].split("/", 1)[0].split(":", 1)[0]
                if _is_public_ipv4(host):
                    candidates.append(host)
        elif isinstance(raw, str) and raw.strip():
            host = raw.split("%", 1)[0].split("/", 1)[0].split(":", 1)[0]
            if _is_public_ipv4(host):
                candidates.append(host)
    # Hostinfo.RoutableIPs sometimes carries extras
    hostinfo = self_obj.get("Hostinfo") if isinstance(self_obj.get("Hostinfo"), dict) else {}
    for item in hostinfo.get("RoutableIPs") or []:
        host = str(item or "").split("/", 1)[0].strip()
        if _is_public_ipv4(host):
            candidates.append(host)
    return candidates[0] if candidates else ""


def discover_wan_public_identity(*, force: bool = False) -> dict[str, Any]:
    """Return wan_public_ip + vpn_endpoint_ip (cached). Never raises."""
    now = time.time()
    if not force and _CACHE.get("data") and (now - float(_CACHE.get("ts") or 0)) < _CACHE_TTL_SEC:
        return dict(_CACHE["data"])

    wan = _ipify_wan()
    endpoint = ""
    try:
        endpoint = _vpn_endpoint_from_status(_tailscale_self_json())
    except Exception as exc:  # noqa: BLE001
        logger.debug("vpn endpoint parse failed: %s", exc)

    # Prefer true WAN egress for map geo; keep VPN STUN endpoint as secondary signal.
    geo_ip = wan or endpoint
    out = {
        "wan_public_ip": wan,
        "vpn_endpoint_ip": endpoint,
        "public_ip": geo_ip,
        "geo_ip": geo_ip,
        "discovered_at": int(now),
        "source": "ipify" if wan else ("tailscale_stun" if endpoint else "none"),
    }
    _CACHE["ts"] = now
    _CACHE["data"] = out
    return dict(out)


def hostname_short() -> str:
    try:
        return (socket.gethostname() or "hayabusa-controller").strip() or "hayabusa-controller"
    except OSError:
        return "hayabusa-controller"
