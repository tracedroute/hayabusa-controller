"""Discover what this controller sees on its LAN (neighbors, routes, ifaces).

Used by bridge RPC so Hayabusa can map remote-site infrastructure without
running discovery from the Hayabusa host's network.
"""

from __future__ import annotations

import json
import logging
import os
import re
import socket
import subprocess
import time
from typing import Any

logger = logging.getLogger("hayabusa-controller.lan")

_PRIVATE_RE = re.compile(
    r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)"
)
# Overlay / mesh ifaces must not be reported as the controller's site identity.
_OVERLAY_IFACE_PREFIXES = (
    "docker",
    "br-",
    "veth",
    "cni",
    "flannel",
    "virbr",
    "tun",
    "tailscale",
    "wg",
    "wog",
    "ipsec",
    "vti",
    "kube-",
    "nodelocal",
    "zt",
)
_CGNAT_RE = re.compile(r"^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.")


def _is_overlay_iface(name: str) -> bool:
    n = (name or "").lower()
    return any(n.startswith(p) for p in _OVERLAY_IFACE_PREFIXES)


def _is_mesh_or_cgnat_ip(ip: str) -> bool:
    return bool(_CGNAT_RE.match((ip or "").strip()))


def _run_json(cmd: list[str], timeout: float = 5.0) -> Any:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0 or not (r.stdout or "").strip():
            return None
        return json.loads(r.stdout)
    except Exception as exc:  # noqa: BLE001
        logger.debug("cmd %s failed: %s", cmd, exc)
        return None


def _run_text(cmd: list[str], timeout: float = 5.0) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout or "" if r.returncode == 0 else ""
    except Exception:  # noqa: BLE001
        return ""


def collect_addresses() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    data = _run_json(["ip", "-j", "addr", "show"])
    if not isinstance(data, list):
        return out
    for item in data:
        if not isinstance(item, dict):
            continue
        ifname = str(item.get("ifname") or "")
        if ifname in {"lo"} or _is_overlay_iface(ifname):
            continue
        for addr in item.get("addr_info") or []:
            if not isinstance(addr, dict):
                continue
            if addr.get("family") != "inet":
                continue
            local = str(addr.get("local") or "").strip()
            prefix = addr.get("prefixlen")
            if not local:
                continue
            out.append(
                {
                    "ip": local,
                    "prefix": prefix,
                    "cidr": f"{local}/{prefix}" if prefix is not None else local,
                    "dev": ifname,
                    "scope": str(addr.get("scope") or ""),
                }
            )
    return out


def collect_neighbors() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    data = _run_json(["ip", "-j", "neigh", "show"])
    if not isinstance(data, list):
        # fallback non-json
        text = _run_text(["ip", "neigh", "show"])
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            ip = parts[0]
            mac = None
            dev = None
            state = None
            if "lladdr" in parts:
                mac = parts[parts.index("lladdr") + 1]
            if "dev" in parts:
                dev = parts[parts.index("dev") + 1]
            state = parts[-1] if parts else None
            out.append({"ip": ip, "mac": mac, "dev": dev, "state": state})
        return out
    for item in data:
        if not isinstance(item, dict):
            continue
        ip = str(item.get("dst") or "").strip()
        if not ip:
            continue
        state_raw = item.get("state")
        if isinstance(state_raw, list):
            state = " ".join(str(x) for x in state_raw)
        else:
            state = str(state_raw or "")
        out.append(
            {
                "ip": ip,
                "mac": str(item.get("lladdr") or "").strip() or None,
                "dev": str(item.get("dev") or "").strip() or None,
                "state": state or None,
            }
        )
    return out


def collect_routes() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    data = _run_json(["ip", "-j", "route", "show"])
    if not isinstance(data, list):
        return out
    for item in data:
        if not isinstance(item, dict):
            continue
        dst = str(item.get("dst") or "").strip() or "default"
        out.append(
            {
                "dst": dst,
                "via": str(item.get("gateway") or "").strip() or None,
                "dev": str(item.get("dev") or "").strip() or None,
            }
        )
    return out


def collect_iface_telemetry() -> list[dict[str, Any]]:
    """Bytes counters from /proc/net/dev (controller host view)."""
    rows: list[dict[str, Any]] = []
    try:
        with open("/proc/net/dev", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return rows
    for ln in lines[2:]:
        if ":" not in ln:
            continue
        iface, rest = ln.split(":", 1)
        iface = iface.strip()
        if iface in {"lo"} or iface.startswith("docker") or iface.startswith("br-"):
            continue
        cols = rest.split()
        if len(cols) < 16:
            continue
        try:
            rx = int(cols[0])
            tx = int(cols[8])
        except ValueError:
            continue
        rows.append({"iface": iface, "rx_bytes": rx, "tx_bytes": tx})
    return rows


def _probe_open(ip: str, port: int, timeout: float = 0.35) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        ok = sock.connect_ex((ip, port)) == 0
        sock.close()
        return ok
    except Exception:  # noqa: BLE001
        return False


def build_inventory(*, probe: bool = True, max_hosts: int = 256) -> dict[str, Any]:
    """Return Hayabusa-compatible host list + raw topology from this controller's LAN."""
    addrs = collect_addresses()
    neighbors = collect_neighbors()
    routes = collect_routes()
    default_gw = None
    for r in routes:
        if r.get("dst") == "default" and r.get("via"):
            default_gw = r["via"]
            break

    by_ip: dict[str, dict[str, Any]] = {}

    def _ensure(ip: str) -> dict[str, Any]:
        h = by_ip.get(ip)
        if h is None:
            h = {
                "hostname": ip,
                "ip": ip,
                "name": ip,
                "status": "unknown",
                "mac": None,
                "vendor": "Unknown",
                "latency": None,
                "os": None,
                "type": "Unknown",
                "group": "Controller LAN",
                "networkSources": ["controller-lan"],
                "source": "controller-lan",
            }
            by_ip[ip] = h
        return h

    # Self addresses (controller on its real LAN/WAN NICs — never mesh/VPN overlay)
    for a in addrs:
        ip = a["ip"]
        if ip.startswith("127.") or _is_mesh_or_cgnat_ip(ip):
            continue
        if _is_overlay_iface(str(a.get("dev") or "")):
            continue
        h = _ensure(ip)
        h["status"] = "up"
        h["type"] = "Controller"
        h["group"] = "Controller"
        h["name"] = f"controller@{a.get('dev') or ip}"
        h["hostname"] = h["name"]
        h["self"] = True
        h["dev"] = a.get("dev")

    for n in neighbors:
        ip = str(n.get("ip") or "")
        if not ip or ":" in ip:  # skip v6 for map parity with Hayabusa IPv4 LAN
            continue
        # Prefer private / CGNAT-ish; still include others if on a non-lo iface
        state = (n.get("state") or "").upper()
        if "FAILED" in state or "INCOMPLETE" in state:
            continue
        h = _ensure(ip)
        if n.get("mac"):
            h["mac"] = n["mac"]
        h["dev"] = n.get("dev")
        h["neigh_state"] = n.get("state")
        if "REACHABLE" in state or "STALE" in state or "DELAY" in state or "PROBE" in state:
            h["status"] = "up"
        if len(by_ip) >= max_hosts:
            break

    if default_gw:
        h = _ensure(default_gw)
        h["type"] = "Gateway"
        h["group"] = "Gateway"
        h["status"] = "up"
        h["name"] = f"gateway:{default_gw}"
        h["hostname"] = h["name"]

    if probe:
        common_ports = (22, 80, 443, 445, 8006, 8443)
        for ip, h in list(by_ip.items()):
            if h.get("self"):
                continue
            open_ports = [p for p in common_ports if _probe_open(ip, p)]
            if open_ports:
                h["status"] = "up"
                h["ports"] = open_ports
                if 8006 in open_ports:
                    h["os"] = "Proxmox VE"
                    h["type"] = "Proxmox"
                    h["group"] = "Proxmox"

    hosts = list(by_ip.values())
    cidrs = sorted({a["cidr"] for a in addrs if a.get("cidr")})
    return {
        "ok": True,
        "hosts": hosts,
        "count": len(hosts),
        "addresses": addrs,
        "cidrs": cidrs,
        "default_gateway": default_gw,
        "neighbors": neighbors[:500],
        "routes": routes[:200],
        "collected_at": int(time.time()),
        "hostname": os.environ.get("HOSTNAME") or socket.gethostname(),
        "source": "controller-lan",
    }


def build_topology() -> dict[str, Any]:
    inv = build_inventory(probe=False)
    return {
        "ok": True,
        "success": True,
        "neighbors": inv.get("neighbors") or [],
        "routes": inv.get("routes") or [],
        "default_gateway": inv.get("default_gateway"),
        "source": "controller-lan",
        "collected_at": inv.get("collected_at"),
    }


def build_telemetry() -> dict[str, Any]:
    ifaces = collect_iface_telemetry()
    inv = build_inventory(probe=False, max_hosts=64)
    host_stats = []
    for h in inv.get("hosts") or []:
        if not isinstance(h, dict):
            continue
        host_stats.append(
            {
                "ip": h.get("ip"),
                "status": h.get("status"),
                "mac": h.get("mac"),
                "type": h.get("type"),
            }
        )
    return {
        "ok": True,
        "ifaces": ifaces,
        "hosts": host_stats,
        "host_count": len(host_stats),
        "collected_at": int(time.time()),
        "source": "controller-lan",
    }
