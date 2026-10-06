"""Dial Hayabusa control-plane endpoints over the mesh VPN.

With ``--tun=userspace-networking``, the kernel has no 100.64/10 route, so a normal
TCP connect to ``ws://100.64.0.1:8791`` never reaches Tailscale. Dial through the
local SOCKS5 server that ``tailscaled`` exposes (see entrypoint ``--socks5-server``).

Kernel TUN peers can dial directly; we still fall back to SOCKS if direct fails.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import socket
import struct
from urllib.parse import urlparse

logger = logging.getLogger("hayabusa-controller.mesh_dial")

_DEFAULT_SOCKS = "127.0.0.1:1055"
_DEFAULT_MESH_WS_PORT = 8791


def _socks_endpoint() -> tuple[str, int] | None:
    raw = (os.environ.get("TS_SOCKS5") or os.environ.get("CONTROLLER_MESH_SOCKS5") or _DEFAULT_SOCKS).strip()
    if not raw or raw.lower() in {"0", "off", "false", "no"}:
        return None
    host, _, port_s = raw.rpartition(":")
    if not host or not port_s:
        return None
    try:
        return host, int(port_s)
    except ValueError:
        return None


def host_is_mesh(host: str) -> bool:
    h = (host or "").strip().strip("[]")
    if not h:
        return False
    try:
        addr = ipaddress.ip_address(h)
        return addr in ipaddress.ip_network("100.64.0.0/10") or addr in ipaddress.ip_network("fd7a:115c:a1e0::/48")
    except ValueError:
        return h.endswith(".ts.net") or h in {"peregrine-main", "hayabusa"}


def ws_url_is_mesh(ws_url: str) -> bool:
    try:
        return host_is_mesh(urlparse(ws_url).hostname or "")
    except Exception:  # noqa: BLE001
        return False


def socks5_connect_sync(dest_host: str, dest_port: int, *, timeout: float = 15.0) -> socket.socket:
    endpoint = _socks_endpoint()
    if not endpoint:
        raise RuntimeError("mesh SOCKS5 is disabled")
    proxy_host, proxy_port = endpoint
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(b"\x05\x01\x00")
        resp = s.recv(2)
        if resp != b"\x05\x00":
            raise RuntimeError(f"SOCKS5 greeting failed: {resp!r}")
        host_b = dest_host.encode("utf-8")
        if len(host_b) > 255:
            raise RuntimeError("destination host too long for SOCKS5")
        req = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + struct.pack("!H", dest_port)
        s.sendall(req)
        hdr = s.recv(4)
        if len(hdr) < 4 or hdr[0] != 5 or hdr[1] != 0:
            raise RuntimeError(f"SOCKS5 connect failed: {hdr!r}")
        atyp = hdr[3]
        if atyp == 1:
            s.recv(4 + 2)
        elif atyp == 3:
            ln = s.recv(1)[0]
            s.recv(ln + 2)
        elif atyp == 4:
            s.recv(16 + 2)
        else:
            raise RuntimeError(f"SOCKS5 bad atyp {atyp}")
    except Exception:
        s.close()
        raise
    s.settimeout(None)
    s.setblocking(False)
    return s


def _kernel_has_mesh_route() -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("100.64.0.1", 1))
            local = probe.getsockname()[0]
            return str(local).startswith("100.")
    except OSError:
        return False


async def _direct_tcp(dest_host: str, dest_port: int, *, timeout: float) -> socket.socket:
    loop = asyncio.get_running_loop()
    family = socket.AF_INET6 if ":" in dest_host and not dest_host.startswith("100.") else socket.AF_INET
    # Prefer IPv4 for CGNAT mesh IPs.
    if host_is_mesh(dest_host) and ":" not in dest_host:
        family = socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setblocking(False)
    try:
        await asyncio.wait_for(loop.sock_connect(sock, (dest_host, dest_port)), timeout=timeout)
        return sock
    except Exception:
        sock.close()
        raise


async def open_mesh_tcp(dest_host: str, dest_port: int, *, timeout: float = 15.0) -> socket.socket:
    """Return a connected non-blocking socket to dest via kernel route or SOCKS."""
    direct_err: Exception | None = None
    if _kernel_has_mesh_route() or not _socks_endpoint():
        try:
            return await _direct_tcp(dest_host, dest_port, timeout=min(timeout, 8.0))
        except Exception as exc:  # noqa: BLE001
            direct_err = exc
            if not _socks_endpoint():
                raise

    logger.info(
        "mesh dial %s:%s via SOCKS5%s",
        dest_host,
        dest_port,
        f" (direct failed: {direct_err})" if direct_err else "",
    )
    return await asyncio.to_thread(socks5_connect_sync, dest_host, dest_port, timeout=timeout)


async def open_ws_socket_for_url(ws_url: str, *, timeout: float = 15.0) -> socket.socket | None:
    """If this is a mesh control URL, return a pre-connected socket; else None (normal dial)."""
    if not ws_url_is_mesh(ws_url):
        return None
    parsed = urlparse(ws_url)
    host = (parsed.hostname or "").strip()
    if not host:
        return None
    port = parsed.port
    if port is None:
        if parsed.scheme in {"wss", "https"}:
            port = 443
        elif host_is_mesh(host):
            port = _DEFAULT_MESH_WS_PORT
        else:
            port = 80
    return await open_mesh_tcp(host, int(port), timeout=timeout)
