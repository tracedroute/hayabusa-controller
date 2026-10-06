#!/usr/bin/env python3
"""Read-only helpers for Security & Fire Systems playbooks.

Supports:
  - http-get: authenticated/unauthenticated JSON/text GETs
  - bacnet-whois: optional BACnet Who-Is when bacpypes3/BAC0 is installed
  - bacnet-read: optional ReadProperty when bacpypes3 is installed

Never commands life-safety outputs. Exit 0 with JSON result; missing optional
libraries return ok=false with a clear error (playbooks treat as soft fail).
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import urllib.error
import urllib.request


def _out(payload: dict, code: int = 0) -> int:
    print(json.dumps(payload, sort_keys=True))
    return code


def http_get(url: str, token: str = "", verify_tls: bool = False, timeout: float = 8.0) -> dict:
    headers = {"Accept": "application/json, text/plain, */*"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    ctx = None
    if url.lower().startswith("https") and not verify_tls:
        import ssl
        ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(65536).decode("utf-8", errors="replace")
            return {
                "ok": True,
                "status": getattr(resp, "status", 200),
                "url": url,
                "body_preview": body[:2000],
            }
    except urllib.error.HTTPError as exc:
        return {"ok": True, "status": exc.code, "url": url, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "url": url, "error": str(exc)[:300]}


def bacnet_whois(bind: str = "0.0.0.0", timeout: float = 3.0) -> dict:
    try:
        from bacpypes3.ipv4.app import NormalApplication
        from bacpypes3.local.device import DeviceObject
        from bacpypes3.pdu import Address
        import asyncio

        async def _run():
            device = DeviceObject(objectIdentifier=("device", 699), objectName="hayabusa-security-probe")
            app = NormalApplication(device, bind)
            try:
                iams = await asyncio.wait_for(app.who_is(), timeout=timeout)
                return [
                    {
                        "device_identifier": str(getattr(x, "iAmDeviceIdentifier", "")),
                        "address": str(getattr(x, "pduSource", "")),
                    }
                    for x in (iams or [])
                ]
            finally:
                app.close()

        devices = asyncio.run(_run())
        return {"ok": True, "protocol": "bacnet", "devices": devices}
    except Exception as exc:  # noqa: BLE001
        # Soft dependency — still useful as documentation of intent.
        return {
            "ok": False,
            "protocol": "bacnet",
            "error": f"bacnet whois unavailable: {exc}"[:400],
            "hint": "Install bacpypes3 in the runner image for live Who-Is; UDP/47808 reachability can still be checked via wait_for.",
        }


def bacnet_read(address: str, object_id: str, property_id: str = "present-value") -> dict:
    try:
        from bacpypes3.ipv4.app import NormalApplication
        from bacpypes3.local.device import DeviceObject
        from bacpypes3.pdu import Address
        import asyncio

        async def _run():
            device = DeviceObject(objectIdentifier=("device", 698), objectName="hayabusa-security-read")
            app = NormalApplication(device, "0.0.0.0")
            try:
                val = await app.read_property(Address(address), object_id, property_id)
                return {"value": str(val)}
            finally:
                app.close()

        result = asyncio.run(_run())
        return {"ok": True, "protocol": "bacnet", "address": address, "object_id": object_id, "property": property_id, **result}
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "protocol": "bacnet",
            "address": address,
            "object_id": object_id,
            "error": str(exc)[:400],
            "hint": "Install bacpypes3 for live ReadProperty; keep panel_apply_changes=false.",
        }


def udp_probe(host: str, port: int = 47808, timeout: float = 2.0) -> dict:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"\x01", (host, port))
        try:
            data, addr = sock.recvfrom(128)
            return {"ok": True, "host": host, "port": port, "bytes": len(data), "from": f"{addr[0]}:{addr[1]}"}
        except socket.timeout:
            # Many BACnet devices won't answer a bogus payload; open/filtered still useful.
            return {"ok": True, "host": host, "port": port, "note": "UDP sent; no response (common). Pair with bacnet-whois."}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "host": host, "port": port, "error": str(exc)[:300]}
    finally:
        try:
            sock.close()
        except Exception:
            pass


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Security & Fire Systems read-only probe helper")
    sub = p.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("http-get")
    h.add_argument("--url", required=True)
    h.add_argument("--token", default=os.environ.get("SECURITY_PANEL_TOKEN", ""))
    h.add_argument("--verify-tls", action="store_true")

    b = sub.add_parser("bacnet-whois")
    b.add_argument("--bind", default="0.0.0.0")
    b.add_argument("--timeout", type=float, default=3.0)

    r = sub.add_parser("bacnet-read")
    r.add_argument("--address", required=True, help="BACnet device address, e.g. 192.168.1.50")
    r.add_argument("--object-id", required=True, help="e.g. analogValue,1 or binaryInput,12")
    r.add_argument("--property", default="present-value")

    u = sub.add_parser("udp-probe")
    u.add_argument("--host", required=True)
    u.add_argument("--port", type=int, default=47808)

    args = p.parse_args(argv)
    if args.cmd == "http-get":
        return _out(http_get(args.url, token=args.token, verify_tls=args.verify_tls))
    if args.cmd == "bacnet-whois":
        return _out(bacnet_whois(bind=args.bind, timeout=args.timeout))
    if args.cmd == "bacnet-read":
        return _out(bacnet_read(args.address, args.object_id, args.property))
    if args.cmd == "udp-probe":
        return _out(udp_probe(args.host, args.port))
    return _out({"ok": False, "error": "unknown command"}, 2)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
