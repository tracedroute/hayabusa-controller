#!/usr/bin/env python3
"""Hayabusa PLC/SCADA CLI — same dispatch as /api/plc/read and /api/plc/write."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request


def _load_payload(args: argparse.Namespace) -> dict:
    if args.payload_env:
        raw = os.environ.get(args.payload_env, "").strip()
        if not raw:
            raise SystemExit(f"Environment variable {args.payload_env} is empty")
        return json.loads(raw)
    if args.payload:
        return json.loads(args.payload)
    if args.payload_file:
        with open(args.payload_file, encoding="utf-8") as handle:
            return json.load(handle)
    raise SystemExit("Provide --payload, --payload-file, or --payload-env")


def _plc_string(value, label: str, max_len: int) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len:
        raise ValueError(f"Invalid {label}")
    return text


def _plc_validate_host(host) -> str:
    host = _plc_string(host, "host", 253)
    if not re.match(r"^[A-Za-z0-9_.\-]+$", host):
        raise ValueError("Invalid host")
    return host


def _plc_int(value, label: str, min_v: int, max_v: int) -> int:
    try:
        num = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid {label}") from exc
    if num < min_v or num > max_v:
        raise ValueError(f"Invalid {label}")
    return num


def _plc_float(value, label: str, min_v: float, max_v: float) -> float:
    try:
        num = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid {label}") from exc
    if num < min_v or num > max_v:
        raise ValueError(f"Invalid {label}")
    return num


def _parse_jsonish_value(value):
    if isinstance(value, (dict, list, bool, int, float)) or value is None:
        return value
    text = str(value).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _opcua_lab_helpers():
    for path in ("/var/lib/peregrine/patches", "/peregrine"):
        if path not in sys.path:
            sys.path.insert(0, path)
    from opcua_lab import opcua_read_signed, opcua_write_signed

    return opcua_read_signed, opcua_write_signed


def _opcua_read_cli(data: dict) -> dict:
    host = _plc_validate_host(data.get("host"))
    port = _plc_int(data.get("port", 4840), "port", 1, 65535)
    endpoint = str(data.get("endpoint") or f"opc.tcp://{host}:{port}").strip()
    if not endpoint.startswith("opc.tcp://") or len(endpoint) > 300:
        raise ValueError("Invalid OPC UA endpoint")
    node_id = _plc_string(data.get("node_id"), "OPC UA node id", 220)
    timeout_sec = min(max(_plc_float(data.get("timeout", 3), "timeout", 0.5, 30.0), 0.5), 30.0)
    security = str(data.get("security") or "auto").strip().lower()

    if security in ("auto", "sign", "signed", "basic256sha256"):
        opcua_read_signed, _ = _opcua_lab_helpers()
        return opcua_read_signed(
            data, timeout_sec, _plc_validate_host, _plc_string, _plc_int, _plc_float
        )

    sys.path.insert(0, "/peregrine")
    from run import _opcua_read

    return _opcua_read(data, timeout_sec)


def _opcua_write_cli(data: dict) -> dict:
    host = _plc_validate_host(data.get("host"))
    port = _plc_int(data.get("port", 4840), "port", 1, 65535)
    endpoint = str(data.get("endpoint") or f"opc.tcp://{host}:{port}").strip()
    if not endpoint.startswith("opc.tcp://") or len(endpoint) > 300:
        raise ValueError("Invalid OPC UA endpoint")
    _plc_string(data.get("node_id"), "OPC UA node id", 220)
    if "value" not in data:
        raise ValueError("OPC UA write requires value")
    timeout_sec = min(max(_plc_float(data.get("timeout", 3), "timeout", 0.5, 30.0), 0.5), 30.0)
    security = str(data.get("security") or "auto").strip().lower()

    if security in ("auto", "sign", "signed", "basic256sha256"):
        _, opcua_write_signed = _opcua_lab_helpers()
        return opcua_write_signed(
            data,
            timeout_sec,
            _plc_validate_host,
            _plc_string,
            _plc_int,
            _plc_float,
            _parse_jsonish_value,
        )

    sys.path.insert(0, "/peregrine")
    from run import _opcua_write

    return _opcua_write(data, timeout_sec)


def _dispatch(action: str, payload: dict) -> dict:
    protocol = str(payload.get("protocol") or "").lower()
    if protocol == "opcua":
        if action == "read":
            return _opcua_read_cli(payload)
        if action == "write":
            payload.setdefault("authorized", True)
            return _opcua_write_cli(payload)

    sys.path.insert(0, "/peregrine")
    from run import _plc_read_dispatch, _plc_write_dispatch

    if action == "read":
        return _plc_read_dispatch(payload)
    if action == "write":
        payload.setdefault("authorized", True)
        return _plc_write_dispatch(payload)
    raise SystemExit(f"Unsupported action: {action}")


def _fuxa_status(url: str, timeout: float) -> dict:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {
                "url": url,
                "reachable": True,
                "status_code": resp.status,
            }
    except urllib.error.HTTPError as exc:
        return {
            "url": url,
            "reachable": exc.code < 500,
            "status_code": exc.code,
            "error": str(exc),
        }
    except Exception as exc:
        return {"url": url, "reachable": False, "error": str(exc)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    for action in ("read", "write"):
        p = sub.add_parser(action, help=f"PLC {action} via Hayabusa dispatch")
        p.add_argument("--payload", help="JSON payload string")
        p.add_argument("--payload-file", help="Path to JSON payload file")
        p.add_argument("--payload-env", help="Environment variable containing JSON payload")

    fuxa = sub.add_parser("fuxa-status", help="Check FUXA SCADA/HMI HTTP reachability")
    fuxa.add_argument("--url", default="http://127.0.0.1:1881/")
    fuxa.add_argument("--timeout", type=float, default=5.0)

    drivers = sub.add_parser("drivers", help="Report installed Hayabusa PLC driver modules")
    args = parser.parse_args()

    try:
        if args.command == "fuxa-status":
            result = _fuxa_status(args.url, args.timeout)
        elif args.command == "drivers":
            sys.path.insert(0, "/peregrine")
            from run import _PLC_DRIVER_SPECS, _plc_driver_available

            result = {
                "drivers": [
                    {
                        "protocol": key,
                        "label": spec.get("label"),
                        "available": _plc_driver_available(key),
                        "module": spec.get("module"),
                        "brands": spec.get("brands") or [],
                    }
                    for key, spec in _PLC_DRIVER_SPECS.items()
                ]
            }
        else:
            payload = _load_payload(args)
            result = _dispatch(args.command, payload)
        print(json.dumps({"success": True, "result": result}, indent=2, default=str))
        return 0
    except PermissionError as exc:
        print(json.dumps({"success": False, "error": str(exc)}))
        return 3
    except (ValueError, RuntimeError) as exc:
        print(json.dumps({"success": False, "error": str(exc)}))
        return 2
    except Exception as exc:
        print(json.dumps({"success": False, "error": str(exc) or "PLC command failed"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
