#!/usr/bin/env python3
"""Read Allen-Bradley / Rockwell Logix controller identity via CIP (no tag I/O)."""
from __future__ import annotations

import argparse
import json
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="Controller host or host/path (e.g. 10.0.0.1/0)")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()
    path = args.host if "/" in args.host else f"{args.host}/0"
    try:
        from pycomm3 import LogixDriver

        with LogixDriver(path, init_tags=False) as plc:
            try:
                plc.socket_timeout = args.timeout
            except Exception:
                pass
            info = dict(plc.info or {})
            for key, val in list(info.items()):
                if isinstance(val, (bytes, bytearray)):
                    info[key] = val.hex()
            result = {
                "path": path,
                "product_name": info.get("product_name"),
                "vendor": info.get("vendor"),
                "product_type": info.get("product_type"),
                "product_code": info.get("product_code"),
                "revision": info.get("revision"),
                "serial": info.get("serial"),
                "keyswitch": info.get("keyswitch"),
            }
        print(json.dumps({"success": True, "result": result}, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"success": False, "error": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
