#!/usr/bin/env python3
"""Read/write Rockwell Logix tags — pycomm3 for hardware, cpppo client for lab emulators."""
from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys


CPPPO_LINE = re.compile(
    r"^\s+(?P<tag>.+?)\s+(?P<op>==|<=)\s+(?P<value>\[[^\]]*\]):\s+'(?P<status>\w+)'$"
)


def _normalize_cpppo_tag(raw: str) -> str:
    raw = raw.strip()
    match = re.match(r"^(\S+?\[[^\]]+\])", raw)
    if match:
        return match.group(1)
    return raw.split()[0]


def _cpppo_address(host: str, port: int) -> str:
    host = host.strip()
    if ":" in host and "/" not in host:
        return host
    return f"{host}:{port}"


def _cpppo_run(address: str, specs: list[str], timeout: float) -> list[dict]:
    cmd = [
        sys.executable,
        "-m",
        "cpppo.server.enip.client",
        "-a",
        address,
        "-p",
        "-t",
        str(timeout),
        *specs,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 15, check=False)
    values: list[dict] = []
    for line in (proc.stdout or "").splitlines():
        match = CPPPO_LINE.match(line)
        if not match:
            continue
        status = match.group("status")
        raw_val = match.group("value")
        try:
            parsed = ast.literal_eval(raw_val)
        except (SyntaxError, ValueError):
            parsed = raw_val
        if isinstance(parsed, list) and len(parsed) == 1:
            parsed = parsed[0]
        values.append(
            {
                "tag": _normalize_cpppo_tag(match.group("tag")),
                "value": parsed,
                "error": "" if status == "OK" else status,
            }
        )
    if proc.returncode != 0 and not values:
        detail = (proc.stderr or proc.stdout or "cpppo client failed").strip()
        raise RuntimeError(detail)
    return values


def _pycomm3_path(host: str, path: str | None) -> str:
    if path:
        return path
    return host if "/" in host else f"{host}/0"


def _pycomm3_read(path: str, tags: list[str], timeout: float) -> list[dict]:
    from pycomm3 import LogixDriver

    with LogixDriver(path, init_tags=False) as plc:
        try:
            plc.socket_timeout = timeout
        except Exception:
            pass
        rows = plc.read(*tags)
        if not isinstance(rows, list):
            rows = [rows]
        return [
            {
                "tag": row.tag,
                "value": row.value,
                "error": str(row.error) if row.error else "",
            }
            for row in rows
        ]


def _pycomm3_write(path: str, tag: str, value, timeout: float) -> list[dict]:
    from pycomm3 import LogixDriver

    with LogixDriver(path, init_tags=False) as plc:
        try:
            plc.socket_timeout = timeout
        except Exception:
            pass
        rows = plc.write((tag, value))
        if not isinstance(rows, list):
            rows = [rows]
        return [
            {
                "tag": row.tag,
                "value": row.value,
                "error": str(row.error) if row.error else "",
            }
            for row in rows
        ]


def _parse_value(raw: str):
    text = raw.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)

    read_p = sub.add_parser("read")
    read_p.add_argument("--host", required=True)
    read_p.add_argument("--path")
    read_p.add_argument("--port", type=int, default=44818)
    read_p.add_argument("--engine", choices=["pycomm3", "cpppo"], default="pycomm3")
    read_p.add_argument("--timeout", type=float, default=5.0)
    read_p.add_argument("--tags", required=True, help="Comma-separated tag names")

    write_p = sub.add_parser("write")
    write_p.add_argument("--host", required=True)
    write_p.add_argument("--path")
    write_p.add_argument("--port", type=int, default=44818)
    write_p.add_argument("--engine", choices=["pycomm3", "cpppo"], default="pycomm3")
    write_p.add_argument("--timeout", type=float, default=5.0)
    write_p.add_argument("--tag", required=True)
    write_p.add_argument("--value", required=True, help="JSON-encoded value")

    args = parser.parse_args()
    tags = [item.strip() for item in args.tags.split(",") if item.strip()] if args.action == "read" else []

    try:
        if args.action == "read":
            if args.engine == "cpppo":
                values = _cpppo_run(_cpppo_address(args.host, args.port), tags, args.timeout)
            else:
                values = _pycomm3_read(_pycomm3_path(args.host, args.path), tags, args.timeout)
        else:
            value = _parse_value(args.value)
            if args.engine == "cpppo":
                spec = f"{args.tag}={json.dumps(value) if isinstance(value, str) else value}"
                values = _cpppo_run(_cpppo_address(args.host, args.port), [spec], args.timeout)
            else:
                values = _pycomm3_write(_pycomm3_path(args.host, args.path), args.tag, value, args.timeout)

        ok = any(not row.get("error") for row in values)
        print(
            json.dumps(
                {
                    "success": ok,
                    "result": {
                        "engine": args.engine,
                        "values": values,
                    },
                },
                indent=2,
                default=str,
            )
        )
        return 0 if ok else 1
    except Exception as exc:
        print(json.dumps({"success": False, "error": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
