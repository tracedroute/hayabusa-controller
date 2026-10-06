#!/usr/bin/env python3
"""OpenPLC v4 runtime HTTPS API helper (JWT bootstrap, login, status)."""
from __future__ import annotations

import argparse
import json
import ssl
import urllib.error
import urllib.request


def _ssl_context(insecure: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _request(
    base_url: str,
    method: str,
    path: str,
    *,
    body: dict | None = None,
    token: str | None = None,
    timeout: float = 8.0,
    insecure: bool = True,
) -> tuple[int, dict | str]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{base_url.rstrip('/')}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=_ssl_context(insecure), timeout=timeout) as resp:
            raw = resp.read().decode()
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, raw


def bootstrap_user(base_url: str, username: str, password: str, timeout: float) -> dict:
    status, body = _request(
        base_url,
        "POST",
        "/api/create-user",
        body={"username": username, "password": password},
        timeout=timeout,
    )
    return {"action": "create-user", "status": status, "body": body}


def login(base_url: str, username: str, password: str, timeout: float) -> dict:
    status, body = _request(
        base_url,
        "POST",
        "/api/login",
        body={"username": username, "password": password},
        timeout=timeout,
    )
    if status != 200 or not isinstance(body, dict) or not body.get("access_token"):
        raise RuntimeError(f"OpenPLC v4 login failed ({status}): {body}")
    return {"status": status, "access_token": body["access_token"], "body": body}


def status(base_url: str, token: str, timeout: float) -> dict:
    status_code, body = _request(base_url, "GET", "/api/status", token=token, timeout=timeout)
    if status_code != 200:
        raise RuntimeError(f"OpenPLC v4 status failed ({status_code}): {body}")
    return {"status": status_code, "body": body}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["bootstrap", "login", "status", "lab-session"])
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--username", default="labuser")
    parser.add_argument("--password", default="LabOps123!")
    parser.add_argument("--token")
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()

    try:
        if args.action == "bootstrap":
            result = bootstrap_user(args.base_url, args.username, args.password, args.timeout)
            ok = result["status"] in (200, 201, 400, 409)
        elif args.action == "login":
            result = login(args.base_url, args.username, args.password, args.timeout)
            ok = True
        elif args.action == "status":
            if not args.token:
                raise ValueError("--token is required for status")
            result = status(args.base_url, args.token, args.timeout)
            ok = True
        else:
            bootstrap = bootstrap_user(args.base_url, args.username, args.password, args.timeout)
            session = login(args.base_url, args.username, args.password, args.timeout)
            runtime = status(args.base_url, session["access_token"], args.timeout)
            result = {"bootstrap": bootstrap, "login": {"status": session["status"]}, "runtime": runtime}
            ok = runtime["status"] == 200

        print(json.dumps({"success": ok, "result": result}, indent=2, default=str))
        return 0 if ok else 1
    except Exception as exc:
        print(json.dumps({"success": False, "error": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
