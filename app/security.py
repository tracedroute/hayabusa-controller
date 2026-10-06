"""Controller edge controls: CSRF, IP rate limits, optional Turnstile, host allowlist."""

from __future__ import annotations

import hmac
import html as html_module
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterable
from urllib.parse import urlparse

from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger("hayabusa-controller.security")

_LOCK = threading.Lock()
_DB_PATH: str | None = None

DEFAULT_BUCKETS: dict[str, tuple[int, int]] = {
    "login_post": (10, 300),
    "login_fail": (20, 300),
    "oauth_start": (40, 300),
    "api_mutate": (180, 60),
}

_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_CSRF_EXEMPT_EXACT = frozenset(
    {
        "/healthz",
        "/health",
        "/api/local/reconnect-bridge",
    }
)

_CSRF_EXEMPT_PREFIXES = (
    "/static/",
    "/ztp/fetch/",
)

_LOGIN_PATHS = frozenset({"/login/manual", "/auth/manual", "/"})
_OAUTH_START_RE = re.compile(r"^/auth/(google|github|discord|slack|microsoft|teams)/start$")


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _env_truthy(name: str, default: str = "0") -> bool:
    return _env(name, default).lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)) or default)
    except (TypeError, ValueError):
        return default


def set_abuse_db_path(path: str) -> None:
    global _DB_PATH
    _DB_PATH = path


def _abuse_db_path() -> str:
    if _DB_PATH:
        return _DB_PATH
    data = _env("CONTROLLER_DATA_DIR", "/var/lib/hayabusa-controller") or "/var/lib/hayabusa-controller"
    return os.path.join(data, "edge_abuse.sqlite3")


def rate_limit_enabled() -> bool:
    return _env("CONTROLLER_ABUSE_RATE_LIMIT", "1").lower() not in {"0", "false", "no", "off"}


def csrf_enabled() -> bool:
    return _env("CONTROLLER_CSRF_PROTECT", "1").lower() not in {"0", "false", "no", "off"}


def _bucket_limits(kind: str) -> tuple[int, int]:
    base_limit, base_window = DEFAULT_BUCKETS.get(kind, (60, 60))
    limit = max(1, _env_int(f"CONTROLLER_ABUSE_LIMIT_{kind.upper()}", base_limit))
    window = max(5, _env_int(f"CONTROLLER_ABUSE_WINDOW_{kind.upper()}", base_window))
    return limit, window


def _connect() -> sqlite3.Connection:
    path = _abuse_db_path()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS hits (
            bucket TEXT NOT NULL,
            ts REAL NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ctrl_hits_bucket_ts ON hits(bucket, ts)")
    return conn


def check_ip_rate_limit(kind: str, ip: str | None) -> tuple[bool, str | None]:
    """Return (allowed, error_message)."""
    if not rate_limit_enabled():
        return True, None
    peer = (ip or "").strip() or "unknown"
    limit, window = _bucket_limits(kind)
    key = f"{kind}:{peer}"
    now = time.time()
    cutoff = now - window
    with _LOCK:
        conn = _connect()
        try:
            conn.execute("DELETE FROM hits WHERE bucket = ? AND ts < ?", (key, cutoff))
            row = conn.execute(
                "SELECT COUNT(*) FROM hits WHERE bucket = ? AND ts >= ?", (key, cutoff)
            ).fetchone()
            count = int(row[0] if row else 0)
            if count >= limit:
                conn.commit()
                return False, f"Too many requests — try again shortly ({kind})"
            conn.execute("INSERT INTO hits(bucket, ts) VALUES (?, ?)", (key, now))
            conn.commit()
        finally:
            conn.close()
    return True, None


def client_ip(request: Request) -> str:
    """Prefer direct peer; only trust X-Forwarded-For when explicitly enabled."""
    if _env_truthy("CONTROLLER_TRUST_X_FORWARDED_FOR"):
        xff = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
        if xff:
            return xff
        xri = (request.headers.get("x-real-ip") or "").strip()
        if xri:
            return xri
    if request.client and request.client.host:
        return str(request.client.host)
    return "unknown"


def ensure_csrf_token(session: Any) -> str:
    tok = str(session.get("_csrf_token") or "").strip()
    if tok and len(tok) >= 32:
        return tok
    tok = secrets.token_urlsafe(32)
    session["_csrf_token"] = tok
    return tok


def csrf_tokens_match(expected: str, provided: str) -> bool:
    a = (expected or "").strip()
    b = (provided or "").strip()
    if not a or not b or len(a) < 16 or len(b) < 16:
        return False
    return hmac.compare_digest(a, b)


async def extract_csrf_from_request(request: Request) -> str:
    hdr = (
        request.headers.get("X-CSRF-Token")
        or request.headers.get("X-CSRFToken")
        or ""
    ).strip()
    if hdr:
        return hdr
    ctype = (request.headers.get("content-type") or "").lower()
    if "application/json" in ctype:
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            payload = None
        if isinstance(payload, dict):
            return str(payload.get("csrf_token") or payload.get("_csrf") or "").strip()
        return ""
    if "application/x-www-form-urlencoded" in ctype or "multipart/form-data" in ctype:
        try:
            form = await request.form()
        except Exception:  # noqa: BLE001
            return ""
        return str(form.get("csrf_token") or form.get("_csrf") or "").strip()
    return ""


def csrf_path_exempt(path: str) -> bool:
    p = (path or "/").split("?", 1)[0]
    if len(p) > 1:
        p = p.rstrip("/") or "/"
    if p in _CSRF_EXEMPT_EXACT:
        return True
    for prefix in _CSRF_EXEMPT_PREFIXES:
        if p == prefix.rstrip("/") or p.startswith(prefix):
            return True
    return False


def request_requires_csrf(method: str, path: str, headers: Headers | Any) -> bool:
    if not csrf_enabled():
        return False
    m = (method or "GET").upper()
    if m not in _UNSAFE_METHODS:
        return False
    if csrf_path_exempt(path):
        return False
    try:
        auth = (headers.get("Authorization") or headers.get("authorization") or "").strip()
    except Exception:  # noqa: BLE001
        auth = ""
    if auth.lower().startswith("bearer "):
        return False
    return True


def turnstile_configured() -> bool:
    return bool(_env("TURNSTILE_SECRET_KEY") and _env("TURNSTILE_SITE_KEY"))


def turnstile_site_key() -> str:
    return _env("TURNSTILE_SITE_KEY")


def verify_turnstile(token: str, remote_ip: str | None = None) -> tuple[bool, str | None]:
    secret = _env("TURNSTILE_SECRET_KEY")
    if not secret:
        return True, None
    tok = (token or "").strip()
    if not tok:
        return False, "Bot check required"
    body: dict[str, str] = {"secret": secret, "response": tok}
    if remote_ip:
        body["remoteip"] = remote_ip
    data = urllib.parse.urlencode(body).encode()
    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=data,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace") or "{}")
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return False, f"Bot check unavailable: {exc}"
    if payload.get("success") is True:
        return True, None
    return False, "Bot check failed"


async def extract_turnstile_from_request(request: Request) -> str:
    ctype = (request.headers.get("content-type") or "").lower()
    if "application/json" in ctype:
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            return ""
        if isinstance(payload, dict):
            return str(
                payload.get("cf-turnstile-response") or payload.get("turnstile_token") or ""
            ).strip()
        return ""
    try:
        form = await request.form()
    except Exception:  # noqa: BLE001
        return ""
    return str(form.get("cf-turnstile-response") or "").strip()


def log_auth_failure(ip: str, reason: str = "bad_credentials") -> None:
    """Structured line for optional host fail2ban filters."""
    logger.warning("AUTH_FAIL ip=%s reason=%s", (ip or "unknown").strip() or "unknown", reason)


def allowed_hosts() -> list[str] | None:
    """
    None => do not enforce (LAN appliance default).
    Non-empty list => Starlette TrustedHostMiddleware allowlist.
    """
    raw = _env("CONTROLLER_ALLOWED_HOSTS")
    if not raw or raw == "*":
        return None
    hosts = [h.strip() for h in raw.split(",") if h.strip()]
    return hosts or None


def hosts_from_public_base(public_base_url: str) -> list[str]:
    hosts = ["localhost", "127.0.0.1", "[::1]"]
    try:
        host = urlparse(public_base_url).hostname
        if host:
            hosts.append(host)
    except Exception:  # noqa: BLE001
        pass
    return hosts


def security_headers() -> dict[str, str]:
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Cross-Origin-Opener-Policy": "same-origin",
    }


def _wants_html(scope: Scope, headers: Iterable[tuple[bytes, bytes]]) -> bool:
    if scope.get("type") != "http":
        return False
    ctype = b""
    for k, v in headers:
        if k.lower() == b"content-type":
            ctype = v.lower()
            break
    return b"text/html" in ctype


async def _buffer_http_body(receive: Receive) -> tuple[bytes, Receive]:
    """Consume and replay the request body so handlers can still read it."""
    chunks: list[bytes] = []
    while True:
        message = await receive()
        if message["type"] != "http.request":
            # Unexpected; return a receive that yields this message once.
            async def passthrough() -> Message:
                return message

            return b"", passthrough
        chunks.append(message.get("body") or b"")
        if not message.get("more_body"):
            break
    body = b"".join(chunks)
    sent = False

    async def replay() -> Message:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    return body, replay


class ControllerSecurityMiddleware:
    """Session-aware CSRF, rate limits, security headers, CSRF meta injection."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        path = request.url.path or "/"
        method = (request.method or "GET").upper()
        ip = client_ip(request)
        app_receive = receive

        # Rate-limit OAuth starts early (GET).
        if method == "GET" and _OAUTH_START_RE.match(path):
            ok, msg = check_ip_rate_limit("oauth_start", ip)
            if not ok:
                await JSONResponse(
                    {"ok": False, "error": "rate_limited", "message": msg},
                    status_code=429,
                )(scope, receive, send)
                return

        if (
            method in _UNSAFE_METHODS
            and path.startswith("/api/")
            and not csrf_path_exempt(path)
        ):
            ok, msg = check_ip_rate_limit("api_mutate", ip)
            if not ok:
                await JSONResponse(
                    {"ok": False, "error": "rate_limited", "message": msg},
                    status_code=429,
                )(scope, receive, send)
                return

        # CSRF first for login so failed tokens do not burn login_post budget.
        if request_requires_csrf(method, path, request.headers):
            hdr = (
                request.headers.get("X-CSRF-Token")
                or request.headers.get("X-CSRFToken")
                or ""
            ).strip()
            provided = hdr
            if not provided:
                body, app_receive = await _buffer_http_body(receive)
                request = Request(scope, receive=app_receive)
                request._body = body  # type: ignore[attr-defined]
                provided = await extract_csrf_from_request(request)
            session = request.session
            expected = ensure_csrf_token(session)
            if not csrf_tokens_match(expected, provided):
                accept = (request.headers.get("accept") or "").lower()
                wants_json = "application/json" in accept or path.startswith("/api/")
                if wants_json:
                    await JSONResponse(
                        {
                            "ok": False,
                            "error": "csrf_failed",
                            "message": "Invalid CSRF token",
                        },
                        status_code=403,
                    )(scope, receive, send)
                else:
                    await RedirectResponse(
                        "/login?error=CSRF%20validation%20failed.%20Refresh%20and%20retry.",
                        status_code=302,
                    )(scope, receive, send)
                return

        if method in _UNSAFE_METHODS and path in _LOGIN_PATHS:
            ok, msg = check_ip_rate_limit("login_post", ip)
            if not ok:
                await RedirectResponse(
                    f"/login?error={urllib.parse.quote(msg or 'rate limited')}",
                    status_code=302,
                )(scope, receive, send)
                return

        csrf_tok = ""
        try:
            csrf_tok = ensure_csrf_token(request.session)
        except Exception:  # noqa: BLE001
            csrf_tok = ""

        response_headers: list[tuple[bytes, bytes]] = []

        async def send_wrapper(message: Message) -> None:
            nonlocal response_headers
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                existing = {k.lower() for k, _ in headers}
                for hk, hv in security_headers().items():
                    kb = hk.lower().encode()
                    if kb not in existing:
                        headers.append((kb, hv.encode()))
                        existing.add(kb)
                if csrf_tok and b"x-csrf-token" not in existing:
                    headers.append((b"x-csrf-token", csrf_tok.encode()))
                if _wants_html(scope, headers) and csrf_tok:
                    headers = [(k, v) for k, v in headers if k.lower() != b"content-length"]
                message = {**message, "headers": headers}
                response_headers = headers
                await send(message)
                return

            if message["type"] == "http.response.body" and csrf_tok:
                if _wants_html(scope, response_headers) and not message.get("more_body"):
                    body = message.get("body") or b""
                    try:
                        text = body.decode("utf-8")
                    except UnicodeDecodeError:
                        await send(message)
                        return
                    if "controller-csrf.js" not in text and "</head>" in text.lower():
                        inject = (
                            f'<meta name="csrf-token" content="{html_module.escape(csrf_tok, quote=True)}">\n'
                            f'<script src="/static/js/controller-csrf.js" defer></script>\n'
                        )
                        idx = text.lower().rfind("</head>")
                        if idx >= 0:
                            text = text[:idx] + inject + text[idx:]
                            await send({**message, "body": text.encode("utf-8")})
                            return
            await send(message)

        await self.app(scope, app_receive, send_wrapper)
