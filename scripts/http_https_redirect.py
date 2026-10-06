#!/usr/bin/env python3
"""Tiny HTTP→HTTPS redirector for LAN appliances (uvicorn is TLS-only on the main port)."""

from __future__ import annotations

import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def main() -> int:
    listen_host = (os.environ.get("CONTROLLER_LISTEN_HOST") or "0.0.0.0").strip() or "0.0.0.0"
    try:
        http_port = int(os.environ.get("CONTROLLER_HTTP_REDIRECT_PORT") or "0")
    except ValueError:
        http_port = 0
    try:
        https_port = int(os.environ.get("CONTROLLER_LISTEN_PORT") or "8790")
    except ValueError:
        https_port = 8790
    if http_port <= 0:
        return 0

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args) -> None:  # noqa: A003
            sys.stderr.write("[http-redirect] " + (fmt % args) + "\n")

        def do_GET(self) -> None:  # noqa: N802
            self._redirect()

        def do_HEAD(self) -> None:  # noqa: N802
            self._redirect()

        def do_POST(self) -> None:  # noqa: N802
            self._redirect()

        def _redirect(self) -> None:
            host = (self.headers.get("Host") or f"127.0.0.1:{http_port}").strip()
            # Strip any existing port; browser Host may be "192.168.1.10" or "...:80"
            if host.startswith("["):
                # [::1]:port
                if "]:" in host:
                    host = host.split("]:", 1)[0] + "]"
            elif host.count(":") == 1:
                host = host.rsplit(":", 1)[0]
            target = f"https://{host}:{https_port}{self.path}"
            self.send_response(301)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()

    try:
        server = ThreadingHTTPServer((listen_host, http_port), Handler)
    except OSError as exc:
        sys.stderr.write(f"[http-redirect] bind {listen_host}:{http_port} failed: {exc}\n")
        return 1
    sys.stderr.write(
        f"[http-redirect] http://{listen_host}:{http_port} → https://<host>:{https_port}\n"
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
