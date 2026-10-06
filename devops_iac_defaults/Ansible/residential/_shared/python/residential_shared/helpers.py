from __future__ import annotations

from typing import Any, Callable


def health_payload(
    *,
    device: str,
    reachable: bool,
    api_supported: bool = True,
    tested: bool = False,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "status": "ok" if reachable else "degraded",
        "reachable": reachable,
        "api_supported": api_supported,
        "tested": tested,
        "device": device,
    }
    if extra:
        out.update(extra)
    return out


def require_api_key_header(
    configured_key: str,
    provided: str | None,
    *,
    unauthorized: Callable[[str], Any],
) -> None:
    if configured_key and provided != configured_key:
        raise unauthorized("Invalid or missing X-API-Key header")
