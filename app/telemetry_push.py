"""Push site telemetry to Hayabusa Core with controller/device labels.

Core hosts Prometheus/Influx/Grafana. Controllers stamp identity so Grafana
does not need per-device edits.

Labels always include:
  controller_branch, device_id (when known), job=hayabusa_controller
"""

from __future__ import annotations

import logging
import os
import time
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger("hayabusa-controller.telemetry_push")


def controller_branch_label() -> str:
    return (
        os.environ.get("CONTROLLER_DISPLAY_NAME")
        or os.environ.get("HAYABUSA_CONTROLLER_BRANCH")
        or os.environ.get("CONTROLLER_MESH_HOSTNAME")
        or "controller"
    ).strip()[:80] or "controller"


def _prom_escape(value: str) -> str:
    return (
        (value or "")
        .replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace('"', '\\"')
    )


def build_prometheus_text(
    *,
    metrics: list[dict[str, Any]],
    controller_branch: str | None = None,
    extra_labels: dict[str, str] | None = None,
) -> str:
    """Build Prometheus exposition text with controller labels injected."""
    branch = _prom_escape(controller_branch or controller_branch_label())
    base = {"controller_branch": branch, "job": "hayabusa_controller"}
    if extra_labels:
        for k, v in extra_labels.items():
            if k and v is not None:
                base[str(k)[:64]] = _prom_escape(str(v)[:128])
    lines: list[str] = []
    now_ms = int(time.time() * 1000)
    for row in metrics or []:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "").strip()
        if not name or not name.replace("_", "").isalnum():
            continue
        try:
            value = float(row.get("value"))
        except (TypeError, ValueError):
            continue
        labels = dict(base)
        device_id = str(row.get("device_id") or row.get("device") or "").strip()
        if device_id:
            labels["device_id"] = _prom_escape(device_id[:128])
        for lk, lv in (row.get("labels") or {}).items() if isinstance(row.get("labels"), dict) else []:
            if lk in ("controller_branch", "job"):
                continue
            labels[str(lk)[:64]] = _prom_escape(str(lv)[:128])
        label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        ts = row.get("timestamp_ms")
        try:
            ts_i = int(ts) if ts is not None else now_ms
        except (TypeError, ValueError):
            ts_i = now_ms
        lines.append(f"{name}{{{label_str}}} {value} {ts_i}")
    return "\n".join(lines) + ("\n" if lines else "")


def push_to_core_pushgateway(
    *,
    core_base_url: str,
    tenant: str,
    agent_token: str,
    body: str,
    job: str = "hayabusa_controller",
    timeout: float = 15.0,
) -> dict[str, Any]:
    """POST Prometheus text to Core agent pushgateway proxy."""
    base = (core_base_url or "").rstrip("/")
    tenant = (tenant or "").strip().strip("/")
    token = (agent_token or "").strip()
    if not base or not tenant or not token:
        return {
            "ok": False,
            "error": "core_base_url, tenant, and agent_token are required",
            "code": "telemetry_push_config",
        }
    if not body.strip():
        return {"ok": False, "error": "empty metrics body", "code": "empty_metrics"}
    # Path must include peregrine_tenant/{tenant} (Core observability contract).
    path = f"/api/observability/pushgateway/metrics/job/{job}/peregrine_tenant/{tenant}"
    url = f"{base}{path}"
    req = urllib.request.Request(
        url,
        data=body.encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "text/plain; version=0.0.4",
            "X-Hayabusa-Agent-Token": token,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = getattr(resp, "status", None) or resp.getcode()
            return {"ok": 200 <= int(code) < 300, "http_status": int(code), "url": url}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "error": f"http_{exc.code}", "detail": str(exc.reason)[:200], "url": url}
    except Exception as exc:  # noqa: BLE001
        logger.debug("telemetry push failed: %s", exc)
        return {"ok": False, "error": str(exc)[:200], "url": url}


def push_lan_iface_sample(
    *,
    core_base_url: str,
    tenant: str,
    agent_token: str,
    device_metrics: list[dict[str, Any]],
) -> dict[str, Any]:
    """Convenience: label + push a list of device metrics to Core."""
    text = build_prometheus_text(metrics=device_metrics)
    result = push_to_core_pushgateway(
        core_base_url=core_base_url,
        tenant=tenant,
        agent_token=agent_token,
        body=text,
    )
    result["controller_branch"] = controller_branch_label()
    result["metric_lines"] = text.count("\n") if text else 0
    return result
