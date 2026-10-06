"""Integrations bundle (webhooks, builder apps, automation jobs) on this controller.

Hayabusa Core dual-writes / pulls via ``integrations.bundle.get`` /
``integrations.bundle.put`` against the selected controller branch.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any

_LOCK = threading.RLock()
_OWNER_RE = re.compile(r"^[A-Za-z0-9._@+:-]{1,160}$")


def _safe_owner(raw: str) -> str:
    key = str(raw or "").strip() or "anonymous"
    if not _OWNER_RE.match(key):
        key = re.sub(r"[^A-Za-z0-9._@+:-]+", "_", key)[:160] or "anonymous"
    return key


def _empty_bundle() -> dict[str, Any]:
    return {
        "version": 1,
        "webhook_library": {"projects": {}},
        "platform_config": {"platforms": {}},
        "custom_apps": {"apps": {}},
        "automation_jobs": {"version": 1, "jobs": []},
        "updated_at": None,
    }


def _mask_url(url: str) -> str:
    u = str(url or "").strip()
    if not u:
        return ""
    if len(u) <= 24:
        return "***"
    return u[:16] + "…" + u[-6:]


class IntegrationsStore:
    def __init__(self, data_dir: str | Path) -> None:
        self._root = Path(data_dir) / "integrations"
        self._root.mkdir(parents=True, exist_ok=True)

    def _path(self, owner: str) -> Path:
        return self._root / f"{_safe_owner(owner)}.json"

    def get_bundle(self, owner: str) -> dict[str, Any]:
        path = self._path(owner)
        with _LOCK:
            if not path.is_file():
                return _empty_bundle()
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return _empty_bundle()
            if not isinstance(data, dict):
                return _empty_bundle()
            out = _empty_bundle()
            for key in ("webhook_library", "platform_config", "custom_apps", "automation_jobs"):
                if isinstance(data.get(key), dict):
                    out[key] = data[key]
            out["updated_at"] = data.get("updated_at")
            out["version"] = int(data.get("version") or 1)
            return out

    def put_bundle(self, owner: str, bundle: dict[str, Any] | None) -> dict[str, Any]:
        if not isinstance(bundle, dict):
            bundle = {}
        out = _empty_bundle()
        for key in ("webhook_library", "platform_config", "custom_apps", "automation_jobs"):
            section = bundle.get(key)
            if isinstance(section, dict):
                out[key] = section
        out["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        out["version"] = int(bundle.get("version") or 1)
        path = self._path(owner)
        tmp = path.with_suffix(".tmp")
        with _LOCK:
            self._root.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            os.replace(tmp, path)
        return out

    def public_summary(self, owner: str) -> dict[str, Any]:
        """LAN UI payload — webhook URLs masked, code truncated."""
        bundle = self.get_bundle(owner)
        lib = bundle.get("webhook_library") if isinstance(bundle.get("webhook_library"), dict) else {}
        projects_raw = lib.get("projects") if isinstance(lib.get("projects"), dict) else {}
        webhooks: list[dict[str, Any]] = []
        for pid, rec in projects_raw.items():
            if not isinstance(rec, dict):
                continue
            url = str(rec.get("webhookUrl") or rec.get("webhook_url") or "")
            webhooks.append(
                {
                    "id": pid,
                    "name": rec.get("name") or pid,
                    "platform": rec.get("platform") or "discord",
                    "status": rec.get("status") or "saved",
                    "webhook_url_masked": _mask_url(url),
                    "has_url": bool(url.strip()),
                }
            )
        webhooks.sort(key=lambda w: (str(w.get("platform") or ""), str(w.get("name") or "")))

        plats = bundle.get("platform_config") if isinstance(bundle.get("platform_config"), dict) else {}
        platforms_raw = plats.get("platforms") if isinstance(plats.get("platforms"), dict) else {}
        platforms: list[dict[str, Any]] = []
        for key, rec in platforms_raw.items():
            if not isinstance(rec, dict):
                continue
            url = str(rec.get("webhook_url") or "")
            platforms.append(
                {
                    "id": key,
                    "platform": key,
                    "status": rec.get("status") or "stopped",
                    "webhook_url_masked": _mask_url(url),
                    "has_url": bool(url.strip()),
                }
            )
        platforms.sort(key=lambda p: str(p.get("platform") or ""))

        apps_wrap = bundle.get("custom_apps") if isinstance(bundle.get("custom_apps"), dict) else {}
        apps_raw = apps_wrap.get("apps") if isinstance(apps_wrap.get("apps"), dict) else {}
        apps: list[dict[str, Any]] = []
        for aid, rec in apps_raw.items():
            if not isinstance(rec, dict):
                continue
            code = str(rec.get("code") or "")
            apps.append(
                {
                    "id": aid,
                    "name": rec.get("name") or aid,
                    "platform": rec.get("platform") or "discord",
                    "status": rec.get("status") or "stopped",
                    "code_approved": bool(rec.get("code_approved")),
                    "code_lines": code.count("\n") + (1 if code.strip() else 0),
                    "has_code": bool(code.strip()),
                }
            )
        apps.sort(key=lambda a: str(a.get("name") or ""))

        jobs_wrap = bundle.get("automation_jobs") if isinstance(bundle.get("automation_jobs"), dict) else {}
        jobs_raw = jobs_wrap.get("jobs") if isinstance(jobs_wrap.get("jobs"), list) else []
        jobs: list[dict[str, Any]] = []
        for job in jobs_raw:
            if not isinstance(job, dict):
                continue
            cmd = str(job.get("command") or "")
            jobs.append(
                {
                    "id": job.get("id"),
                    "name": job.get("name") or "Scheduled job",
                    "command_preview": (cmd[:120] + ("…" if len(cmd) > 120 else "")),
                    "interval_minutes": job.get("interval_minutes"),
                    "enabled": bool(job.get("enabled", True)),
                    "paused": bool(job.get("paused", False)),
                    "next_run": job.get("next_run"),
                    "last_status": job.get("last_status"),
                    "context": job.get("context") or "user",
                }
            )
        jobs.sort(key=lambda j: str(j.get("name") or ""))

        return {
            "owner": _safe_owner(owner),
            "updated_at": bundle.get("updated_at"),
            "counts": {
                "webhooks": len(webhooks),
                "platforms": len(platforms),
                "apps": len(apps),
                "automation_jobs": len(jobs),
            },
            "webhooks": webhooks,
            "platforms": platforms,
            "apps": apps,
            "automation_jobs": jobs,
        }

    def delete_item(self, owner: str, kind: str, item_id: str) -> bool:
        """Delete one webhook library project, builder app, or automation job."""
        kind = str(kind or "").strip().lower()
        item_id = str(item_id or "").strip()
        if not item_id:
            return False
        with _LOCK:
            bundle = self.get_bundle(owner)
            changed = False
            if kind in {"webhook", "webhooks", "library"}:
                lib = bundle.get("webhook_library") if isinstance(bundle.get("webhook_library"), dict) else {}
                projects = lib.get("projects") if isinstance(lib.get("projects"), dict) else {}
                if item_id in projects:
                    del projects[item_id]
                    lib["projects"] = projects
                    bundle["webhook_library"] = lib
                    changed = True
            elif kind in {"app", "apps", "builder"}:
                wrap = bundle.get("custom_apps") if isinstance(bundle.get("custom_apps"), dict) else {}
                apps = wrap.get("apps") if isinstance(wrap.get("apps"), dict) else {}
                if item_id in apps:
                    del apps[item_id]
                    wrap["apps"] = apps
                    bundle["custom_apps"] = wrap
                    changed = True
            elif kind in {"job", "jobs", "automation", "automation_jobs"}:
                wrap = bundle.get("automation_jobs") if isinstance(bundle.get("automation_jobs"), dict) else {}
                jobs = wrap.get("jobs") if isinstance(wrap.get("jobs"), list) else []
                new_jobs = [j for j in jobs if not (isinstance(j, dict) and str(j.get("id")) == item_id)]
                if len(new_jobs) != len(jobs):
                    wrap["jobs"] = new_jobs
                    bundle["automation_jobs"] = wrap
                    changed = True
            elif kind in {"platform", "platforms"}:
                plats = bundle.get("platform_config") if isinstance(bundle.get("platform_config"), dict) else {}
                platforms = plats.get("platforms") if isinstance(plats.get("platforms"), dict) else {}
                if item_id in platforms:
                    del platforms[item_id]
                    plats["platforms"] = platforms
                    bundle["platform_config"] = plats
                    changed = True
            if not changed:
                return False
            self.put_bundle(owner, bundle)
            return True
