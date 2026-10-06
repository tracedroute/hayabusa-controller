"""One-time first-boot setup for Hayabusa Controller.

Persists whether the administrator has finished the novice/advanced setup
wizard. Stored under ``$DATA_DIR/state/setup.json`` so it survives restarts
on the same volume and is empty on a freshly created container.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

_LOCK = threading.RLock()

MODES = frozenset({"novice", "advanced", ""})


def _now() -> float:
    return time.time()


class SetupStore:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / "state" / "setup.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _empty(self) -> dict[str, Any]:
        return {
            "version": 1,
            "completed": False,
            "completed_at": 0,
            "completed_by": "",
            "mode": "",
            "updated_at": 0,
            "legacy_skipped": False,
        }

    def _force_setup(self) -> bool:
        return (os.environ.get("CONTROLLER_FORCE_SETUP") or "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

    def _legacy_already_provisioned(self) -> bool:
        """Volumes created before the wizard already have users / GitOps — do not force re-run."""
        if self._force_setup():
            return False
        # RbacStore persists at $DATA_DIR/rbac.json (not under state/).
        rbac_path = self.data_dir / "rbac.json"
        if rbac_path.is_file():
            try:
                raw = json.loads(rbac_path.read_text(encoding="utf-8"))
                users = (raw or {}).get("users") if isinstance(raw, dict) else None
                if isinstance(users, dict) and users:
                    return True
            except (OSError, json.JSONDecodeError, UnicodeDecodeError, TypeError):
                pass
        gitops_path = self.data_dir / "state" / "gitops.json"
        if gitops_path.is_file():
            try:
                raw = json.loads(gitops_path.read_text(encoding="utf-8"))
                if isinstance(raw, dict) and (raw.get("enabled") or raw.get("repo")):
                    return True
            except (OSError, json.JSONDecodeError, UnicodeDecodeError, TypeError):
                pass
        return False

    def _load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return self._empty()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return self._empty()
        if not isinstance(raw, dict):
            return self._empty()
        out = self._empty()
        out.update({k: raw.get(k, out[k]) for k in out.keys()})
        out["completed"] = bool(out.get("completed"))
        out["legacy_skipped"] = bool(out.get("legacy_skipped"))
        mode = str(out.get("mode") or "").strip().lower()
        out["mode"] = mode if mode in {"novice", "advanced"} else ""
        return out

    def _save(self, data: dict[str, Any]) -> None:
        data = dict(data)
        data["updated_at"] = _now()
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)

    def get(self) -> dict[str, Any]:
        with _LOCK:
            data = self._load()
            if data.get("completed"):
                return data
            if not self.path.is_file() and self._legacy_already_provisioned():
                data["completed"] = True
                data["mode"] = data.get("mode") or "novice"
                data["legacy_skipped"] = True
                data["completed_at"] = data.get("completed_at") or _now()
                data["completed_by"] = data.get("completed_by") or "legacy"
                try:
                    self._save(data)
                except OSError:
                    pass
            return data

    def completed(self) -> bool:
        return bool(self.get().get("completed"))

    def public_status(self) -> dict[str, Any]:
        cfg = self.get()
        done = bool(cfg.get("completed"))
        return {
            "ok": True,
            "completed": done,
            "mode": str(cfg.get("mode") or ""),
            "completed_at": cfg.get("completed_at") or 0,
            "completed_by": str(cfg.get("completed_by") or ""),
            "needs_setup": not done,
        }

    def mark_complete(self, *, mode: str, completed_by: str = "") -> dict[str, Any]:
        mode_n = str(mode or "").strip().lower()
        if mode_n not in {"novice", "advanced"}:
            return {"ok": False, "error": "mode must be novice or advanced", "code": "invalid_mode"}
        with _LOCK:
            data = self._load()
            data["completed"] = True
            data["mode"] = mode_n
            data["completed_at"] = _now()
            data["completed_by"] = str(completed_by or "")[:128]
            data["legacy_skipped"] = False
            data.pop("reset_at", None)
            data.pop("reset_by", None)
            self._save(data)
            return {"ok": True, **self.public_status()}

    def reset(self, *, reset_by: str = "") -> dict[str, Any]:
        """Clear completion so an admin can re-run the first-run wizard."""
        with _LOCK:
            data = self._load()
            prev_mode = str(data.get("mode") or "")
            data["completed"] = False
            data["completed_at"] = 0
            data["completed_by"] = ""
            data["mode"] = ""
            data["legacy_skipped"] = False
            data["reset_at"] = _now()
            data["reset_by"] = str(reset_by or "")[:128]
            data["previous_mode"] = prev_mode if prev_mode in {"novice", "advanced"} else ""
            self._save(data)
            out = self.public_status()
            out["reset"] = True
            out["previous_mode"] = data.get("previous_mode") or ""
            return {"ok": True, **out}
