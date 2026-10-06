"""Pending Hayabusa→controller jobs that require on-LAN approval.

Hayabusa Core runs Ansible/OpenTofu/SECops. After LAN Approve, this appliance
grants ``lan.relay`` so Core can reach LAN devices; vault values are hydrated
only inside the relay on this node and are never returned to Core.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger("hayabusa-controller.job_queue")

_LOCK = threading.RLock()
MAX_JOBS = 200
DEFAULT_TTL_SEC = 24 * 3600
HYDRATED_TTL_SEC = 15 * 60


def _now() -> float:
    return time.time()


class JobQueue:
    def __init__(
        self,
        data_dir: Path,
        *,
        hydrator: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        runner: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        local_executor: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> None:
        self._path = Path(data_dir) / "pending_jobs.json"
        # Prefer hydrator; runner kept as alias for older call sites/tests.
        self._hydrator = hydrator or runner
        self._local_executor = local_executor
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def set_runner(self, runner: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        self._hydrator = runner

    def set_hydrator(self, hydrator: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        self._hydrator = hydrator

    def set_local_executor(
        self, executor: Callable[[dict[str, Any]], dict[str, Any]] | None
    ) -> None:
        self._local_executor = executor

    def _empty(self) -> dict[str, Any]:
        return {"version": 1, "jobs": {}}

    def _load(self) -> dict[str, Any]:
        try:
            if not self._path.is_file():
                return self._empty()
            with self._path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict) or not isinstance(data.get("jobs"), dict):
                return self._empty()
            return data
        except (OSError, ValueError, TypeError):
            return self._empty()

    def _save(self, state: dict[str, Any]) -> None:
        tmp = self._path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, self._path)
        try:
            os.chmod(self._path, 0o600)
        except OSError:
            pass

    def _scrub_hydrated(self, job: dict[str, Any]) -> None:
        job.pop("hydrated", None)
        if isinstance(job.get("result"), dict):
            job["result"].pop("env", None)
            job["result"].pop("extra_files", None)

    def _public(
        self,
        job: dict[str, Any],
        *,
        include_result: bool = True,
        include_hydrated: bool = False,
    ) -> dict[str, Any]:
        out = {
            "id": job.get("id"),
            "status": job.get("status"),
            "created_at": job.get("created_at"),
            "updated_at": job.get("updated_at"),
            "expires_at": job.get("expires_at"),
            "kind": (job.get("params") or {}).get("kind"),
            "workdir": (job.get("params") or {}).get("workdir") or "",
            "args": (job.get("params") or {}).get("args") or [],
            "secret_keys": (job.get("params") or {}).get("secret_keys") or [],
            "source": job.get("source") or "hayabusa",
            "requested_by": job.get("requested_by") or {},
            "extra_file_paths": [
                str(f.get("path") or "")
                for f in ((job.get("params") or {}).get("extra_files") or [])
                if isinstance(f, dict) and f.get("path")
            ],
            "metadata": (
                (job.get("params") or {}).get("metadata")
                if isinstance((job.get("params") or {}).get("metadata"), dict)
                else {}
            ),
            "require_lan_approve": True,
            "executed_on": (
                str((job.get("result") or {}).get("executed_on") or "")
                or str((job.get("params") or {}).get("execute_on") or "hayabusa")
            ),
            "hayabusa_saw_secret_values": False,
            "lan_approved": bool(job.get("lan_approved") or job.get("approved_by")),
            "relay_ready": bool(
                (job.get("result") or {}).get("relay_ready")
                or str(job.get("status") or "") == "approved"
            ),
            # Playbook/text payloads use secret *names* as markers only — safe for Core.
            "params": {
                "kind": (job.get("params") or {}).get("kind"),
                "workdir": (job.get("params") or {}).get("workdir") or "",
                "args": (job.get("params") or {}).get("args") or [],
                "secret_keys": (job.get("params") or {}).get("secret_keys") or [],
                "timeout_sec": (job.get("params") or {}).get("timeout_sec") or 300,
                "execute_on": (job.get("params") or {}).get("execute_on") or "hayabusa",
                "extra_files": (job.get("params") or {}).get("extra_files") or [],
                "metadata": (
                    (job.get("params") or {}).get("metadata")
                    if isinstance((job.get("params") or {}).get("metadata"), dict)
                    else {}
                ),
            },
        }
        if job.get("approved_by"):
            out["approved_by"] = job.get("approved_by")
        if job.get("denied_by"):
            out["denied_by"] = job.get("denied_by")
        if job.get("deny_reason"):
            out["deny_reason"] = job.get("deny_reason")
        if job.get("hydrated_until"):
            out["hydrated_until"] = job.get("hydrated_until")
        if include_result and isinstance(job.get("result"), dict):
            result = dict(job["result"])
            result.pop("secrets", None)
            result.pop("secret_values", None)
            result.pop("env", None)
            if not include_hydrated:
                result.pop("extra_files", None)
            out["result"] = result
        if include_hydrated and isinstance(job.get("hydrated"), dict) and job.get("status") == "hydrated":
            out["hydrated"] = deepcopy(job["hydrated"])
            out["values_ephemeral"] = True
        if job.get("error"):
            out["error"] = job.get("error")
        return out

    def _expire_locked(self, state: dict[str, Any]) -> None:
        now = _now()
        jobs = state["jobs"]
        for jid, job in list(jobs.items()):
            if not isinstance(job, dict):
                jobs.pop(jid, None)
                continue
            exp = float(job.get("expires_at") or 0)
            if job.get("status") == "pending_approval" and exp and now > exp:
                job["status"] = "expired"
                job["updated_at"] = now
                job["error"] = "LAN approval window expired"
                self._scrub_hydrated(job)
            hu = float(job.get("hydrated_until") or job.get("relay_until") or 0)
            if job.get("status") in {"hydrated", "running", "approved"} and hu and now > hu:
                job["status"] = "expired"
                job["updated_at"] = now
                job["error"] = "LAN relay window expired — re-queue and approve again"
                self._scrub_hydrated(job)
        if len(jobs) > MAX_JOBS:
            ordered = sorted(
                jobs.items(),
                key=lambda kv: float((kv[1] or {}).get("updated_at") or 0),
            )
            for jid, _ in ordered[: max(0, len(jobs) - MAX_JOBS)]:
                jobs.pop(jid, None)

    def submit(self, params: dict[str, Any], *, requested_by: dict[str, Any] | None = None) -> dict[str, Any]:
        params = deepcopy(params) if isinstance(params, dict) else {}
        params.pop("secret_values", None)
        params.pop("secrets_map", None)
        if isinstance(params.get("secret_keys"), list):
            params["secret_keys"] = [
                str(x).strip()
                for x in params["secret_keys"][:50]
                if str(x).strip() and not isinstance(x, dict)
            ]
        extras = params.get("extra_files") or []
        clean_extras: list[dict[str, str]] = []
        if isinstance(extras, list):
            for item in extras[:40]:
                if not isinstance(item, dict):
                    continue
                path = str(item.get("path") or "").strip().lstrip("/")
                content = item.get("content")
                if not path or not isinstance(content, str):
                    continue
                if len(content.encode("utf-8", errors="replace")) > 1_500_000:
                    continue
                if ".." in path.split("/"):
                    continue
                clean_extras.append({"path": path, "content": content})
        params["extra_files"] = clean_extras

        jid = uuid.uuid4().hex
        now = _now()
        ttl = int(params.pop("approve_ttl_sec", None) or DEFAULT_TTL_SEC)
        ttl = max(60, min(ttl, 7 * 24 * 3600))
        job = {
            "id": jid,
            "status": "pending_approval",
            "created_at": now,
            "updated_at": now,
            "expires_at": now + ttl,
            "params": params,
            "requested_by": requested_by if isinstance(requested_by, dict) else {},
            "source": "hayabusa",
            "result": None,
            "hydrated": None,
            "hydrated_delivered": False,
        }
        with _LOCK:
            state = self._load()
            self._expire_locked(state)
            state["jobs"][jid] = job
            self._save(state)
        logger.info("job %s queued pending_approval kind=%s", jid, params.get("kind"))
        return {
            "ok": True,
            "pending_approval": True,
            "status": "pending_approval",
            "job_id": jid,
            "id": jid,
            "message": (
                "Job queued on the controller. An administrator on the LAN must "
                "approve it; Core then runs Ansible/OpenTofu/SECops while the "
                "controller lan.relay hydrates secret names toward the LAN."
            ),
            **self._public(job, include_result=False),
        }

    def get(self, job_id: str, *, include_hydrated: bool = False) -> dict[str, Any] | None:
        jid = str(job_id or "").strip()
        if not jid:
            return None
        with _LOCK:
            state = self._load()
            self._expire_locked(state)
            self._save(state)
            job = state["jobs"].get(jid)
            if not isinstance(job, dict):
                return None
            if include_hydrated and isinstance(job.get("hydrated"), dict):
                hydrated = job["hydrated"]
                result = job.get("result") if isinstance(job.get("result"), dict) else {}
                exec_started = bool(str(result.get("cmd") or "").strip())
                if job.get("status") == "hydrated":
                    package = deepcopy(hydrated)
                    job["status"] = "running"
                    job["hydrated_delivered"] = True
                    job["updated_at"] = _now()
                    state["jobs"][jid] = job
                    self._save(state)
                    out = self._public(job, include_hydrated=False)
                    out["hydrated"] = package
                    out["values_ephemeral"] = True
                    return out
                if job.get("status") == "running" and not exec_started:
                    # Claimed but Hayabusa never finished (worker timeout/crash) — allow retry.
                    package = deepcopy(hydrated)
                    job["updated_at"] = _now()
                    state["jobs"][jid] = job
                    self._save(state)
                    out = self._public(job, include_hydrated=False)
                    out["hydrated"] = package
                    out["values_ephemeral"] = True
                    out["retry"] = True
                    return out
            return self._public(job, include_hydrated=include_hydrated)

    def list_jobs(self, *, status: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        with _LOCK:
            state = self._load()
            self._expire_locked(state)
            self._save(state)
            rows = [j for j in state["jobs"].values() if isinstance(j, dict)]
        rows.sort(key=lambda j: float(j.get("created_at") or 0), reverse=True)
        want = (status or "").strip()
        wants = {s.strip() for s in want.split(",") if s.strip()} if want else set()
        out = []
        for job in rows:
            if wants and job.get("status") not in wants:
                continue
            out.append(self._public(job, include_hydrated=False))
            if len(out) >= max(1, min(limit, 100)):
                break
        return out

    def deny(self, job_id: str, *, denied_by: dict[str, Any] | None = None, reason: str = "") -> dict[str, Any]:
        jid = str(job_id or "").strip()
        with _LOCK:
            state = self._load()
            self._expire_locked(state)
            job = state["jobs"].get(jid)
            if not isinstance(job, dict):
                return {"ok": False, "error": "job not found", "code": "not_found"}
            if job.get("status") != "pending_approval":
                return {
                    "ok": False,
                    "error": f"job is {job.get('status')}, not pending_approval",
                    "code": "not_pending",
                    **self._public(job),
                }
            job["status"] = "denied"
            job["updated_at"] = _now()
            job["denied_by"] = denied_by if isinstance(denied_by, dict) else {}
            job["deny_reason"] = str(reason or "")[:400]
            job["error"] = "Denied on LAN"
            self._scrub_hydrated(job)
            self._save(state)
            return {"ok": True, **self._public(job)}

    def is_approved_for_relay(self, job_id: str) -> bool:
        """True when LAN Approve granted Core permission to use lan.relay for this job."""
        jid = str(job_id or "").strip()
        if not jid:
            return False
        with _LOCK:
            state = self._load()
            self._expire_locked(state)
            job = state["jobs"].get(jid)
            if not isinstance(job, dict):
                return False
            status = str(job.get("status") or "")
            if status in {"approved", "running", "hydrated"}:
                return True
            # Completed jobs may still finish in-flight relay briefly.
            if status in {"completed", "failed"} and job.get("lan_approved"):
                hu = float(job.get("relay_until") or job.get("hydrated_until") or 0)
                return bool(hu and _now() <= hu)
            return False

    def approve(self, job_id: str, *, approved_by: dict[str, Any] | None = None) -> dict[str, Any]:
        """LAN approve → grant Core lan.relay (IaC) or run ZTP locally on controller."""
        jid = str(job_id or "").strip()
        with _LOCK:
            state = self._load()
            self._expire_locked(state)
            job = state["jobs"].get(jid)
            if not isinstance(job, dict):
                return {"ok": False, "error": "job not found", "code": "not_found"}
            if job.get("status") != "pending_approval":
                return {
                    "ok": False,
                    "error": f"job is {job.get('status')}, not pending_approval",
                    "code": "not_pending",
                    **self._public(job),
                }
            if float(job.get("expires_at") or 0) and _now() > float(job["expires_at"]):
                job["status"] = "expired"
                job["updated_at"] = _now()
                job["error"] = "LAN approval window expired"
                self._save(state)
                return {"ok": False, "error": "expired", "code": "expired", **self._public(job)}
            job["status"] = "hydrating"
            job["updated_at"] = _now()
            job["approved_by"] = approved_by if isinstance(approved_by, dict) else {}
            params = deepcopy(job.get("params") or {})
            self._save(state)

        kind = str(params.get("kind") or "").strip().lower()
        # ZTP DHCP bind must run on the controller appliance (LAN UDP).
        if kind in {"ztp-dhcp-start", "ztp-dhcp-stop"}:
            if not self._hydrator:
                with _LOCK:
                    state = self._load()
                    job = state["jobs"].get(jid) or {}
                    job["status"] = "failed"
                    job["error"] = "job hydrator not configured"
                    job["updated_at"] = _now()
                    state["jobs"][jid] = job
                    self._save(state)
                return {"ok": False, "error": "job hydrator not configured", **self._public(job)}
            try:
                hydrated = self._hydrator(params)
            except Exception as exc:  # noqa: BLE001
                logger.warning("job %s ztp hydrate/exec failed: %s", jid, exc)
                hydrated = {"ok": False, "error": str(exc)[:400]}
            if not isinstance(hydrated, dict):
                hydrated = {"ok": False, "error": "invalid hydrate result"}
            ok = bool(hydrated.get("ok"))
            with _LOCK:
                state = self._load()
                job = state["jobs"].get(jid) or {"id": jid}
                job["status"] = "completed" if ok else "failed"
                job["updated_at"] = _now()
                job["lan_approved"] = True
                job["hydrated_delivered"] = True
                job["approved_by"] = (
                    approved_by if isinstance(approved_by, dict) else job.get("approved_by") or {}
                )
                if not ok:
                    job["error"] = str(hydrated.get("error") or "ztp failed")[:400]
                else:
                    job.pop("error", None)
                job["result"] = {
                    "ok": ok,
                    "kind": kind,
                    "executed_on": "controller",
                    "lan_approved": True,
                    "hayabusa_saw_secret_values": False,
                    "message": hydrated.get("message") or ("ZTP ok" if ok else "ZTP failed"),
                    "ztp_result": hydrated.get("ztp_result"),
                }
                self._scrub_hydrated(job)
                state["jobs"][jid] = job
                self._save(state)
                return {"ok": ok, **self._public(job, include_hydrated=False)}

        # Ansible / OpenTofu / SECops: approve only — Core runs tools; relay hydrates secrets.
        secret_keys = params.get("secret_keys") if isinstance(params.get("secret_keys"), list) else []
        clean_keys = []
        for item in secret_keys[:50]:
            if isinstance(item, dict):
                k = str(item.get("key") or item.get("name") or "").strip()
            else:
                k = str(item or "").strip()
            if k:
                clean_keys.append(k)
        with _LOCK:
            state = self._load()
            job = state["jobs"].get(jid) or {"id": jid}
            job["status"] = "approved"
            job["updated_at"] = _now()
            job["lan_approved"] = True
            job["relay_until"] = _now() + HYDRATED_TTL_SEC
            job["hydrated_until"] = job["relay_until"]
            job["approved_by"] = (
                approved_by if isinstance(approved_by, dict) else job.get("approved_by") or {}
            )
            job.pop("error", None)
            self._scrub_hydrated(job)
            job["result"] = {
                "ok": True,
                "kind": kind or str(params.get("kind") or ""),
                "workdir": params.get("workdir") or "",
                "args": params.get("args") or [],
                "secret_keys": clean_keys,
                "executed_on": "hayabusa",
                "lan_approved": True,
                "relay_ready": True,
                "hayabusa_saw_secret_values": False,
                "message": (
                    "LAN approved. Core runs Ansible/OpenTofu/SECops; "
                    "controller lan.relay hydrates secret names toward the LAN."
                ),
            }
            state["jobs"][jid] = job
            self._save(state)
            logger.info("job %s LAN approved for Core relay (kind=%s)", jid, kind or "?")
            return {"ok": True, **self._public(job, include_hydrated=False)}

    def complete(
        self,
        job_id: str,
        *,
        ok: bool,
        stdout: str = "",
        stderr: str = "",
        error: str = "",
        returncode: int | None = None,
        cmd: str = "",
        executed_on: str = "hayabusa",
    ) -> dict[str, Any]:
        """Report execution finished; wipe hydrated secrets from disk."""
        jid = str(job_id or "").strip()
        with _LOCK:
            state = self._load()
            self._expire_locked(state)
            job = state["jobs"].get(jid)
            if not isinstance(job, dict):
                return {"ok": False, "error": "job not found", "code": "not_found"}
            if job.get("status") not in {"hydrated", "hydrating", "running", "approved"}:
                return {
                    "ok": False,
                    "error": f"job is {job.get('status')}, not approved/running",
                    "code": "not_hydrated",
                    **self._public(job),
                }
            exec_on = str(executed_on or "hayabusa").strip().lower() or "hayabusa"
            job["status"] = "completed" if ok else "failed"
            job["updated_at"] = _now()
            job["hydrated_delivered"] = True
            job["result"] = {
                "ok": bool(ok),
                "stdout": str(stdout or "")[:80000],
                "stderr": str(stderr or "")[:80000],
                "error": str(error or "")[:400],
                "returncode": returncode,
                "cmd": str(cmd or "")[:500],
                "executed_on": exec_on,
                "lan_approved": True,
                # Core never receives vault values — only secret *names* via lan.relay.
                "hayabusa_saw_secret_values": False,
                "values_persisted_on_controller": False,
            }
            if not ok and error:
                job["error"] = str(error)[:400]
            self._scrub_hydrated(job)
            state["jobs"][jid] = job
            self._save(state)
            return {"ok": True, **self._public(job)}
