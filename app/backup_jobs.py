"""Disaster Prep host-to-host backup jobs — stored on this controller.

Hayabusa Core proxies CRUD/run via RPC against the selected controller branch.
LAN users manage the same store through /api/backup-jobs.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any

_LOCK = threading.RLock()

_SCHEDULES = {
    "manual": None,
    "hourly": 3600,
    "daily": 86400,
    "weekly": 604800,
}

_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9._/+\-~]+$")


def _now() -> float:
    return time.time()


def _normalize_host(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        raw = {}
    ip = str(raw.get("ip") or raw.get("address") or "").strip()
    name = str(raw.get("name") or raw.get("hostname") or ip or "").strip()
    cidr = str(raw.get("cidr") or raw.get("network") or "").strip()
    return {"ip": ip, "name": name or ip, "cidr": cidr}


def _sanitize_paths(paths: Any) -> list[str]:
    out: list[str] = []
    if isinstance(paths, str):
        paths = [p.strip() for p in paths.replace(",", " ").split() if p.strip()]
    if not isinstance(paths, list):
        paths = ["/etc"]
    for p in paths:
        s = str(p or "").strip()
        if not s or ".." in s or not s.startswith("/"):
            continue
        if not _SAFE_PATH_RE.match(s):
            continue
        if s not in out:
            out.append(s)
        if len(out) >= 32:
            break
    return out or ["/etc"]


def build_inventory_yaml(*, source: dict[str, str], dest: dict[str, str]) -> str:
    src_ip = source.get("ip") or source.get("name") or "source"
    dst_ip = dest.get("ip") or dest.get("name") or "dest"
    src_name = re.sub(r"[^A-Za-z0-9_-]+", "-", (source.get("name") or "source"))[:48] or "source"
    dst_name = re.sub(r"[^A-Za-z0-9_-]+", "-", (dest.get("name") or "dest"))[:48] or "dest"
    return (
        "all:\n"
        "  children:\n"
        "    backup_source:\n"
        "      hosts:\n"
        f"        {src_name}:\n"
        f"          ansible_host: {src_ip}\n"
        "    backup_dest:\n"
        "      hosts:\n"
        f"        {dst_name}:\n"
        f"          ansible_host: {dst_ip}\n"
    )


def build_playbook_yaml(
    *,
    source: dict[str, str],
    dest: dict[str, str],
    paths: list[str],
    dest_path: str,
    job_name: str = "",
) -> str:
    dest_path = str(dest_path or "/var/backups/hayabusa").strip() or "/var/backups/hayabusa"
    if not dest_path.startswith("/") or ".." in dest_path:
        dest_path = "/var/backups/hayabusa"
    yaml_paths = "\n".join(f"      - {p}" for p in paths)
    argv_paths = "\n".join(f"          - {p}" for p in paths)
    label = str(job_name or "hayabusa-backup").replace('"', "")[:80]
    src_label = (source.get("name") or source.get("ip") or "source").replace('"', "")
    dst_label = (dest.get("name") or dest.get("ip") or "dest").replace('"', "")
    dest_ip = dest.get("ip") or dest.get("name") or ""
    return f"""---
# Hayabusa Disaster Prep — host-to-host backup
# Job: {label}
# Source: {src_label} → Destination: {dst_label}
- name: Archive and ship backup from source to destination
  hosts: backup_source
  gather_facts: true
  become: true
  vars:
    backup_paths:
{yaml_paths}
    backup_dest_host: "{dest_ip}"
    backup_dest_path: "{dest_path}"
  tasks:
    - name: Build archive name
      ansible.builtin.set_fact:
        backup_archive: "/tmp/hayabusa-backup-{{{{ inventory_hostname }}}}-{{{{ ansible_date_time.epoch | default(lookup('pipe', 'date +%s')) }}}}.tgz"

    - name: Create compressed archive on source
      ansible.builtin.command:
        argv:
          - tar
          - -czf
          - "{{{{ backup_archive }}}}"
{argv_paths}
      register: backup_tar
      changed_when: backup_tar.rc == 0

    - name: Ensure destination directory
      ansible.builtin.file:
        path: "{{{{ backup_dest_path }}}}"
        state: directory
        mode: "0750"
      delegate_to: "{{{{ backup_dest_host }}}}"

    - name: Fetch archive onto Hayabusa runner
      ansible.builtin.fetch:
        src: "{{{{ backup_archive }}}}"
        dest: "/tmp/hayabusa-backup-stage/"
        flat: true

    - name: Copy archive to destination host
      ansible.builtin.copy:
        src: "/tmp/hayabusa-backup-stage/{{{{ backup_archive | basename }}}}"
        dest: "{{{{ backup_dest_path }}}}/{{{{ backup_archive | basename }}}}"
        mode: "0640"
      delegate_to: "{{{{ backup_dest_host }}}}"

    - name: Remove temporary archive on source
      ansible.builtin.file:
        path: "{{{{ backup_archive }}}}"
        state: absent
"""


def _next_run(schedule: str, from_ts: float | None = None) -> float | None:
    gap = _SCHEDULES.get(str(schedule or "manual").strip().lower())
    if not gap:
        return None
    return float(from_ts or _now()) + float(gap)


def enqueue_payload(job: dict[str, Any]) -> dict[str, Any]:
    playbook_path = str(job.get("playbook_path") or "Ansible/playbooks/disaster-host-backup.yml")
    inventory_path = str(job.get("inventory_path") or "Ansible/inventory/disaster_backup_hosts.yml")
    playbook = str(job.get("playbook_yaml") or "")
    inventory = str(job.get("inventory_yaml") or "")
    label = str(job.get("name") or job.get("id") or "backup")
    return {
        "kind": "ansible-playbook",
        "args": ["-i", inventory_path, playbook_path],
        "workdir": "",
        "timeout_sec": 1800,
        "secret_keys": list(job.get("secret_keys") or []),
        "extra_files": [
            {"path": playbook_path, "content": playbook},
            {"path": inventory_path, "content": inventory},
        ],
        "metadata": {
            "hayabusa_backup_job_id": str(job.get("id") or ""),
            "hayabusa_backup_job_name": label,
            "source_ip": (job.get("source_host") or {}).get("ip"),
            "dest_ip": (job.get("dest_host") or {}).get("ip"),
        },
        "require_lan_approve": True,
        "source": "hayabusa-backup",
    }


class BackupJobsStore:
    def __init__(self, data_dir: Path) -> None:
        self._path = Path(data_dir) / "disaster_backup_jobs.json"
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def _empty(self) -> dict[str, Any]:
        return {"version": 1, "jobs": []}

    def _load(self) -> dict[str, Any]:
        try:
            if not self._path.is_file():
                return self._empty()
            with self._path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                return self._empty()
            if not isinstance(data.get("jobs"), list):
                data["jobs"] = []
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

    def list_jobs(self) -> list[dict[str, Any]]:
        with _LOCK:
            state = self._load()
            jobs = [deepcopy(j) for j in (state.get("jobs") or []) if isinstance(j, dict)]
        jobs.sort(key=lambda j: float(j.get("updated_at") or j.get("created_at") or 0), reverse=True)
        return jobs

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        jid = str(job_id or "").strip()
        with _LOCK:
            state = self._load()
            for j in state.get("jobs") or []:
                if isinstance(j, dict) and str(j.get("id") or "") == jid:
                    return deepcopy(j)
        return None

    def create_job(
        self,
        *,
        name: str = "",
        source: dict[str, Any] | None = None,
        dest: dict[str, Any] | None = None,
        paths: Any = None,
        dest_path: str = "/var/backups/hayabusa",
        schedule: str = "daily",
        enabled: bool = True,
        created_by: str = "",
        secret_keys: list[str] | None = None,
    ) -> dict[str, Any]:
        src = _normalize_host(source)
        dst = _normalize_host(dest)
        if not src.get("ip"):
            return {"ok": False, "error": "source host ip is required", "code": "bad_source"}
        if not dst.get("ip"):
            return {"ok": False, "error": "destination host ip is required", "code": "bad_dest"}
        if src["ip"] == dst["ip"]:
            return {"ok": False, "error": "source and destination must be different hosts", "code": "same_host"}
        sched = str(schedule or "daily").strip().lower()
        if sched not in _SCHEDULES:
            return {"ok": False, "error": f"unsupported schedule: {sched}", "code": "bad_schedule"}
        clean_paths = _sanitize_paths(paths)
        dest_path_n = str(dest_path or "/var/backups/hayabusa").strip() or "/var/backups/hayabusa"
        label = str(name or f"Backup {src.get('name') or src['ip']} → {dst.get('name') or dst['ip']}").strip()[:120]
        now = _now()
        playbook = build_playbook_yaml(
            source=src, dest=dst, paths=clean_paths, dest_path=dest_path_n, job_name=label
        )
        inventory = build_inventory_yaml(source=src, dest=dst)
        job = {
            "id": uuid.uuid4().hex[:16],
            "name": label,
            "source_host": src,
            "dest_host": dst,
            "paths": clean_paths,
            "dest_path": dest_path_n,
            "schedule": sched,
            "enabled": bool(enabled) and sched != "manual",
            "playbook_yaml": playbook,
            "inventory_yaml": inventory,
            "playbook_path": "Ansible/playbooks/disaster-host-backup.yml",
            "inventory_path": "Ansible/inventory/disaster_backup_hosts.yml",
            "secret_keys": [str(k).strip() for k in (secret_keys or []) if str(k).strip()][:20],
            "created_at": now,
            "updated_at": now,
            "created_by": str(created_by or "")[:120],
            "last_run_at": None,
            "next_run_at": _next_run(sched, now) if (enabled and sched != "manual") else None,
            "last_controller_job_id": None,
            "last_status": "scheduled" if sched != "manual" else "manual",
            "last_error": "",
            "run_history": [],
        }
        with _LOCK:
            state = self._load()
            state.setdefault("jobs", []).append(job)
            self._save(state)
        return {"ok": True, "job": deepcopy(job)}

    def update_job(self, job_id: str, **patch: Any) -> dict[str, Any]:
        jid = str(job_id or "").strip()
        with _LOCK:
            state = self._load()
            jobs = state.get("jobs") or []
            for i, j in enumerate(jobs):
                if not isinstance(j, dict) or str(j.get("id") or "") != jid:
                    continue
                job = dict(j)
                if "name" in patch and patch["name"] is not None:
                    job["name"] = str(patch["name"]).strip()[:120] or job["name"]
                if "enabled" in patch:
                    job["enabled"] = bool(patch["enabled"])
                if "schedule" in patch and patch["schedule"] is not None:
                    sched = str(patch["schedule"]).strip().lower()
                    if sched not in _SCHEDULES:
                        return {"ok": False, "error": f"unsupported schedule: {sched}", "code": "bad_schedule"}
                    job["schedule"] = sched
                    if sched == "manual":
                        job["enabled"] = False
                        job["next_run_at"] = None
                    elif job.get("enabled"):
                        job["next_run_at"] = _next_run(sched, _now())
                if "paths" in patch and patch["paths"] is not None:
                    job["paths"] = _sanitize_paths(patch["paths"])
                if "dest_path" in patch and patch["dest_path"] is not None:
                    dp = str(patch["dest_path"]).strip() or "/var/backups/hayabusa"
                    if dp.startswith("/") and ".." not in dp:
                        job["dest_path"] = dp
                job["playbook_yaml"] = build_playbook_yaml(
                    source=job.get("source_host") or {},
                    dest=job.get("dest_host") or {},
                    paths=list(job.get("paths") or ["/etc"]),
                    dest_path=str(job.get("dest_path") or "/var/backups/hayabusa"),
                    job_name=str(job.get("name") or ""),
                )
                job["inventory_yaml"] = build_inventory_yaml(
                    source=job.get("source_host") or {},
                    dest=job.get("dest_host") or {},
                )
                job["updated_at"] = _now()
                jobs[i] = job
                state["jobs"] = jobs
                self._save(state)
                return {"ok": True, "job": deepcopy(job)}
        return {"ok": False, "error": "job not found", "code": "not_found"}

    def delete_job(self, job_id: str) -> dict[str, Any]:
        jid = str(job_id or "").strip()
        with _LOCK:
            state = self._load()
            before = list(state.get("jobs") or [])
            jobs = [j for j in before if not (isinstance(j, dict) and str(j.get("id") or "") == jid)]
            if len(jobs) == len(before):
                return {"ok": False, "error": "job not found", "code": "not_found"}
            state["jobs"] = jobs
            self._save(state)
        return {"ok": True, "deleted": jid}

    def mark_enqueued(
        self,
        job_id: str,
        *,
        controller_job_id: str,
        status: str = "pending_approval",
        error: str = "",
    ) -> dict[str, Any]:
        jid = str(job_id or "").strip()
        with _LOCK:
            state = self._load()
            for i, j in enumerate(state.get("jobs") or []):
                if not isinstance(j, dict) or str(j.get("id") or "") != jid:
                    continue
                job = dict(j)
                now = _now()
                job["last_run_at"] = now
                job["last_controller_job_id"] = str(controller_job_id or "")[:80]
                job["last_status"] = str(status or "pending_approval")[:64]
                job["last_error"] = str(error or "")[:400]
                job["updated_at"] = now
                sched = str(job.get("schedule") or "manual")
                if job.get("enabled") and sched != "manual":
                    job["next_run_at"] = _next_run(sched, now)
                hist = list(job.get("run_history") or [])
                hist.insert(
                    0,
                    {
                        "at": now,
                        "controller_job_id": job["last_controller_job_id"],
                        "status": job["last_status"],
                        "error": job["last_error"],
                    },
                )
                job["run_history"] = hist[:25]
                state["jobs"][i] = job
                self._save(state)
                return {"ok": True, "job": deepcopy(job)}
        return {"ok": False, "error": "job not found", "code": "not_found"}

    def due_jobs(self, now: float | None = None) -> list[dict[str, Any]]:
        ts = float(now or _now())
        out = []
        with _LOCK:
            state = self._load()
            for j in state.get("jobs") or []:
                if not isinstance(j, dict) or not j.get("enabled"):
                    continue
                if str(j.get("schedule") or "") == "manual":
                    continue
                nxt = j.get("next_run_at")
                try:
                    nxt_f = float(nxt) if nxt is not None else 0.0
                except (TypeError, ValueError):
                    nxt_f = 0.0
                if nxt_f and nxt_f <= ts:
                    out.append(deepcopy(j))
        return out

    def run_via_queue(
        self,
        job_id: str,
        *,
        job_queue: Any,
        requested_by: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Enqueue playbook into pending_jobs for LAN approve → Hayabusa execute."""
        job = self.get_job(job_id)
        if not job:
            return {"ok": False, "error": "job not found", "code": "not_found"}
        if job_queue is None:
            return {"ok": False, "error": "job queue unavailable", "code": "no_queue"}
        payload = enqueue_payload(job)
        result = job_queue.submit(payload, requested_by=requested_by if isinstance(requested_by, dict) else {})
        if not isinstance(result, dict):
            result = {"ok": False, "error": "invalid queue response"}
        ctrl_id = str(result.get("job_id") or result.get("id") or "")
        if result.get("ok") or result.get("pending_approval") or result.get("status") == "pending_approval":
            result["ok"] = True
            self.mark_enqueued(
                job["id"],
                controller_job_id=ctrl_id,
                status=str(result.get("status") or "pending_approval"),
            )
        else:
            self.mark_enqueued(
                job["id"],
                controller_job_id="",
                status="enqueue_failed",
                error=str(result.get("error") or "enqueue failed")[:400],
            )
        result["backup_job_id"] = job["id"]
        refreshed = self.get_job(job["id"])
        if refreshed:
            result["job"] = refreshed
        return result

    def tick_via_queue(
        self,
        *,
        job_queue: Any,
        requested_by: dict[str, Any] | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        due = self.due_jobs()
        enqueued = []
        errors = []
        for job in due[: max(1, min(int(limit or 20), 40))]:
            result = self.run_via_queue(job["id"], job_queue=job_queue, requested_by=requested_by)
            ctrl_id = str(result.get("job_id") or result.get("id") or "")
            if result.get("ok") and ctrl_id:
                enqueued.append({"backup_job_id": job["id"], "controller_job_id": ctrl_id})
            else:
                errors.append(
                    {
                        "backup_job_id": job["id"],
                        "error": str(result.get("error") or "enqueue failed")[:400],
                    }
                )
        return {
            "ok": True,
            "due": len(due),
            "enqueued": enqueued,
            "errors": errors,
            "jobs": self.list_jobs(),
        }
