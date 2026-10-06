"""Handle Hayabusa → controller RPC (secrets catalog, IaC, jobs).

Secret *values* are not listed via ``secrets.get``. Hayabusa may submit
``job.run`` with secret *names*; after LAN approval this node hydrates an
ephemeral package and runs Ansible/OpenTofu here so vault values never leave this appliance.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable

from .secrets_vault import SecretsVault, is_reserved_secret_key
from . import lan_discover
from .lan_relay import LanRelay

logger = logging.getLogger("hayabusa-controller.bridge_rpc")

SECRET_NAME_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
SAFE_JOB_KINDS = {"ansible-playbook", "tofu", "terraform", "ztp", "ztp-dhcp-start", "ztp-dhcp-stop"}
ZTP_JOB_KINDS = frozenset({"ztp", "ztp-dhcp-start", "ztp-dhcp-stop"})
# Playbook / args placeholders resolved only on this controller.
# Prefer {{ hayabusa_secret:KEY }} or <<SECRET:KEY>> (Core recognizes those names).
# lookup('env','HAYABUSA_SECRET_…') remains for legacy playbooks only.
SECRET_PLACEHOLDER_RE = re.compile(
    r"(?:\{\{\s*hayabusa_secret:([A-Za-z0-9._:-]+)\s*\}\}"
    r"|<<\s*SECRET:([A-Za-z0-9._:-]+)\s*>>"
    r"|lookup\(\s*['\"]env['\"]\s*,\s*['\"]HAYABUSA_SECRET_([A-Za-z0-9_]+)['\"]\s*\))"
)
# High-confidence plaintext that must never leave this appliance toward Core.
# Values that are already hayabusa_secret / SECRET / env-lookup placeholders are ignored.
_PLAINTEXT_SECRET_ASSIGN_RE = re.compile(
    r"(?im)^[ \t]*(?:[-*][ \t]+)?(?P<key>password|passwd|secret|secret_key|api_key|api_token|"
    r"access_key|access_key_id|secret_access_key|private_key|auth_token|token|"
    r"client_secret|db_password|mysql_password|postgres_password|"
    r"aws_secret_access_key|aws_access_key_id)\s*[:=]\s*(?P<q>['\"]?)(?P<val>[^\s#'\"][^#\n]*?)(?P=q)\s*$"
)
_PLAINTEXT_TF_SECRET_RE = re.compile(
    r"(?im)\b(?P<key>password|secret|secret_key|api_key|token|access_key|"
    r"secret_access_key|private_key|client_secret)\s*=\s*(?P<q>[\"'])(?P<val>(?:(?!\2).){6,}?)\2"
)
_PLACEHOLDER_VALUE_RE = re.compile(
    r"(?i)(\{\{\s*hayabusa_secret:|<<\s*SECRET:|lookup\s*\(\s*['\"]env['\"]|"
    r"\$\{|var\.|aws_ssm|data\.|environ|HAYABUSA_SECRET_)"
)
# Image Nest refs (ISO / WIM / qcow2 paths) — resolved at LAN approve like secrets.
IMAGE_NEST_PLACEHOLDER_RE = re.compile(
    r"(?:\{\{\s*hayabusa_image:([A-Za-z0-9._-]+)(?::([A-Za-z0-9._-]+))?\s*\}\}"
    r"|<<\s*IMAGE_NEST:([A-Za-z0-9._-]+)(?::([A-Za-z0-9._-]+))?\s*>>"
    r"|lookup\(\s*['\"]env['\"]\s*,\s*['\"]HAYABUSA_IMAGE_NEST_([A-Za-z0-9_]+)['\"]\s*\))"
)
IMAGE_NEST_REF_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
IMAGE_NEST_ENV_DEFAULT_FIELD = "source_image"


class BridgeRpcHandler:
    def __init__(
        self,
        *,
        vault: SecretsVault,
        devops_root: Path,
        list_tree: Callable[[str], list[dict[str, Any]]] | None = None,
        read_file: Callable[[str], str] | None = None,
        import_sync: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        inventory_summary: Callable[[], dict[str, Any]] | None = None,
        ztp_status: Callable[[], dict[str, Any]] | None = None,
        ztp_edge: Any | None = None,
        job_queue: Any | None = None,
        rbac: Any | None = None,
        image_nest: Any | None = None,
        gitops: Any | None = None,
        backup_jobs: Any | None = None,
        gameplan: Any | None = None,
        integrations: Any | None = None,
    ) -> None:
        self.vault = vault
        self.devops_root = Path(devops_root)
        self._list_tree = list_tree
        self._read_file = read_file
        self._import_sync = import_sync
        self._inventory_summary = inventory_summary
        self._ztp_edge = ztp_edge
        self._ztp_status = ztp_status
        self._job_queue = job_queue
        self._rbac = rbac
        self._image_nest = image_nest
        self._gitops = gitops
        self._backup_jobs = backup_jobs
        self._gameplan = gameplan
        self._integrations = integrations
        self._lan_relay = LanRelay(
            vault_get=lambda key: self.vault.get(str(key or "").strip()),
            job_approved=lambda jid: bool(
                self._job_queue is not None and self._job_queue.is_approved_for_relay(jid)
            ),
        )

    def set_job_queue(self, job_queue: Any | None) -> None:
        self._job_queue = job_queue

    def set_rbac(self, rbac: Any | None) -> None:
        self._rbac = rbac

    def set_backup_jobs(self, backup_jobs: Any | None) -> None:
        self._backup_jobs = backup_jobs

    def set_gameplan(self, gameplan: Any | None) -> None:
        self._gameplan = gameplan

    def set_integrations(self, integrations: Any | None) -> None:
        self._integrations = integrations

    def set_image_nest(self, image_nest: Any | None) -> None:
        self._image_nest = image_nest

    def set_gitops(self, gitops: Any | None) -> None:
        self._gitops = gitops

    async def handle(self, method: str, params: dict[str, Any] | None) -> dict[str, Any]:
        params = params if isinstance(params, dict) else {}
        method = (method or "").strip()
        try:
            if method == "secrets.list":
                return self._secrets_list()
            if method == "secrets.get":
                # Hard rule: do not exfiltrate vault values via secrets.get.
                # After LAN approve, job.status(include_hydrated=True) returns an
                # ephemeral hydrated package for Hayabusa execution, then job.complete wipes it.
                return {
                    "ok": False,
                    "error": (
                        "Secret values are not returned via secrets.get. "
                        "Pass secret key names to job.run; after LAN approve Core runs tools "
                        "and lan.relay hydrates secret names on this controller."
                    ),
                    "code": "secrets_stay_on_controller",
                    "values_included": False,
                }
            if method == "guacamole.ssh_credentials":
                # Guacamole needs the SSH username/password to build working SSH connections.
                # This endpoint returns the requested secret *values* only for the narrow
                # Guacamole provisioning flow.
                return self._guacamole_ssh_credentials(params)
            if method == "secrets.resolve_ephemeral":
                # Hayabusa AI (and similar) resolve named vault secrets for one outbound call.
                # Values must not be persisted on Hayabusa.
                return self._secrets_resolve_ephemeral(params)
            if method == "gitops.credentials":
                # Ephemeral PAT/webhook secret for Hayabusa git pull — not persisted on Hayabusa.
                return await asyncio.to_thread(self._gitops_credentials, params)
            if method == "gitops.status":
                return await asyncio.to_thread(self._gitops_status, params)
            if method == "iac.list":
                return self._iac_list(params)
            if method == "iac.read":
                return self._iac_read(params)
            if method == "iac.export_owned":
                return await asyncio.to_thread(self._iac_export_owned, params)
            if method == "iac.import_sync":
                return await asyncio.to_thread(self._iac_import_sync, params)
            if method == "iac.inventory_summary":
                return await asyncio.to_thread(self._iac_inventory_summary, params)
            if method == "iac.state_snapshot":
                return await asyncio.to_thread(self._iac_state_snapshot, params)
            if method == "gameplan.list":
                return await asyncio.to_thread(self._gameplan_list, params)
            if method == "gameplan.get":
                return await asyncio.to_thread(self._gameplan_get, params)
            if method == "gameplan.save":
                return await asyncio.to_thread(self._gameplan_save, params)
            if method == "gameplan.delete":
                return await asyncio.to_thread(self._gameplan_delete, params)
            if method == "integrations.bundle.get":
                return await asyncio.to_thread(self._integrations_bundle_get, params)
            if method == "integrations.bundle.put":
                return await asyncio.to_thread(self._integrations_bundle_put, params)
            if method == "telemetry.push":
                return await asyncio.to_thread(self._telemetry_push, params)
            if method == "job.run":
                return await asyncio.to_thread(self._job_run_or_queue, params)
            if method == "job.status":
                return await asyncio.to_thread(self._job_status, params)
            if method == "job.approve":
                return await asyncio.to_thread(self._job_approve, params)
            if method == "job.complete":
                return await asyncio.to_thread(self._job_complete, params)
            if method == "job.list":
                return await asyncio.to_thread(self._job_list, params)
            if method == "backup.jobs.list":
                return await asyncio.to_thread(self._backup_jobs_list, params)
            if method == "backup.jobs.get":
                return await asyncio.to_thread(self._backup_jobs_get, params)
            if method == "backup.jobs.create":
                return await asyncio.to_thread(self._backup_jobs_create, params)
            if method == "backup.jobs.update":
                return await asyncio.to_thread(self._backup_jobs_update, params)
            if method == "backup.jobs.delete":
                return await asyncio.to_thread(self._backup_jobs_delete, params)
            if method == "backup.jobs.run":
                return await asyncio.to_thread(self._backup_jobs_run, params)
            if method == "backup.jobs.tick":
                return await asyncio.to_thread(self._backup_jobs_tick, params)
            if method.startswith("edge."):
                return await asyncio.to_thread(self._edge_radio_dispatch, method, params)
            if method == "lan.inventory":
                probe = str(params.get("probe") if params.get("probe") is not None else "1").lower() not in (
                    "0",
                    "false",
                    "no",
                    "off",
                )
                return await asyncio.to_thread(lan_discover.build_inventory, probe=probe)
            if method == "lan.topology":
                return await asyncio.to_thread(lan_discover.build_topology)
            if method == "lan.telemetry":
                return await asyncio.to_thread(lan_discover.build_telemetry)
            if method == "lan.relay.open":
                return await asyncio.to_thread(self._lan_relay.open_session, params)
            if method == "lan.relay.exec":
                return await asyncio.to_thread(self._lan_relay.exec_command, params)
            if method == "lan.relay.put":
                return await asyncio.to_thread(self._lan_relay.put_file, params)
            if method == "lan.relay.close":
                return await asyncio.to_thread(self._lan_relay.close_session, params)
            if method == "lan.relay.ping":
                return await asyncio.to_thread(self._lan_relay.ping, params)
            if method == "ztp.status":
                if self._ztp_edge is not None:
                    return await asyncio.to_thread(self._ztp_edge.status)
                if not self._ztp_status:
                    return {"ok": False, "error": "ztp edge not configured"}
                return await asyncio.to_thread(self._ztp_status)
            if method == "ztp.config.get":
                if self._ztp_edge is None:
                    return {"ok": False, "error": "ztp edge not configured"}
                cfg = self._ztp_edge.load_config()
                return {"ok": True, "config": cfg}
            if method == "ztp.config.put":
                if self._ztp_edge is None:
                    return {"ok": False, "error": "ztp edge not configured"}
                cfg = params.get("config")
                if not isinstance(cfg, dict):
                    return {"ok": False, "error": "config object required"}
                saved = self._ztp_edge.save_config(cfg)
                return {"ok": True, "config": saved}
            if method == "ztp.start":
                if self._ztp_edge is None:
                    return {"ok": False, "error": "ztp edge not configured"}
                if self._job_queue is not None:
                    return await asyncio.to_thread(
                        self._job_run_or_queue,
                        {"kind": "ztp-dhcp-start", "workdir": "", "args": [], "secret_keys": []},
                    )
                return await asyncio.to_thread(self._ztp_edge.start)
            if method == "ztp.stop":
                if self._ztp_edge is None:
                    return {"ok": False, "error": "ztp edge not configured"}
                if self._job_queue is not None:
                    return await asyncio.to_thread(
                        self._job_run_or_queue,
                        {"kind": "ztp-dhcp-stop", "workdir": "", "args": [], "secret_keys": []},
                    )
                return await asyncio.to_thread(self._ztp_edge.stop)
            if method == "ztp.leases":
                if self._ztp_edge is None:
                    return {"ok": False, "error": "ztp edge not configured"}
                leases = self._ztp_edge.leases()
                return {"ok": True, "leases": leases, "count": len(leases)}
            if method == "ztp.dhcp_events":
                if self._ztp_edge is None:
                    return {"ok": False, "error": "ztp edge not configured"}
                limit = int(params.get("limit") or 80)
                events = self._ztp_edge.dhcp_events(limit=limit)
                return {"ok": True, "events": events, "requests": events, "count": len(events)}
            if method == "ztp.seeking":
                if self._ztp_edge is None:
                    return {"ok": False, "error": "ztp edge not configured"}
                records = self._ztp_edge.seeking_records()
                return {"ok": True, "records": records, "count": len(records)}
            if method == "ztp.recipes":
                return await asyncio.to_thread(self._ztp_recipes)
            if method == "ztp.interfaces":
                return await asyncio.to_thread(self._ztp_interfaces)
            if method == "ping":
                return {"ok": True, "pong": True}
            return {"ok": False, "error": f"unknown method: {method}"}
        except Exception as exc:  # noqa: BLE001
            logger.warning("rpc %s failed: %s", method, exc)
            return {"ok": False, "error": str(exc)[:400]}

    def _gitops_credentials(self, params: dict[str, Any]) -> dict[str, Any]:
        """Return ephemeral git auth for a single Hayabusa pull (values not listed elsewhere)."""
        gitops = self._gitops
        if gitops is None:
            return {"ok": False, "error": "gitops unavailable", "code": "gitops_unavailable"}
        cfg = gitops.get()
        if not cfg.get("enabled"):
            return {"ok": False, "error": "gitops disabled", "code": "gitops_disabled"}
        auth_key = str(cfg.get("auth_secret_key") or "").strip()
        webhook_key = str(cfg.get("webhook_secret_key") or "").strip()
        want = str(params.get("kind") or "auth").strip().lower()
        out: dict[str, Any] = {
            "ok": True,
            "enabled": True,
            "provider": str(cfg.get("provider") or ""),
            "base_url": str(cfg.get("base_url") or ""),
            "repo": str(cfg.get("repo") or ""),
            "ref": str(cfg.get("ref") or "main"),
            "path_prefix": str(cfg.get("path_prefix") or ""),
            "ztp_repo": str(cfg.get("ztp_repo") or ""),
            "ztp_ref": str(cfg.get("ztp_ref") or cfg.get("ref") or "main"),
            "ztp_path_prefix": str(cfg.get("ztp_path_prefix") or ""),
            "clone_url": gitops.clone_https_url(kind="iac"),
            "ztp_clone_url": gitops.clone_https_url(kind="ztp"),
            "allowed_host": str((gitops.bridge_config_payload() or {}).get("allowed_host") or ""),
            "values_ephemeral": True,
            "ttl_hint_sec": 120,
        }
        if want in {"auth", "both", "all", ""}:
            if not auth_key:
                return {"ok": False, "error": "auth_secret_key not configured", "code": "missing_auth"}
            token = self.vault.get(auth_key)
            if token is None:
                return {"ok": False, "error": f"vault secret missing: {auth_key}", "code": "secret_missing"}
            out["auth_token"] = token
            out["auth_secret_key"] = auth_key
        if want in {"webhook", "both", "all"}:
            if not webhook_key:
                return {"ok": False, "error": "webhook_secret_key not configured", "code": "missing_webhook"}
            wh = self.vault.get(webhook_key)
            if wh is None:
                return {"ok": False, "error": f"vault secret missing: {webhook_key}", "code": "secret_missing"}
            out["webhook_secret"] = wh
            out["webhook_secret_key"] = webhook_key
        return out

    def _gitops_status(self, params: dict[str, Any]) -> dict[str, Any]:
        gitops = self._gitops
        if gitops is None:
            return {"ok": False, "error": "gitops unavailable"}
        pub = gitops.public_config()
        # Optional: Hayabusa can report remote status via params for controller to persist.
        if params.get("report"):
            gitops.record_sync(
                ok=bool(params.get("ok")),
                sha=str(params.get("sha") or ""),
                error=str(params.get("error") or ""),
                source=str(params.get("source") or "hayabusa"),
            )
            pub = gitops.public_config()
        return {"ok": True, **{k: v for k, v in pub.items() if k != "ok"}}

    def _ztp_interfaces(self) -> dict[str, Any]:
        """LAN NICs on the controller appliance (for ZTP DHCP bind)."""
        addrs = lan_discover.collect_addresses()
        by_name: dict[str, list[str]] = {}
        for row in addrs:
            if not isinstance(row, dict):
                continue
            name = str(row.get("ifname") or row.get("dev") or row.get("name") or "").strip()
            if not name or name == "lo":
                continue
            ip = str(row.get("ip") or row.get("local") or row.get("address") or "").strip()
            by_name.setdefault(name, [])
            if ip and ip not in by_name[name]:
                by_name[name].append(ip)
        for row in lan_discover.collect_iface_telemetry():
            if not isinstance(row, dict):
                continue
            name = str(row.get("iface") or row.get("ifname") or row.get("dev") or row.get("name") or "").strip()
            if not name or name == "lo" or name.startswith("docker") or name.startswith("br-") or name.startswith("veth"):
                continue
            by_name.setdefault(name, [])
        interfaces = [{"name": n, "addrs": by_name[n]} for n in sorted(by_name.keys())]
        return {"ok": True, "interfaces": interfaces}

    def _ztp_recipes(self) -> dict[str, Any]:
        """List vendor ZTP + bare-metal recipes from the active source (controller vs GitOps)."""
        source = "controller"
        gitops = self._gitops
        if gitops is not None and gitops.enabled() and str((gitops.get() or {}).get("ztp_repo") or "").strip():
            source = "gitops"
        recipes: dict[str, Any] = {
            "ok": True,
            "source": source,
            "vendor_ztp": [],
            "bare_metal": [],
        }
        if self._ztp_edge is None:
            recipes["error"] = "ztp edge not configured"
            return recipes
        listed = self._ztp_edge.list_recipes()
        if isinstance(listed, dict):
            recipes.update(listed)
        recipes["ok"] = True
        recipes["source"] = source
        return recipes

    def _auto_approve_allowed(self) -> bool:
        # Lab/tests only — production mesh jobs always need LAN approval.
        return (os.environ.get("CONTROLLER_JOB_AUTO_APPROVE") or "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

    def _job_run_or_queue(self, params: dict[str, Any]) -> dict[str, Any]:
        """Queue Hayabusa jobs for LAN approve → Core execute via lan.relay.

        Core sends secret *names* only. Vault values stay on this appliance and
        are applied only inside lan.relay after approve.
        """
        params = dict(params) if isinstance(params, dict) else {}
        params.pop("secret_values", None)
        kind = str(params.get("kind") or "").strip().lower()
        if kind in {"ansible", "opentofu", "tf"}:
            kind = {"ansible": "ansible-playbook", "opentofu": "tofu", "tf": "terraform"}.get(kind, kind)
            params["kind"] = kind
        if kind not in SAFE_JOB_KINDS and kind not in {"ansible-playbook", "tofu", "terraform", "ztp"}:
            return {"ok": False, "error": "unsupported kind", "kind": kind}
        # IaC/SECops: Core runs the binaries; controller only approves + relays.
        if kind in {"ansible-playbook", "tofu", "terraform", "ansible", "opentofu"}:
            params["execute_on"] = "hayabusa"
        if self._job_queue is None:
            return {"ok": False, "error": "job queue not configured"}
        requested_by = params.pop("requested_by", None)
        if not isinstance(requested_by, dict):
            requested_by = {}
        out = self._job_queue.submit(params, requested_by=requested_by)
        if self._auto_approve_allowed() and out.get("job_id"):
            return self._job_queue.approve(
                str(out["job_id"]),
                approved_by={"username": "auto", "provider": "CONTROLLER_JOB_AUTO_APPROVE"},
            )
        return out

    def _backup_jobs_list(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._backup_jobs is None:
            return {"ok": False, "error": "backup jobs unavailable", "code": "unavailable"}
        jobs = self._backup_jobs.list_jobs()
        return {"ok": True, "jobs": jobs, "count": len(jobs)}

    def _backup_jobs_get(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._backup_jobs is None:
            return {"ok": False, "error": "backup jobs unavailable", "code": "unavailable"}
        job = self._backup_jobs.get_job(str(params.get("job_id") or params.get("id") or ""))
        if not job:
            return {"ok": False, "error": "job not found", "code": "not_found"}
        return {"ok": True, "job": job}

    def _backup_jobs_create(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._backup_jobs is None:
            return {"ok": False, "error": "backup jobs unavailable", "code": "unavailable"}
        return self._backup_jobs.create_job(
            name=str(params.get("name") or ""),
            source=params.get("source_host") or params.get("source") or {},
            dest=params.get("dest_host") or params.get("dest") or {},
            paths=params.get("paths"),
            dest_path=str(params.get("dest_path") or "/var/backups/hayabusa"),
            schedule=str(params.get("schedule") or "daily"),
            enabled=bool(params.get("enabled", True)),
            created_by=str(params.get("created_by") or "")[:120],
            secret_keys=params.get("secret_keys") or [],
        )

    def _backup_jobs_update(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._backup_jobs is None:
            return {"ok": False, "error": "backup jobs unavailable", "code": "unavailable"}
        jid = str(params.get("job_id") or params.get("id") or "").strip()
        patch = params.get("patch") if isinstance(params.get("patch"), dict) else {}
        if not patch:
            patch = {
                k: params[k]
                for k in ("name", "enabled", "schedule", "paths", "dest_path")
                if k in params
            }
        return self._backup_jobs.update_job(jid, **patch)

    def _backup_jobs_delete(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._backup_jobs is None:
            return {"ok": False, "error": "backup jobs unavailable", "code": "unavailable"}
        return self._backup_jobs.delete_job(str(params.get("job_id") or params.get("id") or ""))

    def _backup_jobs_run(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._backup_jobs is None:
            return {"ok": False, "error": "backup jobs unavailable", "code": "unavailable"}
        requested_by = params.get("requested_by") if isinstance(params.get("requested_by"), dict) else {}
        return self._backup_jobs.run_via_queue(
            str(params.get("job_id") or params.get("id") or ""),
            job_queue=self._job_queue,
            requested_by=requested_by,
        )

    def _backup_jobs_tick(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._backup_jobs is None:
            return {"ok": False, "error": "backup jobs unavailable", "code": "unavailable"}
        requested_by = params.get("requested_by") if isinstance(params.get("requested_by"), dict) else {}
        try:
            limit = int(params.get("limit") or 20)
        except (TypeError, ValueError):
            limit = 20
        return self._backup_jobs.tick_via_queue(
            job_queue=self._job_queue,
            requested_by=requested_by,
            limit=limit,
        )

    def _edge_radio_dispatch(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """SDR / ADS-B / MAVLink edge runtime hosted on this controller."""
        try:
            from . import edge_radio
        except Exception as exc:
            return {
                "ok": False,
                "error": f"edge_radio unavailable: {exc}",
                "code": "unavailable",
            }
        return edge_radio.dispatch(method, params if isinstance(params, dict) else {})

    def _job_approve(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._job_queue is None:
            return {"ok": False, "error": "job queue not configured"}
        jid = str(params.get("job_id") or params.get("id") or "").strip()
        if not jid:
            return {"ok": False, "error": "job_id required"}
        approved_by = params.get("approved_by") if isinstance(params.get("approved_by"), dict) else {}
        return self._job_queue.approve(jid, approved_by=approved_by)

    def _job_status(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._job_queue is None:
            return {"ok": False, "error": "job queue not configured"}
        jid = str(params.get("job_id") or params.get("id") or "").strip()
        # Never hand vault secret *values* to Core. include_hydrated is refused.
        want_hydrated = str(params.get("include_hydrated") or params.get("claim") or "").lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        if want_hydrated:
            job = self._job_queue.get(jid, include_hydrated=False)
            if not job:
                return {"ok": False, "error": "job not found", "code": "not_found"}
            return {
                "ok": False,
                "error": (
                    "Secret values stay on the controller. "
                    "After LAN approve, Core runs tools; lan.relay hydrates secret names on LAN."
                ),
                "code": "secrets_must_stay_on_controller",
                "job_id": jid,
                "status": job.get("status"),
                "executed_on": "hayabusa",
                "hayabusa_saw_secret_values": False,
                "relay_ready": bool(job.get("relay_ready")),
            }
        job = self._job_queue.get(jid, include_hydrated=False)
        if not job:
            return {"ok": False, "error": "job not found", "code": "not_found"}
        return {"ok": True, **job}

    def _job_complete(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._job_queue is None:
            return {"ok": False, "error": "job queue not configured"}
        jid = str(params.get("job_id") or params.get("id") or "").strip()
        if not jid:
            return {"ok": False, "error": "job_id required"}
        rc = params.get("returncode")
        try:
            rc_i = int(rc) if rc is not None and str(rc) != "" else None
        except (TypeError, ValueError):
            rc_i = None
        return self._job_queue.complete(
            jid,
            ok=bool(params.get("ok")),
            stdout=str(params.get("stdout") or ""),
            stderr=str(params.get("stderr") or ""),
            error=str(params.get("error") or ""),
            returncode=rc_i,
            cmd=str(params.get("cmd") or ""),
            executed_on=str(params.get("executed_on") or "hayabusa"),
        )

    def _job_list(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._job_queue is None:
            return {"ok": False, "error": "job queue not configured"}
        status = str(params.get("status") or "").strip() or None
        try:
            limit = int(params.get("limit") or 50)
        except (TypeError, ValueError):
            limit = 50
        jobs = self._job_queue.list_jobs(status=status, limit=limit)
        return {"ok": True, "jobs": jobs, "count": len(jobs)}

    def _secrets_list(self) -> dict[str, Any]:
        keys = self.vault.list_keys(include_reserved=False)
        return {
            "ok": True,
            "keys": keys,
            "count": len(keys),
            "values_included": False,
        }

    def _guacamole_ssh_credentials(self, params: dict[str, Any]) -> dict[str, Any]:
        """Return SSH creds for Hayabusa→Guacamole SSH connections.

        Expected params:
          - user_secret_keys: list[str] | str (candidate secret keys for SSH username)
          - password_secret_keys: list[str] | str (candidate secret keys for SSH password)
        """

        def _as_list(v: Any) -> list[str]:
            if isinstance(v, str):
                return [v]
            if isinstance(v, list):
                return [str(x) for x in v if x is not None]
            return []

        user_keys = _as_list(params.get("user_secret_keys") or params.get("ssh_user_secret_keys") or [])
        pw_keys = _as_list(params.get("password_secret_keys") or params.get("ssh_password_secret_keys") or [])

        # Keep the resolution scope tight: only try keys that match our allowed secret name regex.
        user_keys = [k for k in user_keys if SECRET_NAME_RE.match(str(k or ""))]  # type: ignore[arg-type]
        pw_keys = [k for k in pw_keys if SECRET_NAME_RE.match(str(k or ""))]  # type: ignore[arg-type]

        def _resolve_first(keys: list[str]) -> tuple[str, list[str]]:
            resolved = ""
            tried: list[str] = []
            for k in keys[:20]:
                sk = str(k or "").strip()
                if not sk:
                    continue
                tried.append(sk)
                val = self.vault.get(sk, allow_reserved=False)
                if val is not None and str(val).strip():
                    resolved = str(val)
                    break
            return resolved, tried

        ssh_user, tried_user = _resolve_first(user_keys)
        ssh_password, tried_pw = _resolve_first(pw_keys)

        missing: list[str] = []
        if not ssh_user:
            missing.extend([k for k in tried_user if k])
        if not ssh_password:
            missing.extend([k for k in tried_pw if k])

        if not ssh_user or not ssh_password:
            return {
                "ok": False,
                "error": "missing_guacamole_ssh_secrets",
                "missing_secret_keys": sorted(set(missing)),
                "values_included": False,
            }

        return {
            "ok": True,
            "ssh_user": ssh_user,
            "ssh_password": ssh_password,
            "values_included": True,
        }

    def _secrets_resolve_ephemeral(self, params: dict[str, Any]) -> dict[str, Any]:
        """Return vault values for named keys (AI / short-lived use). Never catalog these as durable.

        Expected params:
          - keys: list[str] | str — vault secret names (max 8)
        """
        raw = params.get("keys") if isinstance(params, dict) else None
        names: list[str] = []
        if isinstance(raw, str):
            names = [raw]
        elif isinstance(raw, list):
            names = [str(x) for x in raw if x is not None]
        # Dedupe while preserving order
        seen: set[str] = set()
        ordered: list[str] = []
        for n in names:
            key = str(n or "").strip()
            if not key or key in seen:
                continue
            if not SECRET_NAME_RE.match(key) or is_reserved_secret_key(key):
                continue
            seen.add(key)
            ordered.append(key)
            if len(ordered) >= 8:
                break
        if not ordered:
            return {
                "ok": False,
                "error": "no_valid_secret_keys",
                "values_included": False,
                "values_ephemeral": True,
            }
        values: dict[str, str] = {}
        missing: list[str] = []
        for key in ordered:
            val = self.vault.get(key, allow_reserved=False)
            if val is None or not str(val).strip():
                missing.append(key)
                continue
            values[key] = str(val)
        if missing and not values:
            return {
                "ok": False,
                "error": "missing_secrets",
                "missing_secret_keys": missing,
                "values_included": False,
                "values_ephemeral": True,
            }
        return {
            "ok": True,
            "values": values,
            "missing_secret_keys": missing,
            "values_included": True,
            "values_ephemeral": True,
            "persist_forbidden": True,
        }

    def _iac_list(self, params: dict[str, Any]) -> dict[str, Any]:
        rel = str(params.get("path") or "").strip()
        if self._list_tree:
            entries = self._list_tree(rel)
            return {"ok": True, "path": rel, "entries": entries}
        root = self.devops_root
        target = (root / rel).resolve() if rel else root.resolve()
        if root.resolve() not in target.parents and target != root.resolve():
            return {"ok": False, "error": "invalid path"}
        if not target.is_dir():
            return {"ok": False, "error": "not a directory"}
        entries = []
        for p in sorted(target.iterdir(), key=lambda x: x.name.lower())[:500]:
            entries.append(
                {
                    "name": p.name,
                    "path": str(p.relative_to(root)).replace("\\", "/"),
                    "type": "dir" if p.is_dir() else "file",
                }
            )
        return {"ok": True, "path": rel, "entries": entries}

    def _iac_read(self, params: dict[str, Any]) -> dict[str, Any]:
        rel = str(params.get("path") or "").strip()
        if not rel:
            return {"ok": False, "error": "path required"}
        if self._read_file:
            try:
                content = self._read_file(rel)
            except Exception as exc:  # noqa: BLE001
                return {"ok": False, "error": str(exc)[:300]}
            return {"ok": True, "path": rel, "content": content, "ephemeral": True}
        root = self.devops_root.resolve()
        path = (root / rel).resolve()
        if root not in path.parents and path != root:
            return {"ok": False, "error": "invalid path"}
        if not path.is_file():
            return {"ok": False, "error": "not a file"}
        if path.stat().st_size > 2 * 1024 * 1024:
            return {"ok": False, "error": "file too large"}
        return {
            "ok": True,
            "path": rel,
            "content": path.read_text(encoding="utf-8", errors="replace"),
            "ephemeral": True,
        }

    def _collect_secret_keys(self, params: dict[str, Any], texts: list[str]) -> list[str]:
        keys: list[str] = []
        seen: set[str] = set()

        def _add(raw: str) -> None:
            key = str(raw or "").strip()
            if not key or key in seen:
                return
            if not SECRET_NAME_RE.match(key) or is_reserved_secret_key(key):
                return
            seen.add(key)
            keys.append(key)

        listed = params.get("secret_keys") or params.get("secrets") or []
        if isinstance(listed, str):
            listed = [listed]
        if isinstance(listed, list):
            for raw in listed[:50]:
                _add(str(raw))

        for text in texts:
            if not text:
                continue
            for m in SECRET_PLACEHOLDER_RE.finditer(text):
                key = m.group(1) or m.group(2) or ""
                env_tail = m.group(3) or ""
                if key:
                    _add(key)
                elif env_tail:
                    dotted = env_tail.replace("_", ".", 1) if "_" in env_tail else env_tail
                    if self.vault.get(dotted, allow_reserved=False) is not None:
                        _add(dotted)
                    else:
                        _add(env_tail)
        return keys

    def _resolve_secrets(self, keys: list[str]) -> tuple[dict[str, str], list[str]]:
        out: dict[str, str] = {}
        missing: list[str] = []
        for key in keys:
            val = self.vault.get(key, allow_reserved=False)
            if val is None:
                missing.append(key)
            else:
                out[key] = val
        return out, missing

    def _collect_image_nest_refs(
        self, params: dict[str, Any], texts: list[str]
    ) -> list[tuple[str, str]]:
        """Return ordered (ref, field) pairs found in params + playbook text."""
        pairs: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()

        def _add(ref: str, field: str = "") -> None:
            r = str(ref or "").strip()
            f = str(field or "").strip().lower()
            if not r or not IMAGE_NEST_REF_RE.match(r):
                return
            key = (r, f)
            if key in seen:
                return
            seen.add(key)
            pairs.append(key)

        listed = params.get("image_nest_refs") or params.get("image_refs") or []
        if isinstance(listed, str):
            listed = [listed]
        if isinstance(listed, list):
            for raw in listed[:50]:
                if isinstance(raw, dict):
                    _add(str(raw.get("ref") or ""), str(raw.get("field") or ""))
                else:
                    text = str(raw or "")
                    if ":" in text and not text.startswith("http"):
                        ref, _, field = text.partition(":")
                        _add(ref, field)
                    else:
                        _add(text)

        for text in texts:
            if not text:
                continue
            for m in IMAGE_NEST_PLACEHOLDER_RE.finditer(text):
                # groups: 1=ref (mustache), 2=field (mustache), 3=ref (angle), 4=field (angle), 5=env
                if m.group(1):
                    _add(m.group(1), m.group(2) or "")
                elif m.group(3):
                    _add(m.group(3), m.group(4) or "")
                elif m.group(5):
                    env_tail = m.group(5)
                    # HAYABUSA_IMAGE_NEST_<REF> or HAYABUSA_IMAGE_NEST_<REF>_<FIELD>
                    parts = env_tail.split("_")
                    if not parts:
                        continue
                    # Prefer matching known aliases/refs by normalizing
                    _add(env_tail.replace("_", "-").lower(), "")
                    _add(env_tail.lower(), "")
        return pairs

    def _resolve_image_nest_map(
        self, pairs: list[tuple[str, str]]
    ) -> tuple[dict[str, str], list[str], list[dict[str, Any]]]:
        """Map placeholder keys → path/value strings; also return payloads for packaging."""
        value_map: dict[str, str] = {}
        missing: list[str] = []
        payloads: list[dict[str, Any]] = []
        if not pairs:
            return value_map, missing, payloads
        if self._image_nest is None:
            for ref, field in pairs:
                label = f"{ref}:{field}" if field else ref
                missing.append(label)
            return value_map, missing, payloads

        seen_payloads: set[str] = set()
        for ref, field in pairs:
            result = self._image_nest.resolve_hydration_value(ref, field)
            label = f"{ref}:{field}" if field else ref
            if not result.get("ok"):
                missing.append(label)
                continue
            value = str(result.get("value") or "")
            field_n = str(result.get("field") or IMAGE_NEST_ENV_DEFAULT_FIELD)
            value_map[f"{ref}:{field_n}"] = value
            if field:
                value_map[f"{ref}:{field}"] = value
            if field_n == IMAGE_NEST_ENV_DEFAULT_FIELD or not field:
                value_map[ref] = value
            payload = result.get("payload") if isinstance(result.get("payload"), dict) else {}
            pref = str(payload.get("requested_ref") or ref)
            if pref and pref not in seen_payloads:
                seen_payloads.add(pref)
                payloads.append(payload)
        return value_map, missing, payloads

    def _substitute_placeholders(self, text: str, secret_map: dict[str, str]) -> str:
        if not text or not secret_map:
            return text

        def repl(m: re.Match[str]) -> str:
            key = m.group(1) or m.group(2) or ""
            env_tail = m.group(3) or ""
            if key and key in secret_map:
                return secret_map[key]
            if env_tail:
                for sk, val in secret_map.items():
                    if re.sub(r"[^A-Za-z0-9_]", "_", sk) == env_tail:
                        return val
            return m.group(0)

        return SECRET_PLACEHOLDER_RE.sub(repl, text)

    def _substitute_image_nest_placeholders(self, text: str, image_map: dict[str, str]) -> str:
        if not text or not image_map:
            return text

        def repl(m: re.Match[str]) -> str:
            if m.group(1):
                ref, field = m.group(1), m.group(2) or ""
            elif m.group(3):
                ref, field = m.group(3), m.group(4) or ""
            else:
                env_tail = m.group(5) or ""
                # Try exact env-style matches against map keys
                for sk, val in image_map.items():
                    if re.sub(r"[^A-Za-z0-9_]", "_", sk).upper() == env_tail.upper():
                        return val
                return m.group(0)
            if field:
                key = f"{ref}:{field}"
                if key in image_map:
                    return image_map[key]
            if ref in image_map:
                return image_map[ref]
            # Default field
            key = f"{ref}:{IMAGE_NEST_ENV_DEFAULT_FIELD}"
            if key in image_map:
                return image_map[key]
            return m.group(0)

        return IMAGE_NEST_PLACEHOLDER_RE.sub(repl, text)

    def _hydrate_text(self, text: str, secret_map: dict[str, str], image_map: dict[str, str]) -> str:
        out = self._substitute_placeholders(text, secret_map)
        return self._substitute_image_nest_placeholders(out, image_map)

    def _image_nest_env_map(self, payloads: list[dict[str, Any]], image_map: dict[str, str]) -> dict[str, str]:
        env: dict[str, str] = {}
        for payload in payloads:
            req = str(payload.get("requested_ref") or payload.get("image_nest_ref") or "")
            if not req:
                continue
            slug = re.sub(r"[^A-Za-z0-9_]", "_", req).upper()
            primary = (
                str(payload.get("source_image") or "")
                or image_map.get(req, "")
                or image_map.get(f"{req}:source_image", "")
            )
            if primary:
                env[f"HAYABUSA_IMAGE_NEST_{slug}"] = primary
            for field in ("source_image", "source_iso", "source_wim", "source_qcow2", "sha256", "image_flavor"):
                val = payload.get(field)
                if val:
                    env[f"HAYABUSA_IMAGE_NEST_{slug}_{field.upper()}"] = str(val)
            ref_name = payload.get("image_nest_ref")
            if ref_name:
                env[f"HAYABUSA_IMAGE_NEST_{slug}_REF"] = str(ref_name)
        return env

    def _image_nest_extra_files(
        self, payloads: list[dict[str, Any]], *, workdir: str, kind: str
    ) -> list[dict[str, str]]:
        """Attach vars JSON + optional OpenTofu auto.tfvars snippets into the hydrated package."""
        files: list[dict[str, str]] = []
        if not payloads:
            return files
        # Always ship a machine-readable summary under OpenTofu/ or workdir.
        summary = {
            "ok": True,
            "hydrated_at": None,
            "refs": [
                {
                    "requested_ref": p.get("requested_ref"),
                    "image_nest_ref": p.get("image_nest_ref"),
                    "source_image": p.get("source_image"),
                    "source_iso": p.get("source_iso"),
                    "source_wim": p.get("source_wim"),
                    "source_qcow2": p.get("source_qcow2"),
                    "sha256": p.get("sha256"),
                    "image_flavor": p.get("image_flavor"),
                    "playbook_vars_file": p.get("playbook_vars_file"),
                }
                for p in payloads
            ],
        }
        import json as _json

        rel_base = (workdir.strip().lstrip("/") + "/") if workdir.strip() not in ("", ".") else ""
        files.append(
            {
                "path": f"{rel_base}image-nest-hydrated.json".lstrip("/"),
                "content": _json.dumps(summary, indent=2, sort_keys=True) + "\n",
            }
        )
        if kind in {"tofu", "terraform"}:
            lines = [
                "# Generated by controller Image Nest hydrate (LAN approve).",
                "# Controller does not run OpenTofu — Hayabusa applies these vars.",
            ]
            # If only one ref, use the conventional OpenTofu variable names.
            if len(payloads) == 1:
                p = payloads[0]
                src = str(p.get("source_image") or p.get("source_iso") or "")
                if src:
                    lines.append(f'source_image   = "{src}"')
                if p.get("source_iso"):
                    lines.append(f'source_iso     = "{p.get("source_iso")}"')
                if p.get("source_wim"):
                    lines.append(f'source_wim     = "{p.get("source_wim")}"')
                if p.get("image_nest_ref"):
                    lines.append(f'image_nest_ref = "{p.get("image_nest_ref")}"')
                if p.get("image_flavor"):
                    lines.append(f'image_flavor   = "{p.get("image_flavor")}"')
                if p.get("sha256"):
                    lines.append(f'image_sha256   = "{p.get("sha256")}"')
            else:
                for p in payloads:
                    req = re.sub(r"[^A-Za-z0-9_]", "_", str(p.get("requested_ref") or "ref"))
                    src = str(p.get("source_image") or p.get("source_iso") or "")
                    if src:
                        lines.append(f'{req}_source_image = "{src}"')
                    if p.get("image_nest_ref"):
                        lines.append(f'{req}_image_nest_ref = "{p.get("image_nest_ref")}"')
            files.append(
                {
                    "path": f"{rel_base}image-nest.auto.tfvars".lstrip("/"),
                    "content": "\n".join(lines) + "\n",
                }
            )
        # Copy per-ref vars JSON content into the package for Ansible -e @…
        for p in payloads:
            vars_path = Path(str(p.get("playbook_vars_file") or ""))
            req = re.sub(r"[^A-Za-z0-9._-]", "-", str(p.get("requested_ref") or "ref"))
            if vars_path.is_file():
                try:
                    content = vars_path.read_text(encoding="utf-8")
                except OSError:
                    continue
                files.append(
                    {
                        "path": f"{rel_base}image-nest-refs/{req}.vars.json".lstrip("/"),
                        "content": content,
                    }
                )
        return files

    def _scrub_secret_values_from_text(self, text: str) -> str:
        """Replace any known vault VALUES with ``{{ hayabusa_secret:KEY }}`` placeholders.

        Hayabusa Core must only ever see secret *names*. Call this before any
        playbook/OpenTofu text leaves the controller toward Core.
        """
        if not text or not getattr(self, "vault", None):
            return text
        try:
            keys = self.vault.list_keys(include_reserved=False)
        except Exception:
            return text
        pairs: list[tuple[str, str]] = []
        for key in keys or []:
            k = str(key or "").strip()
            if not k or not SECRET_NAME_RE.match(k):
                continue
            try:
                val = self.vault.get(k, allow_reserved=False)
            except Exception:
                continue
            if not isinstance(val, str):
                continue
            # Skip tiny/placeholder-like values to avoid corrupting short tokens.
            if len(val) < 6 or not val.strip():
                continue
            pairs.append((val, k))
        if not pairs:
            return text
        pairs.sort(key=lambda row: len(row[0]), reverse=True)
        out = text
        for val, key in pairs:
            if val in out:
                out = out.replace(val, "{{ hayabusa_secret:" + key + " }}")
        return out

    def _lint_plaintext_secrets(self, path: str, text: str) -> list[dict[str, Any]]:
        """Find high-confidence plaintext secrets that are not secret-name placeholders.

        Operators should replace these with ``{{ hayabusa_secret:NAME }}`` (vault on
        this controller). Findings block that file from syncing to Core.
        """
        if not text:
            return []
        findings: list[dict[str, Any]] = []
        rel = str(path or "").strip()

        def _consider(key: str, val: str, line_no: int, snippet: str) -> None:
            v = str(val or "").strip().strip("'\"")
            if len(v) < 6:
                return
            if _PLACEHOLDER_VALUE_RE.search(v):
                return
            # Common non-secrets / templates
            low = v.lower()
            if low in {
                "changeme",
                "password",
                "secret",
                "null",
                "none",
                "true",
                "false",
                "todo",
                "xxx",
                "your-password",
                "example",
            }:
                return
            if v.startswith(("http://", "https://", "/", "./", "../")):
                return
            findings.append(
                {
                    "path": rel,
                    "line": line_no,
                    "key": key,
                    "severity": "plaintext_secret",
                    "message": (
                        f"Replace plaintext {key!r} with {{{{ hayabusa_secret:NAME }}}} "
                        "(vault on controller). File blocked from Core sync."
                    ),
                    "snippet": snippet[:160],
                }
            )

        for i, line in enumerate(text.splitlines(), start=1):
            # Skip comments
            stripped = line.lstrip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            m = _PLAINTEXT_SECRET_ASSIGN_RE.match(line)
            if m:
                _consider(m.group("key"), m.group("val"), i, line.strip())
                continue
            for tm in _PLAINTEXT_TF_SECRET_RE.finditer(line):
                _consider(tm.group("key"), tm.group("val"), i, line.strip())
        # Cap noise per file
        return findings[:20]

    def _iac_export_owned(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._rbac is None:
            return {"ok": False, "error": "rbac not configured"}
        user_key = str(params.get("user_key") or params.get("username") or "").strip()
        if not user_key:
            return {"ok": False, "error": "user_key required"}
        result = self._rbac.export_owned_files(
            user_key,
            read_file=self._read_file or (lambda rel: self._iac_read({"path": rel}).get("content") or ""),
            list_tree=self._list_tree or (lambda rel: (self._iac_list({"path": rel}).get("entries") or [])),
            max_files=int(params.get("max_files") or 400),
            max_bytes=int(params.get("max_bytes") or 12_000_000),
        )
        if not isinstance(result, dict) or not result.get("ok"):
            return result if isinstance(result, dict) else {"ok": False, "error": "export failed"}
        files = result.get("files") if isinstance(result.get("files"), list) else []
        scrubbed: list[dict[str, str]] = []
        total = 0
        lint_blocked: list[dict[str, Any]] = []
        lint_findings: list[dict[str, Any]] = []
        for item in files:
            if not isinstance(item, dict):
                continue
            rel = str(item.get("path") or "").strip().lstrip("/")
            content = item.get("content")
            if not rel or not isinstance(content, str):
                continue
            # Never ship vault values — Core stores secret names only.
            content = self._scrub_secret_values_from_text(content)
            findings = self._lint_plaintext_secrets(rel, content)
            if findings:
                lint_findings.extend(findings)
                lint_blocked.append(
                    {
                        "path": rel,
                        "findings": len(findings),
                        "examples": [f.get("message") for f in findings[:3]],
                    }
                )
                # Block this file from Core — keep vault values / plaintext on controller.
                continue
            nbytes = len(content.encode("utf-8", errors="replace"))
            scrubbed.append({"path": rel, "content": content})
            total += nbytes
        result["files"] = scrubbed
        result["count"] = len(scrubbed)
        result["bytes"] = total
        result["hayabusa_saw_secret_values"] = False
        result["secret_values_scrubbed"] = True
        result["lint_blocked"] = lint_blocked[:80]
        result["lint_findings"] = lint_findings[:120]
        result["lint_blocked_count"] = len(lint_blocked)
        result["note"] = (
            "Exported Ansible/OpenTofu text with secret *names* only; "
            "vault values were scrubbed and plaintext secret assignments were blocked."
        )
        if lint_blocked:
            result["warning"] = (
                f"{len(lint_blocked)} file(s) blocked for plaintext secrets — "
                "replace with {{ hayabusa_secret:NAME }} on the controller, then Sync again."
            )
        return result

    def _iac_import_sync(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._import_sync is None:
            return {"ok": False, "error": "import_sync not configured"}
        params = dict(params) if isinstance(params, dict) else {}
        user_key = str(params.get("user_key") or params.get("username") or "").strip() or "admin"
        files = params.get("files") if isinstance(params.get("files"), list) else []
        out = self._import_sync({"user_key": user_key, "files": files})
        if not isinstance(out, dict):
            return {"ok": False, "error": "invalid import_sync result"}
        if out.get("ok") and self._rbac is not None:
            for item in files[:250]:
                if not isinstance(item, dict):
                    continue
                rel = str(item.get("path") or "").strip().lstrip("/")
                low = rel.lower()
                if low.endswith((".yml", ".yaml")) and low.startswith(("ansible/", "opentofu/")):
                    try:
                        self._rbac.set_playbook_owner(rel, owner_type="user", owner_id=user_key)
                    except Exception:
                        pass
                elif any(low.startswith(p) for p in ("ztp/", "bare-metal-ztp/", "ansible/ztp/", "ansible/bare-metal-ztp/")):
                    try:
                        self._rbac.set_playbook_owner(rel, owner_type="user", owner_id=user_key)
                    except Exception:
                        pass
        return out

    def _iac_inventory_summary(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return compact OpenTofu/Ansible host list for Hayabusa map (no secrets)."""
        params = params if isinstance(params, dict) else {}
        if self._inventory_summary is not None:
            try:
                # Prefer callback that accepts RPC params (opentofu_only, max_hosts).
                try:
                    out = self._inventory_summary(params)  # type: ignore[misc, call-arg]
                except TypeError:
                    out = self._inventory_summary()
            except Exception as exc:  # noqa: BLE001
                return {"ok": False, "error": str(exc)[:300], "hosts": []}
            if not isinstance(out, dict):
                return {"ok": False, "error": "invalid inventory", "hosts": []}
            # Belt-and-suspenders: invent callers may request OpenTofu-only.
            if str(params.get("opentofu_only", "")).lower() in ("1", "true", "yes", "on"):
                hosts = out.get("hosts") if isinstance(out.get("hosts"), list) else []
                filtered = [
                    h
                    for h in hosts
                    if isinstance(h, dict)
                    and (
                        str(h.get("source") or "").lower() == "opentofu"
                        or h.get("tofu_address")
                        or h.get("tofu_type")
                        or h.get("kind") in {"compute", "network_device"}
                    )
                ]
                out = {**out, "hosts": filtered, "count": len(filtered), "opentofu_only": True}
            return out
        # Fallback: scan devops_root for terraform.tfstate names only.
        root = self.devops_root
        hosts: list[dict[str, Any]] = []
        state_path = None
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in {".terraform", ".git"}]
            if "terraform.tfstate" in filenames:
                state_path = str((Path(dirpath) / "terraform.tfstate").relative_to(root)).replace("\\", "/")
                break
        return {
            "ok": True,
            "workspace": str(root),
            "generated_at": None,
            "state_path": state_path,
            "hosts": hosts,
            "count": 0,
            "message": "inventory_summary callback not configured",
        }

    def _iac_state_snapshot(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Scoped OpenTofu state/config for AI recommend — redacted, ephemeral."""
        params = params if isinstance(params, dict) else {}
        # Prefer DevopsIacWorkspace via inventory_summary object when available.
        try:
            from .devops_iac import DevopsIacWorkspace
        except ImportError:
            from devops_iac import DevopsIacWorkspace  # type: ignore
        try:
            ws = DevopsIacWorkspace(self.devops_root)
            return ws.state_snapshot(
                device_id=str(params.get("device_id") or params.get("device") or ""),
                ip=str(params.get("ip") or ""),
                name=str(params.get("name") or ""),
                include_tf_config=str(params.get("include_tf_config", "1")).lower()
                not in ("0", "false", "no", "off"),
                include_raw_state=str(params.get("include_raw_state", "0")).lower()
                in ("1", "true", "yes", "on"),
            )
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)[:300], "device_access": "none"}

    def _gameplan_owner_key(self, params: dict[str, Any]) -> str:
        return str(params.get("user_key") or params.get("owner") or "").strip() or "anonymous"

    def _gameplan_list(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        params = params if isinstance(params, dict) else {}
        if self._gameplan is None:
            return {"ok": False, "error": "gameplan store unavailable"}
        owner = self._gameplan_owner_key(params)
        return {"ok": True, "blueprints": self._gameplan.list_blueprints(owner), "owner": owner}

    def _gameplan_get(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        params = params if isinstance(params, dict) else {}
        if self._gameplan is None:
            return {"ok": False, "error": "gameplan store unavailable"}
        owner = self._gameplan_owner_key(params)
        bp_id = str(params.get("blueprint_id") or params.get("id") or "").strip()
        bp = self._gameplan.get_blueprint(owner, bp_id)
        if not bp:
            return {"ok": False, "error": "not found"}
        return {"ok": True, "blueprint": bp}

    def _gameplan_save(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        params = params if isinstance(params, dict) else {}
        if self._gameplan is None:
            return {"ok": False, "error": "gameplan store unavailable"}
        owner = self._gameplan_owner_key(params)
        payload = params.get("blueprint") if isinstance(params.get("blueprint"), dict) else params
        try:
            bp = self._gameplan.save_blueprint(owner, payload if isinstance(payload, dict) else {})
        except PermissionError as exc:
            return {"ok": False, "error": str(exc), "code": "forbidden"}
        except ValueError as exc:
            return {"ok": False, "error": str(exc), "code": "bad_request"}
        except Exception as exc:  # noqa: BLE001
            logger.exception("gameplan.save failed")
            return {"ok": False, "error": str(exc)[:300]}
        return {"ok": True, "blueprint": bp}

    def _gameplan_delete(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        params = params if isinstance(params, dict) else {}
        if self._gameplan is None:
            return {"ok": False, "error": "gameplan store unavailable"}
        owner = self._gameplan_owner_key(params)
        bp_id = str(params.get("blueprint_id") or params.get("id") or "").strip()
        ok = self._gameplan.delete_blueprint(owner, bp_id)
        return {"ok": ok, "error": None if ok else "not found"}

    def _integrations_owner_key(self, params: dict[str, Any]) -> str:
        return str(params.get("user_key") or params.get("owner") or "").strip() or "anonymous"

    def _integrations_bundle_get(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        params = params if isinstance(params, dict) else {}
        if self._integrations is None:
            return {"ok": False, "error": "integrations store unavailable", "code": "unavailable"}
        owner = self._integrations_owner_key(params)
        bundle = self._integrations.get_bundle(owner)
        return {"ok": True, "bundle": bundle, "owner": owner}

    def _integrations_bundle_put(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        params = params if isinstance(params, dict) else {}
        if self._integrations is None:
            return {"ok": False, "error": "integrations store unavailable", "code": "unavailable"}
        owner = self._integrations_owner_key(params)
        bundle = params.get("bundle") if isinstance(params.get("bundle"), dict) else params
        try:
            saved = self._integrations.put_bundle(owner, bundle if isinstance(bundle, dict) else {})
        except Exception as exc:  # noqa: BLE001
            logger.exception("integrations.bundle.put failed")
            return {"ok": False, "error": str(exc)[:300]}
        return {"ok": True, "bundle": saved, "owner": owner}

    def _telemetry_push(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Stamp controller_branch/device_id and push Prometheus text to Core Pushgateway."""
        params = params if isinstance(params, dict) else {}
        try:
            from . import telemetry_push as tp
        except ImportError:
            import telemetry_push as tp  # type: ignore
        metrics = params.get("metrics") if isinstance(params.get("metrics"), list) else []
        core_url = str(
            params.get("core_base_url")
            or os.environ.get("HAYABUSA_CORE_URL")
            or os.environ.get("PEREGRINE_PUBLIC_URL")
            or ""
        ).strip()
        tenant = str(params.get("tenant") or os.environ.get("HAYABUSA_OBSERVABILITY_TENANT") or "").strip()
        token = str(
            params.get("agent_token") or os.environ.get("HAYABUSA_OBSERVABILITY_AGENT_TOKEN") or ""
        ).strip()
        text = tp.build_prometheus_text(
            metrics=metrics,
            controller_branch=str(params.get("controller_branch") or "") or None,
        )
        if str(params.get("dry_run", "")).lower() in ("1", "true", "yes", "on"):
            return {
                "ok": True,
                "dry_run": True,
                "controller_branch": tp.controller_branch_label(),
                "body_preview": text[:4000],
                "metric_lines": text.count("\n") if text else 0,
            }
        return tp.push_to_core_pushgateway(
            core_base_url=core_url,
            tenant=tenant,
            agent_token=token,
            body=text,
        )

    def _hydrate_job(self, params: dict[str, Any]) -> dict[str, Any]:
        """Resolve secret names into an ephemeral package for Hayabusa execution."""
        params = dict(params) if isinstance(params, dict) else {}
        params.pop("secret_values", None)
        kind = str(params.get("kind") or "ansible-playbook").strip().lower()
        if kind in {"ansible", "opentofu", "tf"}:
            kind = {"ansible": "ansible-playbook", "opentofu": "tofu", "tf": "terraform"}[kind]
        if kind == "ztp-dhcp-start":
            if self._ztp_edge is None:
                return {"ok": False, "error": "ztp edge not configured", "hydrated": False}
            edge_res = self._ztp_edge.start()
            return {
                "ok": bool(edge_res.get("ok")),
                "hydrated": bool(edge_res.get("ok")),
                "kind": kind,
                "ztp_action": "start",
                "ztp_result": edge_res,
                "executed_on": "controller",
                "lan_approved": True,
                "values_ephemeral": False,
                "message": "ZTP DHCP started on controller LAN after LAN approval",
            }
        if kind == "ztp-dhcp-stop":
            if self._ztp_edge is None:
                return {"ok": False, "error": "ztp edge not configured", "hydrated": False}
            edge_res = self._ztp_edge.stop()
            return {
                "ok": bool(edge_res.get("ok")),
                "hydrated": bool(edge_res.get("ok")),
                "kind": kind,
                "ztp_action": "stop",
                "ztp_result": edge_res,
                "executed_on": "controller",
                "lan_approved": True,
                "values_ephemeral": False,
                "message": "ZTP DHCP stopped on controller after LAN approval",
            }
        if kind not in SAFE_JOB_KINDS:
            return {"ok": False, "error": f"unsupported kind: {kind}", "hydrated": False}

        extras_in = params.get("extra_files") or []
        texts: list[str] = []
        args = [str(a) for a in (params.get("args") or [])[:40]]
        texts.extend(args)
        clean_extras: list[dict[str, str]] = []
        if isinstance(extras_in, list):
            for item in extras_in[:40]:
                if not isinstance(item, dict):
                    continue
                path = str(item.get("path") or "").strip().lstrip("/")
                content = item.get("content")
                if not path or not isinstance(content, str):
                    continue
                if ".." in path.split("/"):
                    continue
                texts.append(content)
                clean_extras.append({"path": path, "content": content})

        workdir_rel = str(params.get("workdir") or "").strip().lstrip("/")
        wd = self.devops_root / workdir_rel if workdir_rel else self.devops_root
        if wd.is_dir():
            for name in (
                "terraform.tfvars",
                "terraform.auto.tfvars",
                "variables.tf",
                "providers.tf",
                "main.tf",
                "image-nest.auto.tfvars",
            ):
                tf_path = wd / name
                if tf_path.is_file():
                    try:
                        texts.append(tf_path.read_text(encoding="utf-8"))
                    except OSError:
                        pass
            # Scan playbook / vars paths referenced in args (Ansible + OpenTofu).
            for raw in args:
                rel = str(raw or "").strip().lstrip("/")
                if not rel or ".." in rel.split("/"):
                    continue
                low = rel.lower()
                if not low.endswith(
                    (".yml", ".yaml", ".tfvars", ".tf", ".json", ".j2", ".tpl", ".ini", ".cfg")
                ):
                    continue
                cand = wd / rel
                if not cand.is_file():
                    cand = self.devops_root / rel
                if cand.is_file() and cand.stat().st_size <= 2 * 1024 * 1024:
                    try:
                        texts.append(cand.read_text(encoding="utf-8", errors="replace"))
                    except OSError:
                        pass
            if kind == "ztp":
                ztp_names = (
                    "bootstrap.sh",
                    "post-install.sh",
                    "user-data",
                    "meta-data",
                    "config.json",
                    "ztp_config.json",
                    "recipe.json",
                    "dispatch.ipxe",
                    "boot.ipxe",
                )
                for name in ztp_names:
                    zp = wd / name
                    if zp.is_file():
                        try:
                            texts.append(zp.read_text(encoding="utf-8"))
                        except OSError:
                            pass
                for sub in ("", "scripts", "templates", "configs"):
                    base = wd / sub if sub else wd
                    if not base.is_dir():
                        continue
                    try:
                        for fp in sorted(base.iterdir())[:30]:
                            if not fp.is_file():
                                continue
                            low = fp.name.lower()
                            if low.endswith((".sh", ".cfg", ".json", ".ipxe", ".pxe", ".txt", ".yaml", ".yml", ".j2", ".tpl")):
                                try:
                                    texts.append(fp.read_text(encoding="utf-8"))
                                except OSError:
                                    pass
                    except OSError:
                        pass

        keys = self._collect_secret_keys(params, texts)
        secret_map, missing = self._resolve_secrets(keys)
        if missing:
            return {
                "ok": False,
                "hydrated": False,
                "error": f"missing secrets: {', '.join(missing[:12])}",
                "missing_secret_keys": missing[:50],
                "code": "missing_secrets",
            }

        image_pairs = self._collect_image_nest_refs(params, texts)
        image_map, missing_images, image_payloads = self._resolve_image_nest_map(image_pairs)
        if missing_images:
            return {
                "ok": False,
                "hydrated": False,
                "error": f"missing Image Nest refs: {', '.join(missing_images[:12])}",
                "missing_image_nest_refs": missing_images[:50],
                "code": "missing_image_nest_refs",
            }

        hydrated_files = [
            {
                "path": item["path"],
                "content": self._hydrate_text(item["content"], secret_map, image_map),
            }
            for item in clean_extras
        ]
        hydrated_args = [self._hydrate_text(a, secret_map, image_map) for a in args]
        env_map: dict[str, str] = {}
        for key, val in secret_map.items():
            env_key = "HAYABUSA_SECRET_" + re.sub(r"[^A-Za-z0-9_]", "_", key)
            env_map[env_key] = val
        env_map.update(self._image_nest_env_map(image_payloads, image_map))

        workdir = str(params.get("workdir") or "").strip()
        try:
            timeout_sec = int(params.get("timeout_sec") or params.get("timeout") or 300)
        except (TypeError, ValueError):
            timeout_sec = 300
        timeout_sec = max(5, min(timeout_sec, 3600))

        # Attach Image Nest vars files / auto.tfvars into the ephemeral package.
        for item in self._image_nest_extra_files(image_payloads, workdir=workdir, kind=kind):
            hydrated_files.append(item)

        return {
            "ok": True,
            "hydrated": True,
            "kind": kind,
            "workdir": workdir,
            "args": hydrated_args,
            "extra_files": hydrated_files,
            "env": env_map,
            "timeout_sec": timeout_sec,
            "secret_keys_used": list(secret_map.keys()),
            "image_nest_refs_used": [
                str(p.get("requested_ref") or p.get("image_nest_ref") or "")
                for p in image_payloads
                if p.get("requested_ref") or p.get("image_nest_ref")
            ],
            "image_nest_map": image_map,
            "workspace_root": str(params.get("workspace_root") or "").strip(),
            "workspace_user_key": str(params.get("workspace_user_key") or "").strip(),
            "lan_approved": True,
            "executed_on": (
                "controller"
                if kind in {"ztp-dhcp-start", "ztp-dhcp-stop"}
                or str(params.get("execute_on") or "").strip().lower()
                in {"controller", "local", "appliance"}
                else "hayabusa"
            ),
            "values_ephemeral": True,
            "message": (
                "ZTP action bound to controller LAN"
                if kind in {"ztp-dhcp-start", "ztp-dhcp-stop"}
                else "Hydrated markers only — Core executes; lan.relay applies secret names on controller"
            ),
        }

    def _execute_hydrated_package(self, package: dict[str, Any]) -> dict[str, Any]:
        """Refuse local ansible/tofu — Core executes; controller only vault + lan.relay."""
        package = package if isinstance(package, dict) else {}
        kind = str(package.get("kind") or "ansible-playbook").strip().lower()
        return {
            "ok": False,
            "error": (
                "Controller does not run Ansible/OpenTofu. Hayabusa Core executes "
                f"after LAN Approve; this appliance only vault + lan.relay (kind={kind})."
            ),
            "code": "execute_on_core_only",
            "returncode": 127,
            "executed_on": "controller",
        }

    # Back-compat alias used by JobQueue(..., hydrator=...) wiring.
    def _job_run(self, params: dict[str, Any]) -> dict[str, Any]:
        return self._hydrate_job(params)
