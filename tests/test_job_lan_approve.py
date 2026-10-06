"""LAN approval: grant lan.relay; Core executes IaC (secrets stay on controller)."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from app.bridge_rpc import BridgeRpcHandler
from app.config import get_settings
from app.job_queue import JobQueue
from app.lan_relay import LanRelay, expand_secret_markers, is_secret_name
from app.secrets_vault import SecretsVault


class JobLanApproveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        os.environ["CONTROLLER_SECRET_KEY"] = "unit-test-controller-secret-key-32b!!"
        os.environ["CONTROLLER_DATA_DIR"] = str(root)
        os.environ["CONTROLLER_ALLOW_INSECURE_DEFAULTS"] = "1"
        os.environ.pop("CONTROLLER_JOB_AUTO_APPROVE", None)
        get_settings.cache_clear()
        settings = get_settings()
        self.vault = SecretsVault(settings)
        self.vault.put("api.token", "super-secret-token-value")
        self.vault.put("PROXMOX_PASSWORD", "lab-only-password-value")
        self.devops = settings.devops_workspace
        self.devops.mkdir(parents=True, exist_ok=True)
        (self.devops / "play.yml").write_text(
            "---\n- hosts: localhost\n  gather_facts: false\n  tasks: []\n",
            encoding="utf-8",
        )
        self.rpc = BridgeRpcHandler(vault=self.vault, devops_root=self.devops)
        self.executed_packages: list[dict] = []

        def _fake_exec(package: dict) -> dict:
            self.executed_packages.append(package)
            return {
                "ok": True,
                "returncode": 0,
                "stdout": "ok",
                "stderr": "",
                "cmd": "ansible-playbook play.yml",
                "executed_on": "controller",
            }

        self.queue = JobQueue(
            root,
            hydrator=self.rpc._hydrate_job,
            local_executor=_fake_exec,
        )
        self.rpc.set_job_queue(self.queue)

    def tearDown(self) -> None:
        get_settings.cache_clear()
        self.tmp.cleanup()

    def test_job_run_queues_for_lan_approve(self) -> None:
        out = self.rpc._job_run_or_queue(
            {
                "kind": "ansible-playbook",
                "args": ["play.yml"],
                "secret_keys": ["api.token"],
                "extra_files": [
                    {
                        "path": "from_hayabusa.yml",
                        "content": "msg: '{{ hayabusa_secret:api.token }}'\n",
                    }
                ],
            }
        )
        self.assertTrue(out.get("pending_approval"))
        self.assertEqual(out.get("status"), "pending_approval")
        self.assertEqual(out.get("executed_on"), "hayabusa")
        jid = out.get("job_id")
        self.assertTrue(jid)
        pending = self.queue.list_jobs(status="pending_approval")
        self.assertEqual(len(pending), 1)
        self.assertIn("api.token", pending[0].get("secret_keys") or [])
        self.assertNotIn("super-secret-token-value", str(pending[0]))

    def test_approve_grants_relay_does_not_execute_iac(self) -> None:
        submitted = self.queue.submit(
            {
                "kind": "ansible-playbook",
                "args": ["play.yml"],
                "secret_keys": ["api.token"],
                "extra_files": [
                    {
                        "path": "echo.yml",
                        "content": "token={{ hayabusa_secret:api.token }}\n",
                    }
                ],
                "metadata": {"lan_host": "192.168.1.200", "lan_user": "root", "ssh_secret_key": "PROXMOX_PASSWORD"},
            },
            requested_by={"username": "hayabusa-user"},
        )
        jid = submitted["job_id"]
        result = self.queue.approve(jid, approved_by={"username": "lan-admin"})
        self.assertTrue(result.get("ok"))
        self.assertEqual(result.get("status"), "approved")
        self.assertTrue(result.get("lan_approved"))
        self.assertTrue(result.get("relay_ready"))
        self.assertEqual((result.get("result") or {}).get("executed_on"), "hayabusa")
        # Approve must not run controller-local IaC.
        self.assertEqual(len(self.executed_packages), 0)
        self.assertNotIn("super-secret-token-value", str(result))
        self.assertNotIn("lab-only-password-value", str(result))
        self.assertNotIn("hydrated", result)
        self.assertTrue(self.queue.is_approved_for_relay(jid))

        # Core must not be able to claim hydrated secret packages.
        claim = self.rpc._job_status({"job_id": jid, "claim": "1"})
        self.assertEqual(claim.get("code"), "secrets_must_stay_on_controller")
        self.assertNotIn("hydrated", claim)
        self.assertNotIn("super-secret-token-value", str(claim))

        # Status for Core includes playbook text (markers only) + params.
        st = self.rpc._job_status({"job_id": jid})
        self.assertTrue(st.get("ok"))
        self.assertEqual(st.get("status"), "approved")
        params = st.get("params") or {}
        extras = params.get("extra_files") or []
        self.assertTrue(any("hayabusa_secret:api.token" in (f.get("content") or "") for f in extras))
        self.assertNotIn("super-secret-token-value", str(st))

        # job.complete from Core after execute.
        done = self.queue.complete(
            jid,
            ok=True,
            stdout="changed=0",
            stderr="",
            returncode=0,
            cmd="ansible-playbook play.yml",
            executed_on="hayabusa",
        )
        self.assertTrue(done.get("ok"))
        self.assertEqual(done.get("status"), "completed")
        self.assertFalse((done.get("result") or {}).get("hayabusa_saw_secret_values"))

    def test_lan_relay_rejects_raw_password_and_unapproved(self) -> None:
        relay = LanRelay(
            vault_get=lambda k: self.vault.get(str(k or "").strip()),
            job_approved=lambda jid: self.queue.is_approved_for_relay(jid),
        )
        bad = relay.open_session(
            {
                "job_id": "nope",
                "host": "192.168.1.200",
                "username": "root",
                "secret_key": "PROXMOX_PASSWORD",
                "password": "should-be-rejected",
            }
        )
        self.assertEqual(bad.get("code"), "secret_value_rejected")
        unapproved = relay.open_session(
            {
                "job_id": "missing",
                "host": "192.168.1.200",
                "username": "root",
                "secret_key": "PROXMOX_PASSWORD",
            }
        )
        self.assertEqual(unapproved.get("code"), "not_approved")
        self.assertTrue(is_secret_name("PROXMOX_PASSWORD"))
        self.assertFalse(is_secret_name("has spaces"))
        self.assertFalse(is_secret_name("1bad"))
        self.assertFalse(is_secret_name("short!pass"))
        expanded = expand_secret_markers(
            "x={{ hayabusa_secret:PROXMOX_PASSWORD }}",
            lambda n: self.vault.get(n),
        )
        self.assertIn("lab-only-password-value", expanded)

    def test_deny(self) -> None:
        submitted = self.queue.submit(
            {"kind": "ansible-playbook", "args": ["play.yml"], "secret_keys": ["api.token"]},
            requested_by={"username": "u"},
        )
        out = self.queue.deny(submitted["job_id"], denied_by={"username": "lan"}, reason="nope")
        self.assertTrue(out.get("ok"))
        self.assertEqual(out.get("status"), "denied")
