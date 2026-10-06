"""Five independent verification passes for hayabusa-controller."""

from __future__ import annotations

import os
import re
import tempfile
import unittest
from pathlib import Path

try:
    from fastapi.testclient import TestClient
except ImportError:  # pragma: no cover
    TestClient = None  # type: ignore[misc, assignment]


def _csrf(resp) -> str:
    tok = resp.headers.get("x-csrf-token") or resp.headers.get("X-CSRF-Token") or ""
    if tok:
        return tok
    m = re.search(r'name="csrf-token"\s+content="([^"]+)"', resp.text or "")
    return m.group(1) if m else ""


def _build_client(tmp: Path) -> TestClient:
    os.environ["CONTROLLER_SECRET_KEY"] = "unit-test-controller-secret-key-32b!!"
    os.environ["CONTROLLER_MANUAL_USERNAME"] = "admin"
    os.environ["CONTROLLER_MANUAL_PASSWORD"] = "test-password-please-change"
    os.environ["CONTROLLER_DATA_DIR"] = str(tmp)
    os.environ["HAYABUSA_MESH_SERVER_URL"] = "https://mesh.example:8443"
    os.environ["HAYABUSA_PREAUTH_KEY"] = "tskey-auth-test"
    # Simulate is test-gated: both flags required outside PYTEST_CURRENT_TEST.
    os.environ["CONTROLLER_VPN_MODE"] = "simulate"
    os.environ["CONTROLLER_ALLOW_VPN_SIMULATE"] = "1"
    os.environ["CONTROLLER_MANUAL_MESH_OVERRIDE_LOCAL"] = "1"
    os.environ["CONTROLLER_CSRF_PROTECT"] = "1"
    os.environ["CONTROLLER_ABUSE_RATE_LIMIT"] = "1"
    os.environ["CONTROLLER_SKIP_POST_LOGIN_CONNECT"] = "1"
    from app import config, main
    from app.setup_store import SetupStore

    config.get_settings.cache_clear()
    settings = config.get_settings()
    settings.hayabusa_ws_url = ""
    main.create_app(settings)
    main.bridge.settings.hayabusa_ws_url = ""
    main.bridge._status["ws_url"] = ""
    # HTTP passes exercise the dashboard, not first-run setup.
    main.setup = SetupStore(tmp)
    main.setup.mark_complete(mode="novice", completed_by="unit-test")
    return TestClient(main.app)


@unittest.skipUnless(TestClient is not None, "fastapi not installed")
class FivePassControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.client = _build_client(Path(self.tmp.name))
        self._csrf = ""

    def tearDown(self) -> None:
        self.client.close()
        self.tmp.cleanup()

    def _login(self) -> None:
        page = self.client.get("/login")
        self.assertEqual(page.status_code, 200)
        tok = _csrf(page)
        self.assertTrue(tok)
        r = self.client.post(
            "/auth/manual",
            data={
                "admin_username": "admin",
                "admin_password": "test-password-please-change",
                "csrf_token": tok,
            },
            follow_redirects=False,
        )
        self.assertIn(r.status_code, (302, 303))
        self.assertEqual(r.headers.get("location"), "/")
        dash = self.client.get("/")
        self._csrf = _csrf(dash) or tok

    def _hdr(self) -> dict[str, str]:
        return {"X-CSRF-Token": self._csrf} if self._csrf else {}

    def _run_pass(self, pass_no: int) -> None:
        h = self.client.get("/healthz")
        self.assertEqual(h.status_code, 200, pass_no)
        self.assertTrue(h.json().get("ok"), pass_no)
        self.assertIn(h.json().get("vpn"), ("connected", "disconnected", "error"), pass_no)
        self.assertIn(h.json().get("bridge"), ("granted", "connected", "disconnected"), pass_no)

        login = self.client.get("/login")
        self.assertEqual(login.status_code, 200, pass_no)
        body = login.text
        for token in ("MICROSOFT", "SLACK", "DISCORD", "GOOGLE", "GITHUB", "MANUAL", "selectLoginMethod"):
            self.assertIn(token, body, f"pass {pass_no} missing {token}")
        self.assertTrue(_csrf(login), pass_no)

        for path in (
            "/auth/google/start",
            "/auth/github/start",
            "/auth/discord/start",
            "/auth/slack/start",
            "/auth/microsoft/start",
            "/auth/teams/start",
        ):
            r = self.client.get(path, follow_redirects=False)
            self.assertIn(r.status_code, (302, 303), f"pass {pass_no} {path}")

        self.assertEqual(self.client.get("/api/status").status_code, 401, pass_no)

        self._login()
        dash = self.client.get("/")
        self.assertEqual(dash.status_code, 200, pass_no)
        self.assertIn("Hayabusa Controller", dash.text, pass_no)
        self.assertIn("connPipeline", dash.text, pass_no)
        self.assertIn("stepEnroll", dash.text, pass_no)
        self.assertIn("Site ZTP", dash.text, pass_no)
        self.assertIn("vpnForm", dash.text, pass_no)
        self.assertIn("Manual mesh override", dash.text, pass_no)
        self.assertIn("controller-csrf.js", dash.text, pass_no)

        ztp = self.client.get("/api/ztp/status")
        self.assertEqual(ztp.status_code, 200, pass_no)
        ifaces = self.client.get("/api/ztp/interfaces")
        self.assertEqual(ifaces.status_code, 200, pass_no)
        st = self.client.get("/api/status")
        self.assertEqual(st.status_code, 200, pass_no)
        payload = st.json()
        self.assertTrue(payload["capabilities"]["can_manual_mesh_override"], pass_no)
        self.assertIn("connection", payload, pass_no)
        self.assertIn("steps", payload["connection"], pass_no)
        self.assertIn("vpn", payload, pass_no)
        self.assertIn("health", payload["vpn"], pass_no)

        key = f"pass{pass_no}-db-password"
        put = self.client.put(
            f"/api/secrets/{key}", json={"value": f"secret-{pass_no}"}, headers=self._hdr()
        )
        self.assertEqual(put.status_code, 200, pass_no)
        got = self.client.get(f"/api/secrets/{key}")
        self.assertEqual(got.json().get("value"), f"secret-{pass_no}", pass_no)

        for kind, path, content in (
            ("ansible", f"playbooks/pass{pass_no}.yml", f"- hosts: all\n  tasks: []\n# pass {pass_no}\n"),
            ("opentofu", f"envs/pass{pass_no}/main.tf", f'terraform {{\n  required_version = ">= 1.6"\n}}\n# pass {pass_no}\n'),
        ):
            w = self.client.put(
                f"/api/iac/{kind}/file",
                json={"path": path, "content": content},
                headers=self._hdr(),
            )
            self.assertEqual(w.status_code, 200, pass_no)
            r = self.client.get(f"/api/iac/{kind}/file", params={"path": path})
            self.assertEqual(r.status_code, 200, pass_no)
            self.assertIn(f"pass {pass_no}", r.json().get("content", ""), pass_no)

        cfg = self.client.post(
            "/api/vpn/configure",
            json={
                "mesh_server": "https://mesh.example:8443",
                "preauth_key": "tskey-auth-test",
                "hostname": f"controller-pass-{pass_no}",
            },
            headers=self._hdr(),
        )
        self.assertEqual(cfg.status_code, 200, pass_no)
        join = self.client.post("/api/vpn/join", json={}, headers=self._hdr())
        self.assertEqual(join.status_code, 200, pass_no)
        self.assertTrue(join.json()["vpn"]["connected"], pass_no)
        self.assertEqual(join.json()["vpn"]["backend"], "simulated", pass_no)
        self.assertTrue(join.json()["bridge"]["granted"], pass_no)
        self.assertEqual(join.json()["connection"]["steps"]["mesh"]["state"], "ok", pass_no)

        with self.client.websocket_connect("/ws/status") as ws:
            msg = ws.receive_json()
            self.assertEqual(msg.get("type"), "status", pass_no)
            self.assertIn("connection", msg, pass_no)
            self.assertTrue(msg.get("bridge", {}).get("granted"), pass_no)
            ws.send_json({"type": "ping"})
            pong = ws.receive_json()
            self.assertIn(pong.get("type"), ("pong", "ack", "bridge", "connection"), pass_no)

    def test_pass_1(self) -> None:
        self._run_pass(1)

    def test_pass_2(self) -> None:
        self._run_pass(2)

    def test_pass_3(self) -> None:
        self._run_pass(3)

    def test_pass_4(self) -> None:
        self._run_pass(4)

    def test_pass_5(self) -> None:
        self._run_pass(5)

    def test_manual_mesh_denied_without_permission(self) -> None:
        os.environ["CONTROLLER_MANUAL_MESH_OVERRIDE_LOCAL"] = "0"
        from app import config, main
        from app.setup_store import SetupStore

        config.get_settings.cache_clear()
        settings = config.get_settings()
        main.create_app(settings)
        main.setup = SetupStore(Path(self.tmp.name))
        main.setup.mark_complete(mode="novice", completed_by="unit-test")
        client = TestClient(main.app)
        try:
            page = client.get("/login")
            tok = _csrf(page)
            r = client.post(
                "/auth/manual",
                data={
                    "admin_username": "admin",
                    "admin_password": "test-password-please-change",
                    "csrf_token": tok,
                },
                follow_redirects=False,
            )
            self.assertIn(r.status_code, (302, 303))
            self.assertEqual(r.headers.get("location"), "/")
            dash = client.get("/")
            self.assertEqual(dash.status_code, 200)
            self.assertNotIn("vpnForm", dash.text)
            self.assertIn("Manual mesh override is hidden", dash.text)
            tok2 = _csrf(dash) or tok
            denied = client.post(
                "/api/vpn/configure",
                json={"mesh_server": "https://x", "preauth_key": "k", "hostname": "h"},
                headers={"X-CSRF-Token": tok2},
            )
            self.assertEqual(denied.status_code, 403)
            self.assertEqual(denied.json().get("error"), "manual_mesh_override_denied")
        finally:
            client.close()
            os.environ["CONTROLLER_MANUAL_MESH_OVERRIDE_LOCAL"] = "1"

    def test_simulate_ignored_without_allow_flag(self) -> None:
        """Production must never soft-succeed even if CONTROLLER_VPN_MODE=simulate."""
        import asyncio

        from app.vpn import VpnClient
        from app import config

        os.environ["CONTROLLER_ALLOW_VPN_SIMULATE"] = "0"
        os.environ["CONTROLLER_VPN_MODE"] = "simulate"
        os.environ.pop("PYTEST_CURRENT_TEST", None)
        config.get_settings.cache_clear()
        settings = config.get_settings()
        client = VpnClient(settings)
        client.configure("https://mesh.example:8443", "tskey-auth-test", "deny-sim")
        st = asyncio.run(client.join_mesh())
        self.assertFalse(st.get("connected"))
        self.assertNotEqual(st.get("backend"), "simulated")
        self.assertTrue(st.get("error_code"))
        os.environ["CONTROLLER_ALLOW_VPN_SIMULATE"] = "1"

    def test_classify_errors(self) -> None:
        from app.vpn import classify_tailscale_error, ERROR_FIX

        code, _ = classify_tailscale_error("backend error: invalid key")
        self.assertEqual(code, "auth_key_rejected")
        code, _ = classify_tailscale_error("failed to connect to local tailscaled")
        self.assertEqual(code, "tailscaled_down")
        code, _ = classify_tailscale_error("dial tcp: lookup mesh.example: no such host")
        self.assertEqual(code, "login_server_unreachable")
        self.assertIn("auth_key_rejected", ERROR_FIX)

    def test_secret_key_fail_closed(self) -> None:
        from app import config

        config.get_settings.cache_clear()
        os.environ.pop("CONTROLLER_ALLOW_INSECURE_DEFAULTS", None)
        os.environ["CONTROLLER_SECRET_KEY"] = "too-short"
        with self.assertRaises(RuntimeError):
            config.Settings()
        os.environ["CONTROLLER_SECRET_KEY"] = "unit-test-controller-secret-key-32b!!"
        os.environ["CONTROLLER_LISTEN_HOST"] = "0.0.0.0"
        os.environ.pop("CONTROLLER_ALLOW_LAN_BIND", None)
        with self.assertRaises(RuntimeError):
            config.Settings()
        os.environ["CONTROLLER_ALLOW_LAN_BIND"] = "1"
        s = config.Settings()
        self.assertEqual(s.listen_host, "0.0.0.0")
        os.environ["CONTROLLER_LISTEN_HOST"] = "127.0.0.1"
        os.environ.pop("CONTROLLER_ALLOW_LAN_BIND", None)


if __name__ == "__main__":
    unittest.main()
