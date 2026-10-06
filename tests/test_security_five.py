"""Five-pass verification for controller CSRF, rate limits, headers, path safety."""

from __future__ import annotations

import os
import re
import tempfile
import unittest
import urllib.parse
from pathlib import Path

try:
    from fastapi.testclient import TestClient
except ImportError:  # pragma: no cover
    TestClient = None  # type: ignore[misc, assignment]


def _csrf_from(resp) -> str:
    tok = resp.headers.get("x-csrf-token") or resp.headers.get("X-CSRF-Token") or ""
    if tok:
        return tok
    m = re.search(r'name="csrf-token"\s+content="([^"]+)"', resp.text or "")
    return m.group(1) if m else ""


def _build_client(tmp: Path, **extra_env: str) -> TestClient:
    os.environ["CONTROLLER_SECRET_KEY"] = "unit-test-controller-secret-key-32b!!"
    os.environ["CONTROLLER_MANUAL_USERNAME"] = "admin"
    os.environ["CONTROLLER_MANUAL_PASSWORD"] = "test-password-please-change"
    os.environ["CONTROLLER_DATA_DIR"] = str(tmp)
    os.environ["HAYABUSA_MESH_SERVER_URL"] = "https://mesh.example:8443"
    os.environ["HAYABUSA_PREAUTH_KEY"] = "tskey-auth-test"
    os.environ["CONTROLLER_VPN_MODE"] = "simulate"
    os.environ["CONTROLLER_ALLOW_VPN_SIMULATE"] = "1"
    os.environ["CONTROLLER_MANUAL_MESH_OVERRIDE_LOCAL"] = "1"
    os.environ["CONTROLLER_CSRF_PROTECT"] = "1"
    os.environ["CONTROLLER_ABUSE_RATE_LIMIT"] = "1"
    os.environ["CONTROLLER_SKIP_POST_LOGIN_CONNECT"] = "1"
    os.environ["CONTROLLER_LISTEN_HOST"] = "127.0.0.1"
    os.environ.pop("CONTROLLER_ALLOWED_HOSTS", None)
    os.environ.pop("TURNSTILE_SECRET_KEY", None)
    os.environ.pop("TURNSTILE_SITE_KEY", None)
    for k, v in extra_env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    from app import config, main
    from app.setup_store import SetupStore

    config.get_settings.cache_clear()
    settings = config.get_settings()
    settings.hayabusa_ws_url = ""
    main.create_app(settings)
    main.bridge.settings.hayabusa_ws_url = ""
    main.bridge._status["ws_url"] = ""
    # HTTP passes exercise auth/CSRF on a finished controller, not /setup.
    main.setup = SetupStore(tmp)
    main.setup.mark_complete(mode="novice", completed_by="unit-test")
    return TestClient(main.app)


@unittest.skipUnless(TestClient is not None, "fastapi not installed")
class ControllerSecurityFivePasses(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.client = _build_client(Path(self.tmp.name))

    def tearDown(self) -> None:
        self.client.close()
        self.tmp.cleanup()

    def _login(self) -> str:
        page = self.client.get("/login")
        self.assertEqual(page.status_code, 200)
        csrf = _csrf_from(page)
        self.assertTrue(csrf, "csrf missing on login")
        r = self.client.post(
            "/auth/manual",
            data={
                "admin_username": "admin",
                "admin_password": "test-password-please-change",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        self.assertIn(r.status_code, (302, 303))
        self.assertEqual(r.headers.get("location"), "/")
        # Session CSRF may rotate / stay; prefer response header after login redirect follow.
        dash = self.client.get("/")
        return _csrf_from(dash) or csrf

    def _run_pass(self, pass_no: int) -> None:
        h = self.client.get("/healthz")
        self.assertEqual(h.status_code, 200, pass_no)
        self.assertTrue(h.json().get("ok"), pass_no)
        self.assertIn("x-content-type-options", {k.lower() for k in h.headers.keys()}, pass_no)

        login = self.client.get("/login")
        self.assertEqual(login.status_code, 200, pass_no)
        csrf = _csrf_from(login)
        self.assertTrue(csrf, f"pass {pass_no} csrf")
        self.assertIn('name="csrf-token"', login.text, pass_no)
        self.assertIn("controller-csrf.js", login.text, pass_no)

        # Mutating without CSRF must fail.
        denied = self.client.post(
            "/auth/manual",
            data={"admin_username": "admin", "admin_password": "test-password-please-change"},
            follow_redirects=False,
        )
        self.assertIn(denied.status_code, (302, 403), pass_no)
        if denied.status_code == 302:
            self.assertIn("CSRF", denied.headers.get("location", ""), pass_no)

        csrf = _csrf_from(self.client.get("/login"))
        bad = self.client.put(
            "/api/secrets/nope",
            json={"value": "x"},
            headers={"X-CSRF-Token": "definitely-not-a-valid-csrf-token-value"},
        )
        self.assertEqual(bad.status_code, 403, pass_no)
        self.assertEqual(bad.json().get("error"), "csrf_failed", pass_no)

        tok = self._login()
        key = f"sec-pass{pass_no}"
        put = self.client.put(
            f"/api/secrets/{key}",
            json={"value": f"v-{pass_no}"},
            headers={"X-CSRF-Token": tok},
        )
        self.assertEqual(put.status_code, 200, pass_no)
        got = self.client.get(f"/api/secrets/{key}")
        self.assertEqual(got.json().get("value"), f"v-{pass_no}", pass_no)

        # ZTP fetch path traversal blocked.
        trav = self.client.get("/ztp/fetch/../../etc/passwd")
        self.assertIn(trav.status_code, (404, 400, 403), pass_no)

        # devops escape
        from app import main as m

        bad_path = m.devops.read_file("../etc/passwd")
        self.assertFalse(bad_path.get("ok"), pass_no)

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

    def test_login_rate_limit(self) -> None:
        from app import security as sec

        self.client.close()
        self.tmp.cleanup()
        self.tmp = tempfile.TemporaryDirectory()
        self.client = _build_client(
            Path(self.tmp.name),
            CONTROLLER_ABUSE_LIMIT_LOGIN_POST="2",
            CONTROLLER_ABUSE_WINDOW_LOGIN_POST="300",
        )
        # Direct bucket check (portable; does not depend on redirect wording).
        ok1, _ = sec.check_ip_rate_limit("login_post", "1.2.3.4")
        ok2, _ = sec.check_ip_rate_limit("login_post", "1.2.3.4")
        ok3, msg3 = sec.check_ip_rate_limit("login_post", "1.2.3.4")
        self.assertTrue(ok1)
        self.assertTrue(ok2)
        self.assertFalse(ok3)
        self.assertIn("Too many", msg3 or "")

        csrf = _csrf_from(self.client.get("/login"))
        locs: list[str] = []
        for _ in range(4):
            r = self.client.post(
                "/auth/manual",
                data={
                    "admin_username": "admin",
                    "admin_password": "wrong-password",
                    "csrf_token": csrf,
                },
                follow_redirects=False,
            )
            locs.append(urllib.parse.unquote(r.headers.get("location") or ""))
            csrf = _csrf_from(self.client.get("/login"))
        self.assertTrue(
            any("Too many" in loc or "rate limited" in loc.lower() for loc in locs),
            f"expected rate-limit redirect, got {locs}",
        )

    def test_trusted_host_enforced_when_set(self) -> None:
        # TrustedHost is installed at import time from env — rebuild via fresh process not practical.
        # Unit-check helper instead.
        from app import security as sec

        os.environ["CONTROLLER_ALLOWED_HOSTS"] = "controller.lan,localhost"
        self.assertEqual(sec.allowed_hosts(), ["controller.lan", "localhost"])
        os.environ.pop("CONTROLLER_ALLOWED_HOSTS", None)
        self.assertIsNone(sec.allowed_hosts())


if __name__ == "__main__":
    unittest.main()
