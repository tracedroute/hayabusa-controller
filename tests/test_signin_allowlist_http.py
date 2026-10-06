"""HTTP checks: default-deny sign-in + admin allowlist API (3 passes)."""

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


def _csrf_from(resp) -> str:
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
    os.environ["CONTROLLER_VPN_MODE"] = "simulate"
    os.environ["CONTROLLER_ALLOW_VPN_SIMULATE"] = "1"
    os.environ["CONTROLLER_MANUAL_MESH_OVERRIDE_LOCAL"] = "1"
    os.environ["CONTROLLER_CSRF_PROTECT"] = "0"
    os.environ["CONTROLLER_ABUSE_RATE_LIMIT"] = "0"
    os.environ["CONTROLLER_SKIP_POST_LOGIN_CONNECT"] = "1"
    os.environ["CONTROLLER_LISTEN_HOST"] = "127.0.0.1"
    os.environ.pop("CONTROLLER_ALLOWED_HOSTS", None)
    os.environ.pop("TURNSTILE_SECRET_KEY", None)
    os.environ.pop("TURNSTILE_SITE_KEY", None)
    from app import config, main

    config.get_settings.cache_clear()
    settings = config.get_settings()
    settings.hayabusa_ws_url = ""
    main.create_app(settings)
    main.bridge.settings.hayabusa_ws_url = ""
    main.bridge._status["ws_url"] = ""
    from app.rbac_store import RbacStore
    from app.setup_store import SetupStore
    from app.signin_allowlist_store import SignInAllowlistStore

    main.setup = SetupStore(tmp)
    main.setup.mark_complete(mode="novice", completed_by="unit-test")
    main.signin_allowlist = SignInAllowlistStore(tmp)
    main.rbac = RbacStore(tmp)
    return TestClient(main.app)


@unittest.skipUnless(TestClient is not None, "fastapi not installed")
class SignInAllowlistHttpThreePasses(unittest.TestCase):
    def _login_manual(self, client: TestClient) -> None:
        page = client.get("/login")
        self.assertEqual(page.status_code, 200)
        r = client.post(
            "/auth/manual",
            data={
                "admin_username": "admin",
                "admin_password": "test-password-please-change",
            },
            follow_redirects=False,
        )
        self.assertIn(r.status_code, (302, 303))
        loc = r.headers.get("location") or ""
        self.assertNotIn("error=", loc, loc)
        self.assertEqual(loc, "/")

    def test_three_passes_default_deny_and_admin_whitelist(self) -> None:
        for i in range(1, 4):
            with self.subTest(pass_no=i):
                with tempfile.TemporaryDirectory() as tmpname:
                    tmp = Path(tmpname)
                    client = _build_client(tmp)
                    try:
                        from app import main

                        # Empty store: OAuth identity denied at gate
                        ok, reason = main.signin_allowlist.is_allowed(
                            provider="google",
                            email=f"pass{i}@example.com",
                            username=f"u{i}",
                            oauth_id=f"sub-{i}",
                        )
                        self.assertFalse(ok)
                        self.assertIn("whitelisted", reason)

                        # Break-glass manual login still works
                        self._login_manual(client)

                        # Admin page present with Sign-in rail
                        admin_page = client.get("/administration")
                        self.assertEqual(admin_page.status_code, 200)
                        self.assertIn("data-admin-section=\"signin\"", admin_page.text)
                        self.assertIn("Sign-in allowlist", admin_page.text)

                        # GET allowlist
                        g = client.get("/api/admin/signin-allowlist")
                        self.assertEqual(g.status_code, 200)
                        body = g.json()
                        self.assertTrue(body.get("ok"))
                        self.assertTrue(body.get("default_deny"))
                        self.assertIn("google", body.get("platforms") or {})

                        # Whitelist specific google email
                        email = f"allowed{i}@example.com"
                        p = client.post(
                            "/api/admin/signin-allowlist",
                            json={
                                "platforms": {
                                    "google": {
                                        "emails": [email],
                                        "usernames": [],
                                        "user_ids": [],
                                    }
                                }
                            },
                        )
                        self.assertEqual(p.status_code, 200)
                        self.assertTrue(p.json().get("ok"))

                        ok2, why2 = main.signin_allowlist.is_allowed(
                            provider="google",
                            email=email,
                            username="",
                            oauth_id="",
                        )
                        self.assertTrue(ok2, why2)

                        denied, _ = main.signin_allowlist.is_allowed(
                            provider="google",
                            email=f"other{i}@example.com",
                            username="",
                            oauth_id="",
                        )
                        self.assertFalse(denied)

                        # Simulate finish_login redirect for non-whitelisted oauth
                        # by invoking the gate the same way _finish_login does
                        allowed, msg = main.signin_allowlist.is_allowed(
                            provider="github",
                            email=email,
                            username="ghuser",
                            oauth_id="1",
                        )
                        self.assertFalse(allowed)
                        self.assertTrue(msg)

                        # Persist file on disk
                        self.assertTrue((tmp / "signin_allowlist.json").is_file())
                    finally:
                        client.close()


if __name__ == "__main__":
    unittest.main()
