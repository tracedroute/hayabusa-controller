"""First-boot one-time password → SSO admin claim with 2FA.

Store-level tests run without FastAPI. HTTP tests skip if fastapi is missing
(install controller-hotfixes/requirements.txt into a venv first).
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch


class AuthSettingsStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        from app.auth_settings_store import AuthSettingsStore

        self.store = AuthSettingsStore(Path(self.tmp.name))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_mark_sso_admin_claimed(self) -> None:
        self.store.set_needs_sso_admin(True, updated_by="boot")
        self.assertTrue(self.store.needs_sso_admin())
        out = self.store.mark_sso_admin_claimed(updated_by="owner@example.com")
        self.assertFalse(out.get("needs_sso_admin"))
        self.assertFalse(out.get("local_password_login_enabled"))
        self.assertTrue(out.get("require_2fa"))
        self.assertFalse(self.store.needs_sso_admin())

    def test_require_2fa_toggle(self) -> None:
        self.store.set_require_2fa(False, updated_by="admin")
        self.assertFalse(self.store.require_2fa())
        self.store.set_require_2fa(True, updated_by="admin")
        self.assertTrue(self.store.require_2fa())

    def test_migrate_must_change_to_needs_sso(self) -> None:
        path = Path(self.tmp.name) / "state" / "auth_settings.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            '{"version":1,"local_password_login_enabled":true,"must_change_password":true}\n',
            encoding="utf-8",
        )
        from app.auth_settings_store import AuthSettingsStore

        store = AuthSettingsStore(Path(self.tmp.name))
        self.assertTrue(store.needs_sso_admin())


class SignInAddIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        from app.signin_allowlist_store import SignInAllowlistStore

        self.store = SignInAllowlistStore(Path(self.tmp.name))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_add_identity_then_allow(self) -> None:
        out = self.store.add_identity(
            provider="github",
            email="dev@example.com",
            username="octocat",
            oauth_id="42",
            updated_by="claim",
        )
        self.assertTrue(out.get("ok"))
        ok, why = self.store.is_allowed(
            provider="github",
            email="dev@example.com",
            username="octocat",
            oauth_id="42",
        )
        self.assertTrue(ok)
        self.assertTrue(why)


class FinishLoginClaimLogicTests(unittest.TestCase):
    """Exercise _finish_login claim/MFA gates without spinning HTTP if possible."""

    def setUp(self) -> None:
        try:
            import fastapi  # noqa: F401
        except ImportError:
            self.skipTest("fastapi not installed — use controller venv / pip install -r requirements.txt")
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ["CONTROLLER_SECRET_KEY"] = "unit-test-controller-secret-key-32b!!"
        os.environ["CONTROLLER_MANUAL_USERNAME"] = "admin"
        os.environ["CONTROLLER_MANUAL_PASSWORD"] = "bootstrap-once-password"
        os.environ["CONTROLLER_DATA_DIR"] = str(self.root)
        os.environ["HAYABUSA_MESH_SERVER_URL"] = "https://mesh.example:8443"
        os.environ["HAYABUSA_PREAUTH_KEY"] = "tskey-auth-test"
        os.environ["CONTROLLER_VPN_MODE"] = "simulate"
        os.environ["CONTROLLER_ALLOW_VPN_SIMULATE"] = "1"
        os.environ["CONTROLLER_MANUAL_MESH_OVERRIDE_LOCAL"] = "1"
        os.environ["CONTROLLER_CSRF_PROTECT"] = "0"
        os.environ["CONTROLLER_SKIP_POST_LOGIN_CONNECT"] = "1"
        os.environ["CONTROLLER_LISTEN_HOST"] = "127.0.0.1"
        os.environ["CONTROLLER_OAUTH_MODE"] = "local"
        os.environ.pop("TURNSTILE_SECRET_KEY", None)
        os.environ.pop("TURNSTILE_SITE_KEY", None)

        from app import config, main
        from app.auth_settings_store import AuthSettingsStore
        from app.signin_allowlist_store import SignInAllowlistStore

        config.get_settings.cache_clear()
        settings = config.get_settings()
        settings.hayabusa_ws_url = ""
        settings.manual_password = "bootstrap-once-password"
        main.create_app(settings)
        main.bridge.settings.hayabusa_ws_url = ""
        main.bridge._status["ws_url"] = ""
        main.auth_settings = AuthSettingsStore(self.root)
        main.signin_allowlist = SignInAllowlistStore(self.root)
        main.auth_settings.set_needs_sso_admin(True, updated_by="test")
        main.auth_settings.set_local_password_enabled(True, updated_by="test")
        main.auth_settings.set_require_2fa(True, updated_by="test")
        self.main = main

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _req(self, session: dict):
        from starlette.requests import Request

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 123),
            "server": ("test", 80),
            "session": session,
        }
        return Request(scope)

    def test_claim_requires_mfa(self) -> None:
        async def _run() -> str:
            resp = await self.main._finish_login(
                self._req({"claim_sso_admin": True}),
                username="octocat",
                email="dev@example.com",
                provider="github",
                sub="99",
                mfa_ok=False,
                mfa_checked=True,
            )
            return str(resp.headers.get("location") or "")

        loc = asyncio.run(_run())
        self.assertIn("claim-admin", loc)
        self.assertTrue(self.main.auth_settings.needs_sso_admin())

    def test_claim_with_mfa_allowlists(self) -> None:
        async def _run() -> str:
            with patch.object(self.main, "_session_begin", lambda *_a, **_k: None):
                with patch.object(self.main, "_liability_require_on_login", lambda *_a, **_k: None):
                    with patch.object(self.main.bridge, "send_event", new=AsyncMock(return_value=True)):
                        resp = await self.main._finish_login(
                            self._req({"claim_sso_admin": True}),
                            username="octocat",
                            email="dev@example.com",
                            provider="github",
                            sub="99",
                            mfa_ok=True,
                            mfa_checked=True,
                        )
            return str(resp.headers.get("location") or "")

        loc = asyncio.run(_run())
        self.assertFalse(self.main.auth_settings.needs_sso_admin())
        ok, _ = self.main.signin_allowlist.is_allowed(
            provider="github",
            email="dev@example.com",
            username="octocat",
            oauth_id="99",
        )
        self.assertTrue(ok)
        self.assertNotIn("claim-admin", loc)

    def test_require_2fa_blocks_later_signin(self) -> None:
        self.main.auth_settings.mark_sso_admin_claimed(updated_by="seed")
        self.main.auth_settings.set_require_2fa(True, updated_by="seed")
        self.main.signin_allowlist.add_identity(
            provider="discord",
            email="u@example.com",
            username="user",
            oauth_id="1",
            updated_by="seed",
        )

        async def _run() -> str:
            resp = await self.main._finish_login(
                self._req({}),
                username="user",
                email="u@example.com",
                provider="discord",
                sub="1",
                mfa_ok=False,
                mfa_checked=True,
            )
            return str(resp.headers.get("location") or "")

        loc = asyncio.run(_run())
        self.assertIn("/login", loc)
        self.assertIn("error=", loc)


class GitopsWebhookHardenTests(unittest.TestCase):
    def test_verify_rejects_weak_secret(self) -> None:
        root = Path("/home/swoopingbird/hayabusa/peregrine-src")
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        import hayabusa_gitops_agent as agent

        self.assertFalse(agent.verify_gitlab_token("abcdefghijklmnop", "short"))
        self.assertFalse(agent.verify_github_signature(b"{}", "sha256=abc", ""))
        secret = "sixteen-chars-ok!"
        self.assertTrue(agent.verify_gitlab_token(secret, secret))

    def test_redact_and_rate_limit(self) -> None:
        root = Path("/home/swoopingbird/hayabusa/peregrine-src")
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        import hayabusa_gitops_agent as agent

        token = "ghp_supersecrettokenvalue"
        red = agent._redact_secret(f"fatal: {token} rejected", token)
        self.assertNotIn(token, red)
        self.assertIn("***", red)

        ip = "203.0.113.50"
        agent._WEBHOOK_HITS.pop(ip, None)
        for _ in range(min(agent._WEBHOOK_MAX_PER_MIN, 5)):
            self.assertTrue(agent._webhook_rate_allow(ip))
        agent._WEBHOOK_HITS[ip] = [__import__("time").time()] * agent._WEBHOOK_MAX_PER_MIN
        self.assertFalse(agent._webhook_rate_allow(ip))
        agent._WEBHOOK_HITS.pop(ip, None)


if __name__ == "__main__":
    unittest.main()
