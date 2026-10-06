"""Default-deny sign-in allowlist (per platform)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.signin_allowlist_store import SignInAllowlistStore, default_allowlist


class SignInAllowlistStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = SignInAllowlistStore(self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_default_deny_empty_platform(self) -> None:
        allowed, reason = self.store.is_allowed(
            provider="google",
            email="anyone@example.com",
            username="anyone",
            oauth_id="sub-1",
        )
        self.assertFalse(allowed)
        self.assertIn("no identities are whitelisted", reason)

    def test_unknown_platform_denied(self) -> None:
        allowed, reason = self.store.is_allowed(provider="myspace", email="a@b.c")
        self.assertFalse(allowed)
        self.assertIn("Unknown", reason)

    def test_email_whitelist_google(self) -> None:
        self.store.save(
            {
                "google": {
                    "emails": ["Admin@Example.COM"],
                    "usernames": [],
                    "user_ids": [],
                }
            },
            updated_by="admin",
        )
        ok, why = self.store.is_allowed(
            provider="google",
            email="admin@example.com",
            username="other",
            oauth_id="x",
        )
        self.assertTrue(ok)
        self.assertIn("email", why)

        denied, _ = self.store.is_allowed(
            provider="google",
            email="intruder@example.com",
            username="admin",
            oauth_id="x",
        )
        self.assertFalse(denied)

    def test_github_username_and_teams_alias(self) -> None:
        self.store.save(
            {
                "github": {"emails": [], "usernames": ["octocat"], "user_ids": []},
                "microsoft": {"emails": ["ms@corp.example"], "usernames": [], "user_ids": []},
            }
        )
        ok_gh, _ = self.store.is_allowed(provider="github", username="OctoCat", email="")
        self.assertTrue(ok_gh)
        ok_ms, _ = self.store.is_allowed(
            provider="teams",
            email="ms@corp.example",
            username="",
            oauth_id="",
        )
        self.assertTrue(ok_ms)

    def test_user_id_whitelist_and_persistence(self) -> None:
        self.store.save(
            {
                "discord": {
                    "emails": [],
                    "usernames": [],
                    "user_ids": ["1234567890"],
                }
            },
            updated_by="owner",
        )
        path = self.root / "signin_allowlist.json"
        self.assertTrue(path.is_file())
        # Reload from disk
        again = SignInAllowlistStore(self.root)
        ok, why = again.is_allowed(
            provider="discord",
            email="",
            username="",
            oauth_id="1234567890",
        )
        self.assertTrue(ok)
        self.assertIn("user id", why)
        data = again.get()
        self.assertTrue(data.get("default_deny"))
        self.assertEqual(data.get("updated_by"), "owner")

    def test_platform_isolation(self) -> None:
        self.store.save(
            {
                "slack": {"emails": ["ok@slack.example"], "usernames": [], "user_ids": []},
            }
        )
        ok_slack, _ = self.store.is_allowed(provider="slack", email="ok@slack.example")
        self.assertTrue(ok_slack)
        denied_gh, reason = self.store.is_allowed(
            provider="github", email="ok@slack.example"
        )
        self.assertFalse(denied_gh)
        self.assertIn("github", reason)

    def test_three_full_passes(self) -> None:
        """Run the core default-deny + whitelist cycle three times as requested."""
        for i in range(1, 4):
            with self.subTest(pass_no=i):
                store = SignInAllowlistStore(self.root / f"pass{i}")
                # Empty → deny
                a0, _ = store.is_allowed(
                    provider="google", email=f"u{i}@ex.com", username=f"u{i}"
                )
                self.assertFalse(a0)
                # Whitelist email → allow
                store.save(
                    {
                        "google": {
                            "emails": [f"u{i}@ex.com"],
                            "usernames": [],
                            "user_ids": [],
                        },
                        "totp": {
                            "emails": [],
                            "usernames": [f"totp-user-{i}"],
                            "user_ids": [],
                        },
                    },
                    updated_by=f"admin-{i}",
                )
                a1, _ = store.is_allowed(provider="google", email=f"u{i}@ex.com")
                self.assertTrue(a1)
                a2, _ = store.is_allowed(
                    provider="totp", username=f"totp-user-{i}", email=""
                )
                self.assertTrue(a2)
                # Other identity still denied on google
                a3, _ = store.is_allowed(provider="google", email=f"nope{i}@ex.com")
                self.assertFalse(a3)
                # Empty microsoft still default-deny
                a4, _ = store.is_allowed(
                    provider="microsoft", email=f"u{i}@ex.com"
                )
                self.assertFalse(a4)
                # Clear platform → deny again
                store.save(
                    {
                        "google": {"emails": [], "usernames": [], "user_ids": []},
                    }
                )
                a5, reason = store.is_allowed(provider="google", email=f"u{i}@ex.com")
                self.assertFalse(a5)
                self.assertIn("whitelisted", reason)

    def test_default_allowlist_shape(self) -> None:
        base = default_allowlist()
        self.assertTrue(base["default_deny"])
        for name in (
            "google",
            "github",
            "discord",
            "slack",
            "microsoft",
            "totp",
            "manual",
        ):
            self.assertIn(name, base["platforms"])
            self.assertEqual(base["platforms"][name]["emails"], [])


if __name__ == "__main__":
    unittest.main()
