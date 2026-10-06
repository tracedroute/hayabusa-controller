"""Session lifetime helpers without FastAPI TestClient (host may lack deps)."""

from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace


class _FakeSession(dict):
    def clear(self):  # type: ignore[override]
        super().clear()


class SessionHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["CONTROLLER_SECRET_KEY"] = "unit-test-controller-secret-key-32b!!"
        os.environ["CONTROLLER_DATA_DIR"] = tempfile.mkdtemp()
        os.environ["CONTROLLER_ALLOW_INSECURE_DEFAULTS"] = "1"
        os.environ["CONTROLLER_SESSION_LIFETIME_SEC"] = "120"
        os.environ["CONTROLLER_SESSION_WARN_BEFORE_SEC"] = "60"
        # Import after env is set
        from app import main as m

        self.m = m
        self.m.CONTROLLER_SESSION_LIFETIME_SEC = 120
        self.m.CONTROLLER_SESSION_WARN_BEFORE_SEC = 60

    def _req(self, sess: dict | None = None):
        return SimpleNamespace(session=sess if sess is not None else _FakeSession())

    def test_five_passes_status_warn_renew_expire(self) -> None:
        for i in range(1, 6):
            with self.subTest(pass_no=i):
                req = self._req()
                req.session["authenticated"] = True
                self.m._session_begin(req)
                st = self.m._session_status(req)
                self.assertTrue(st["ok"])
                self.assertGreater(st["remaining_sec"], 50)
                self.assertEqual(st["lifetime_sec"], 120)
                self.assertFalse(st["should_warn"])

                # Near expiry → should_warn
                req.session["_session_expires_at"] = int(time.time()) + 30
                st2 = self.m._session_status(req)
                self.assertTrue(st2["should_warn"])
                self.assertLessEqual(st2["remaining_sec"], 30)

                # Renew restores full window
                self.m._session_begin(req)
                st3 = self.m._session_status(req)
                self.assertFalse(st3["should_warn"])
                self.assertGreaterEqual(st3["remaining_sec"], 100)

                # Expired → _authed clears
                req.session["_session_expires_at"] = int(time.time()) - 1
                self.assertFalse(self.m._authed(req))
                self.assertFalse(req.session.get("authenticated"))


if __name__ == "__main__":
    unittest.main()
