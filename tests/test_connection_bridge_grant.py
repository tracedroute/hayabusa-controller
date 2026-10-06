"""Connection tab: mesh IP alone is never fully connected / ready."""

from __future__ import annotations

import unittest

from app.connection_progress import enrich_connection_steps, phase_from_steps, public_connection_view


class ConnectionBridgeGrantTests(unittest.TestCase):
    def test_mesh_ip_alone_not_ready(self) -> None:
        view = public_connection_view(
            {"phase": "ready", "steps": {"enroll": {"state": "ok", "detail": "x"}, "mesh": {"state": "ok", "detail": "100.64.0.6"}, "bridge": {"state": "ok", "detail": "stale"}}},
            enroll={"enrolled": True, "ok": True},
            vpn={"connected": True, "ip": "100.64.0.6", "health": "connected"},
            bridge={"granted": False, "connected": False},
        )
        self.assertFalse(view["ready"])
        self.assertFalse(view["linked"])
        self.assertFalse(view["bridge_granted"])
        self.assertTrue(view["mesh_connected"])
        self.assertEqual(view["steps"]["mesh"]["state"], "ok")
        self.assertEqual(view["steps"]["mesh"]["detail"], "Mesh VPN up")
        self.assertNotIn("100.64", view["steps"]["mesh"]["detail"])
        self.assertIn("not granted", view["steps"]["bridge"]["detail"].lower())
        self.assertEqual(view["steps"]["bridge"]["state"], "pending")
        self.assertNotEqual(view["phase"], "ready")

    def test_ready_requires_bridge_grant(self) -> None:
        view = public_connection_view(
            {"phase": "idle", "steps": {}},
            enroll={"enrolled": True},
            vpn={"connected": True, "ip": "100.64.0.9"},
            bridge={"granted": True, "connected": True},
        )
        self.assertEqual(view["phase"], "ready")
        self.assertTrue(view["ready"])
        self.assertTrue(view["linked"])
        self.assertEqual(view["steps"]["bridge"]["state"], "ok")

    def test_enrich_does_not_leave_bridge_idle_when_mesh_up(self) -> None:
        steps = enrich_connection_steps(
            {"enroll": {"state": "idle", "detail": ""}, "mesh": {"state": "idle", "detail": ""}, "bridge": {"state": "idle", "detail": ""}},
            enroll={"enrolled": True},
            vpn={"connected": True, "ip": "100.64.0.1"},
            bridge={"granted": False, "connected": False},
        )
        self.assertEqual(steps["enroll"]["state"], "ok")
        self.assertEqual(steps["mesh"]["state"], "ok")
        self.assertEqual(steps["bridge"]["state"], "pending")
        self.assertEqual(phase_from_steps(steps), "bridge_running")

    def test_stale_ready_tracker_cleared_without_grant(self) -> None:
        steps = enrich_connection_steps(
            {
                "enroll": {"state": "ok", "detail": "Enrolled"},
                "mesh": {"state": "ok", "detail": "Connected"},
                "bridge": {"state": "ok", "detail": "Granted"},
            },
            enroll={"enrolled": True},
            vpn={"connected": True, "ip": "100.64.0.2"},
            bridge={"granted": False, "connected": False},
        )
        self.assertEqual(steps["bridge"]["state"], "pending")
        self.assertNotEqual(phase_from_steps(steps), "ready")


    def test_unclaimed_boot_grant_not_ready(self) -> None:
        view = public_connection_view(
            {},
            enroll={"enrolled": True},
            vpn={"connected": True, "ip": "100.64.0.6"},
            bridge={
                "granted": True,
                "connected": True,
                "identity_claimed": False,
                "owner_key": "boot",
            },
        )
        self.assertFalse(view["ready"])
        self.assertFalse(view["linked"])
        self.assertEqual(view["steps"]["bridge"]["state"], "pending")
        self.assertIn("claim", view["steps"]["bridge"]["detail"].lower())

    def test_live_mesh_clears_stale_mesh_failed_step(self) -> None:
        """Pass: recovered Tailscale must not keep advertising Mesh join failed."""
        view = public_connection_view(
            {
                "steps": {
                    "enroll": {"state": "ok", "detail": "Enrolled"},
                    "mesh": {"state": "failed", "detail": "Mesh join failed"},
                    "bridge": {"state": "ok", "detail": "Granted"},
                }
            },
            enroll={"enrolled": True, "ok": True},
            vpn={"connected": True, "ip": "100.64.0.7", "error": "", "error_code": ""},
            bridge={"granted": True, "connected": True, "identity_claimed": True},
        )
        self.assertEqual(view["steps"]["mesh"]["state"], "ok")
        self.assertEqual(view["steps"]["mesh"]["detail"], "Mesh VPN up")
        self.assertEqual(view["phase"], "ready")
        self.assertTrue(view["ready"])


if __name__ == "__main__":
    unittest.main()
