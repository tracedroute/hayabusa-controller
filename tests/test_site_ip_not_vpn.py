"""Site identity must be real WAN/LAN — never mesh CGNAT or overlay VPN IPs."""

from __future__ import annotations

import unittest
from unittest import mock

from app.connection_progress import public_connection_view
from app.lan import _is_cgnat_ipv4, _ok_site_ipv4, detect_lan_ipv4, resolve_public_base_url
from app.wan_public_ip import sanitize_reported_public_ip


class SiteIpNotVpnTests(unittest.TestCase):
    def test_cgnat_rejected(self) -> None:
        self.assertTrue(_is_cgnat_ipv4("100.64.0.5"))
        self.assertFalse(_ok_site_ipv4("100.64.0.5"))
        self.assertEqual(sanitize_reported_public_ip("100.64.0.5"), "")
        self.assertEqual(sanitize_reported_public_ip("178.156.169.232"), "178.156.169.232")

    def test_ok_site_prefers_real_addresses(self) -> None:
        self.assertTrue(_ok_site_ipv4("192.168.1.10", private_only=True))
        self.assertTrue(_ok_site_ipv4("178.156.169.232"))
        self.assertTrue(_ok_site_ipv4("10.1.1.1"))  # RFC1918 OK on a real LAN NIC
        self.assertFalse(_ok_site_ipv4("127.0.0.1"))
        self.assertFalse(_ok_site_ipv4("100.64.0.5"))

    def test_detect_skips_overlay_and_picks_public_on_physical(self) -> None:
        """Simulate VPS: enp1s0 has public IP; wog0/tailscale0 are overlays."""
        ip_out = (
            "2: enp1s0    inet 178.156.169.232/32 scope global enp1s0\n"
            "16: wog0     inet 10.1.1.1/24 scope global wog0\n"
            "78: tailscale0    inet 100.64.0.1/32 scope global tailscale0\n"
        )

        def fake_check_output(cmd, **kwargs):  # noqa: ANN001
            if cmd[:3] == ["ip", "-4", "-o"]:
                return ip_out
            raise AssertionError(cmd)

        with mock.patch.dict("os.environ", {"CONTROLLER_LAN_IP": ""}, clear=False):
            with mock.patch("subprocess.check_output", side_effect=fake_check_output):
                with mock.patch("socket.socket") as sock_cls:
                    sock_cls.return_value.connect.side_effect = OSError("no")
                    got = detect_lan_ipv4()
        self.assertEqual(got, "178.156.169.232")
        self.assertNotEqual(got, "10.1.1.1")
        self.assertFalse(_is_cgnat_ipv4(got or ""))

    def test_resolve_public_base_uses_real_ip(self) -> None:
        with mock.patch("app.lan.detect_lan_ipv4", return_value="178.156.169.232"):
            with mock.patch.dict(
                "os.environ",
                {
                    "CONTROLLER_PUBLIC_BASE_URL": "auto",
                    "CONTROLLER_ALLOW_LAN_BIND": "1",
                    "CONTROLLER_LISTEN_HOST": "0.0.0.0",
                },
                clear=False,
            ):
                url, auto = resolve_public_base_url(listen_port=8790, tls_enabled=True)
        self.assertTrue(auto)
        self.assertEqual(url, "https://178.156.169.232:8790")
        self.assertNotIn("100.64", url)
        self.assertNotIn("10.1.1.1", url)

    def test_connection_mesh_detail_not_site_ip(self) -> None:
        view = public_connection_view(
            {},
            enroll={"enrolled": True},
            vpn={"connected": True, "ip": "100.64.0.5"},
            bridge={"granted": True, "identity_claimed": True},
        )
        detail = view["steps"]["mesh"]["detail"]
        self.assertEqual(detail, "Mesh VPN up")
        self.assertNotIn("100.64", detail)


if __name__ == "__main__":
    unittest.main()
