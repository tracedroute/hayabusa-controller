"""Tailscale/Headscale VPN client for the user's Hayabusa mesh."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .config import Settings

logger = logging.getLogger("hayabusa-controller.vpn")

# Short codes → operator-facing fix text shown on the controller dashboard.
ERROR_FIX: dict[str, str] = {
    "missing_credentials": "Enroll with Hayabusa first, or paste a mesh server URL and preauth key (if permitted).",
    "no_tailscale_binary": "Rebuild/redeploy the controller image with Tailscale installed.",
    "tun_missing": "Run the controller with /dev/net/tun mounted and NET_ADMIN capability.",
    "tailscaled_down": "Ensure entrypoint started tailscaled (check /var/log/tailscaled.log).",
    "login_server_unreachable": "Check DNS/firewall from this host to the Headscale login server URL.",
    "auth_key_rejected": "Re-enroll to mint a fresh preauth key, or paste a valid unused key.",
    "join_timeout": "Retry enroll; if it persists, check Headscale health on Hayabusa.",
    "join_failed": "See detail below; re-enroll after fixing the underlying Tailscale error.",
    "preflight_failed": "Fix the preflight item, then Enroll & connect again.",
    "not_connected": "Mesh is down — use Enroll & connect.",
}


def vpn_simulate_allowed() -> bool:
    """Simulate is test-only. Production images never soft-succeed a join."""
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return True
    return (os.environ.get("CONTROLLER_ALLOW_VPN_SIMULATE") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _ts_socket() -> str:
    """Socket path for this appliance's tailscaled (never the collocated hub's)."""
    return (
        os.environ.get("TS_SOCKET")
        or os.environ.get("TAILSCALE_SOCKET")
        or "/var/run/tailscale/controller.sock"
    ).strip()


def _ts_cmd(*args: str) -> list[str]:
    """Build a `tailscale` CLI argv that always targets our daemon socket."""
    cmd = ["tailscale"]
    sock = _ts_socket()
    if sock:
        cmd.extend(["--socket", sock])
    cmd.extend(args)
    return cmd


def classify_tailscale_error(raw: str) -> tuple[str, str]:
    """Return (error_code, human message) from tailscale stderr/stdout."""
    text = (raw or "").strip()
    low = text.lower()
    if not text:
        return "join_failed", "Mesh join failed with no error output"
    if any(x in low for x in ("invalid key", "authkey", "unauthorized", "401", "403", "expired")):
        return "auth_key_rejected", "Preauth / auth key was rejected or expired"
    if any(x in low for x in ("no such file", "connection refused", "not running", "failed to connect to local")):
        return "tailscaled_down", "tailscaled is not running or the control socket is missing"
    if any(x in low for x in ("operation not permitted", "tun", "device or resource busy", "cannot create tun")):
        return "tun_missing", "TUN device unavailable — mount /dev/net/tun and grant NET_ADMIN"
    if any(x in low for x in ("no route", "network is unreachable", "i/o timeout", "temporary failure", "dial tcp", "lookup ")):
        return "login_server_unreachable", "Cannot reach the mesh login server"
    return "join_failed", text[:400]


class VpnClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.state_path = settings.state_dir / "vpn_status.json"
        self._status: dict[str, Any] = {
            "connected": False,
            "backend": "tailscale",
            "hostname": settings.controller_mesh_hostname,
            "mesh_server": settings.hayabusa_mesh_server_url or "",
            "ip": "",
            "error": "",
            "error_code": "",
            "fix": "",
            "phase": "idle",
            "last_action": "idle",
            "preflight": {},
        }
        self._load()

    def _load(self) -> None:
        if self.state_path.is_file():
            try:
                data = json.loads(self.state_path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self._status.update(data)
            except (OSError, json.JSONDecodeError):
                pass

    def _save(self) -> None:
        self.settings.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(self._status, indent=2), encoding="utf-8")

    def health_state(self) -> str:
        """connected | disconnected | error — for /healthz and ops."""
        st = self.status()
        if st.get("connected"):
            return "connected"
        if st.get("error") or st.get("error_code"):
            return "error"
        return "disconnected"

    def status(self) -> dict[str, Any]:
        # Refresh IP if possible (never invent one). Stale "connected" from disk
        # is cleared when Tailscale cannot report an address.
        if self._status.get("backend") == "simulated":
            out = dict(self._status)
            out["health"] = "connected" if out.get("connected") else "disconnected"
            return out
        if shutil.which("tailscale"):
            try:
                ip = subprocess.check_output(
                    _ts_cmd("ip", "-4"),
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=5,
                ).strip().splitlines()[0]
                if ip:
                    cleared = bool(self._status.get("error") or self._status.get("error_code") or not self._status.get("connected"))
                    self._status["ip"] = ip
                    self._status["connected"] = True
                    self._status["error"] = ""
                    self._status["error_code"] = ""
                    self._status["fix"] = ""
                    self._status["phase"] = "joined"
                    # Persist recovery so SSR/disk never re-surfaces a stale join failure.
                    if cleared:
                        try:
                            self._save()
                        except OSError:
                            pass
                else:
                    self._status["connected"] = False
                    self._status["ip"] = ""
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, IndexError, OSError):
                if self._status.get("connected"):
                    self._status["connected"] = False
                    self._status["ip"] = ""
                    if not self._status.get("error"):
                        self._fail_fields("not_connected", "tailscale is not connected (no mesh IP)")
        elif self._status.get("connected"):
            self._status["connected"] = False
            self._status["ip"] = ""
            if not self._status.get("error"):
                self._fail_fields("no_tailscale_binary", "tailscale binary not found")
        out = dict(self._status)
        # Live mesh IP wins over any leftover error fields from a prior failed join.
        if out.get("connected") and out.get("ip"):
            out["error"] = ""
            out["error_code"] = ""
            out["fix"] = ""
            out["health"] = "connected"
        else:
            out["health"] = self._health_from(out)
        if out.get("error_code") and not out.get("fix"):
            out["fix"] = ERROR_FIX.get(str(out["error_code"]), "")
        return out

    @staticmethod
    def _health_from(st: dict[str, Any]) -> str:
        if st.get("connected"):
            return "connected"
        if st.get("error") or st.get("error_code"):
            return "error"
        return "disconnected"

    def _fail_fields(self, code: str, message: str) -> None:
        self._status["error_code"] = code
        self._status["error"] = message
        self._status["fix"] = ERROR_FIX.get(code, "")

    def configure(self, mesh_server: str, preauth_key: str, hostname: str | None = None) -> dict[str, Any]:
        mesh_server = (mesh_server or "").strip().rstrip("/")
        preauth_key = (preauth_key or "").strip()
        if hostname:
            self.settings.controller_mesh_hostname = hostname.strip() or self.settings.controller_mesh_hostname
        self._status["mesh_server"] = mesh_server
        self._status["hostname"] = self.settings.controller_mesh_hostname
        if mesh_server:
            os.environ["HAYABUSA_MESH_SERVER_URL"] = mesh_server
        if preauth_key:
            os.environ["HAYABUSA_PREAUTH_KEY"] = preauth_key
        self.settings.hayabusa_mesh_server_url = mesh_server or self.settings.hayabusa_mesh_server_url
        self.settings.hayabusa_preauth_key = preauth_key or self.settings.hayabusa_preauth_key
        self._status["last_action"] = "configured"
        self._status["error"] = ""
        self._status["error_code"] = ""
        self._status["fix"] = ""
        self._status["phase"] = "configured"
        self._save()
        return self.status()

    def _fail(self, code: str, message: str, *, server: str = "", detail: str = "") -> dict[str, Any]:
        msg = (message or "mesh join failed").strip()[:800]
        self._status["connected"] = False
        self._status["ip"] = ""
        self._fail_fields(code, msg)
        if detail:
            self._status["error"] = f"{msg}: {detail[:400]}"
        self._status["backend"] = "tailscale"
        self._status["last_action"] = "join_failed"
        self._status["phase"] = "failed"
        if server:
            self._status["mesh_server"] = server
        self._status.pop("simulate_reason", None)
        self._save()
        logger.warning("mesh join failed [%s]: %s", code, self._status.get("error"))
        return self.status()

    def preflight(self, server: str = "") -> dict[str, Any]:
        """Fast checks before tailscale up — fail early with a clear code."""
        server = (server or self.settings.hayabusa_mesh_server_url or self._status.get("mesh_server") or "").strip()
        sock = _ts_socket()
        checks: dict[str, Any] = {
            "tailscale_binary": bool(shutil.which("tailscale")),
            "tun_present": Path("/dev/net/tun").exists(),
            "tailscaled_socket": Path(sock).exists() if sock else False,
            "login_server_reachable": None,
            "login_server": server or "",
        }
        ok = True
        code = ""
        message = ""
        if not checks["tailscale_binary"]:
            ok = False
            code = "no_tailscale_binary"
            message = "tailscale binary not found on this controller"
        elif not checks["tun_present"] and not self._userspace_ok():
            # userspace-networking can work without tun char device in some setups,
            # but entrypoint prefers tun; still warn as hard fail for clarity.
            ok = False
            code = "tun_missing"
            message = "/dev/net/tun is missing — mount it into the container"
        elif not checks["tailscaled_socket"]:
            ok = False
            code = "tailscaled_down"
            message = f"tailscaled socket missing ({sock})"
        elif server:
            reachable = self._probe_login_server(server)
            checks["login_server_reachable"] = reachable
            if not reachable:
                ok = False
                code = "login_server_unreachable"
                message = f"Cannot reach mesh login server {server}"
        else:
            checks["login_server_reachable"] = None

        result = {"ok": ok, "error_code": code, "error": message, "fix": ERROR_FIX.get(code, ""), "checks": checks}
        self._status["preflight"] = result
        return result

    @staticmethod
    def _userspace_ok() -> bool:
        # entrypoint uses --tun=userspace-networking when tun exists; without tun we fail.
        return False

    @staticmethod
    def _probe_login_server(server: str, timeout: float = 3.0) -> bool:
        """TCP reachability including DNS, hard-capped so joins never hang on resolve."""
        import concurrent.futures

        def _do() -> bool:
            parsed = urlparse(server if "://" in server else f"https://{server}")
            host = parsed.hostname
            if not host:
                return False
            port = parsed.port or (443 if (parsed.scheme or "https") == "https" else 80)
            with socket.create_connection((host, int(port)), timeout=timeout):
                return True

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(_do)
            try:
                return bool(fut.result(timeout=timeout + 0.5))
            except (concurrent.futures.TimeoutError, OSError):
                return False
            except Exception:  # noqa: BLE001
                return False

    async def join_mesh(self) -> dict[str, Any]:
        server = (self.settings.hayabusa_mesh_server_url or self._status.get("mesh_server") or "").strip()
        key = (self.settings.hayabusa_preauth_key or os.environ.get("HAYABUSA_PREAUTH_KEY") or "").strip()
        hostname = self.settings.controller_mesh_hostname
        self._status["last_action"] = "join"
        self._status["phase"] = "joining"
        if not server or not key:
            return self._fail("missing_credentials", "Mesh server URL and preauth key are required", server=server)

        force_sim = (os.environ.get("CONTROLLER_VPN_MODE") or "").strip().lower() in {
            "simulate",
            "sim",
            "test",
        }
        if force_sim and vpn_simulate_allowed():
            self._status["connected"] = True
            self._status["ip"] = "100.64.0.2"
            self._status["error"] = ""
            self._status["error_code"] = ""
            self._status["fix"] = ""
            self._status["backend"] = "simulated"
            self._status["last_action"] = "simulated_join"
            self._status["phase"] = "joined"
            self._status["mesh_server"] = server
            self._status["simulate_reason"] = "test_only"
            self._status["preflight"] = {"ok": True, "skipped": "simulate"}
            self._save()
            logger.warning("VPN simulate join for %s (test-only; not available in production)", server)
            return self.status()
        if force_sim and not vpn_simulate_allowed():
            logger.error("CONTROLLER_VPN_MODE=simulate ignored — set CONTROLLER_ALLOW_VPN_SIMULATE=1 only in tests")

        pf = self.preflight(server)
        if not pf.get("ok"):
            return self._fail(
                str(pf.get("error_code") or "preflight_failed"),
                str(pf.get("error") or "Preflight failed"),
                server=server,
            )

        # Already on the mesh (e.g. prior boot / single-use key already spent):
        # treat as success and open the control bridge without re-auth.
        already = self.status()
        if already.get("connected") and already.get("ip"):
            self._status["mesh_server"] = server
            self._status["backend"] = "tailscale"
            self._status["last_action"] = "already_joined"
            self._status["phase"] = "joined"
            self._status["error"] = ""
            self._status["error_code"] = ""
            self._status["fix"] = ""
            self._status.pop("simulate_reason", None)
            self._save()
            logger.info("mesh already joined at %s — skipping tailscale up", already.get("ip"))
            return self.status()

        state_dir = str(self.settings.tailscale_state_dir)
        Path(state_dir).mkdir(parents=True, exist_ok=True)
        sock = _ts_socket()
        cmd = _ts_cmd(
            "up",
            f"--login-server={server}",
            f"--auth-key={key}",
            f"--hostname={hostname}",
            "--accept-dns=false",
            "--reset",
        )
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "TS_STATE_DIR": state_dir, "TS_SOCKET": sock},
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=45)
            if proc.returncode != 0:
                err = (stderr or stdout or b"tailscale up failed").decode("utf-8", "replace")[:800]
                code, human = classify_tailscale_error(err)
                # Auth key may already be spent while the node is still online.
                recovered = self.status()
                if recovered.get("connected") and recovered.get("ip"):
                    logger.warning(
                        "tailscale up failed (%s) but mesh IP %s is live — continuing",
                        code,
                        recovered.get("ip"),
                    )
                    self._status["mesh_server"] = server
                    self._status["backend"] = "tailscale"
                    self._status["last_action"] = "joined_recovered"
                    self._status["phase"] = "joined"
                    self._status["error"] = ""
                    self._status["error_code"] = ""
                    self._status["fix"] = ""
                    self._status.pop("simulate_reason", None)
                    self._save()
                    return self.status()
                return self._fail(code, human, server=server, detail=err)
            self._status["connected"] = True
            self._status["error"] = ""
            self._status["error_code"] = ""
            self._status["fix"] = ""
            self._status["mesh_server"] = server
            self._status["backend"] = "tailscale"
            self._status["last_action"] = "joined"
            self._status["phase"] = "joined"
            self._status.pop("simulate_reason", None)
        except asyncio.TimeoutError:
            return self._fail("join_timeout", "Mesh join timed out waiting for tailscale up (45s)", server=server)
        except Exception as exc:  # noqa: BLE001
            err = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
            return self._fail("join_failed", "Mesh join failed", server=server, detail=err)
        self._save()
        return self.status()
