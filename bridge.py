"""WebSocket bridge from controller to Hayabusa (over user VPN mesh)."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Callable, Awaitable

import websockets
from websockets.exceptions import ConnectionClosed

from .config import Settings
from .mesh_dial import open_ws_socket_for_url
from .wan_public_ip import (
    discover_wan_public_identity,
    sanitize_reported_public_ip,
)

logger = logging.getLogger("hayabusa-controller.bridge")

RpcHandler = Callable[[str, dict[str, Any] | None], Awaitable[dict[str, Any]]]
_PRESENCE_INTERVAL_SEC = 60.0
_KEEPALIVE_PING_INTERVAL_SEC = 15.0


def bridge_simulate_allowed() -> bool:
    """Local grant without a Core WS is test-only (mirrors VPN simulate)."""
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return True
    return (os.environ.get("CONTROLLER_ALLOW_VPN_SIMULATE") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


class HayabusaBridge:
    """Maintains a WebSocket session to Hayabusa after the user authenticates.

    Protocol (controller → Hayabusa):
      {"type":"hello","role":"controller","user":{...},"vpn_ip":"...","public_ip":"...","ts":...}
      {"type":"access_request","user":{...},"capabilities":["iac","secrets","jobs"]}
      {"type":"presence","vpn_ip":"...","public_ip":"...","wan_public_ip":"...","ts":...}
      {"type":"rpc_response","id":"...","result":{...}}
    Protocol (Hayabusa → controller):
      {"type":"hello_ack","granted":true,"mesh_user":"..."}
      {"type":"access_grant","token":"...","expires_at":...}
      {"type":"rpc_request","id":"...","method":"secrets.list","params":{}}
      {"type":"error","message":"..."}
    """

    def __init__(self, settings: Settings, rpc_handler: RpcHandler | None = None) -> None:
        self.settings = settings
        self._rpc_handler = rpc_handler
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._status: dict[str, Any] = {
            "connected": False,
            "ws_url": settings.hayabusa_ws_url or "",
            "ws_url_fallback": "",
            "granted": False,
            "token_preview": "",
            "last_error": "",
            "last_event": "idle",
            "mode": "standby",
            "rpc_ok": 0,
            "rpc_err": 0,
            "public_ip": "",
            "wan_public_ip": "",
            "vpn_endpoint_ip": "",
        }
        self._user: dict[str, Any] | None = None
        self._vpn_ip = ""
        self._listeners: set[asyncio.Queue] = set()
        self._bridge_token = (settings.controller_bridge_token or "").strip()
        self._ws: Any = None
        self._last_presence_sent = 0.0
        self._last_keepalive_ping = 0.0
        self._ws_url_fallback = ""

    def set_ws_urls(self, primary: str, fallback: str = "") -> None:
        primary = (primary or "").strip()
        fallback = (fallback or "").strip()
        if primary:
            self.settings.hayabusa_ws_url = primary
            self._status["ws_url"] = primary
        self._ws_url_fallback = fallback if fallback and fallback != primary else ""
        self._status["ws_url_fallback"] = self._ws_url_fallback

    def _location_fields(self, *, force: bool = False) -> dict[str, Any]:
        ident = discover_wan_public_identity(force=force)
        # Never report mesh CGNAT / VPN overlay addresses as the site's public IP.
        public_ip = sanitize_reported_public_ip(str(ident.get("public_ip") or ""))
        wan = sanitize_reported_public_ip(str(ident.get("wan_public_ip") or ""))
        endpoint = sanitize_reported_public_ip(str(ident.get("vpn_endpoint_ip") or ""))
        geo = sanitize_reported_public_ip(str(ident.get("geo_ip") or public_ip or ""))
        # If discovery somehow returned the mesh address, drop it rather than lie.
        if self._vpn_ip and public_ip and public_ip == str(self._vpn_ip).strip():
            public_ip = ""
            geo = wan or endpoint
        # Site name comes from the controller mesh hostname (VPN settings), not the container id.
        site_name = (
            str(getattr(self.settings, "controller_display_name", "") or "").strip()
            or str(getattr(self.settings, "controller_mesh_hostname", "") or "").strip()
            or str(self._status.get("hostname") or "").strip()
            or "hayabusa-controller"
        )
        fields = {
            "hostname": site_name,
            "display_name": site_name,
            "public_ip": public_ip or wan or endpoint,
            "wan_public_ip": wan,
            "vpn_endpoint_ip": endpoint,
            "geo_ip": geo or public_ip or wan or endpoint,
            "location_source": str(ident.get("source") or ""),
        }
        # Tenant-scoped control-node address (from enroll), never mesh CGNAT.
        try:
            import json
            from pathlib import Path

            en_path = Path(self.settings.data_dir) / "state" / "enrollment.json"
            if en_path.is_file():
                raw = json.loads(en_path.read_text(encoding="utf-8"))
                cip = str((raw or {}).get("control_node_ip") or "").strip()
                if cip and cip != self._vpn_ip:
                    fields["control_node_ip"] = cip
        except Exception:  # noqa: BLE001
            pass
        self._status["public_ip"] = fields["public_ip"]
        self._status["wan_public_ip"] = fields["wan_public_ip"]
        self._status["vpn_endpoint_ip"] = fields["vpn_endpoint_ip"]
        if fields.get("control_node_ip"):
            self._status["control_node_ip"] = fields["control_node_ip"]
        return fields

    def set_rpc_handler(self, handler: RpcHandler | None) -> None:
        self._rpc_handler = handler

    async def send_event(self, payload: dict[str, Any]) -> bool:
        """Push a controller→Hayabusa event on the live bridge (e.g. iac_sync)."""
        ws = self._ws
        if ws is None:
            return False
        try:
            await ws.send(json.dumps(payload))
            self._status["last_event"] = str(payload.get("type") or "event")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("bridge send_event failed: %s", exc)
            return False

    def status(self) -> dict[str, Any]:
        out = dict(self._status)
        user = dict(self._user or {})
        out["user"] = {
            "username": str(user.get("username") or "")[:120],
            "email": str(user.get("email") or "")[:200],
            "provider": str(user.get("provider") or "")[:64],
            "sub": str(user.get("sub") or user.get("oauth_id") or "")[:200],
        }
        owner = str(user.get("sub") or user.get("oauth_id") or user.get("username") or user.get("email") or "").strip().lower()
        provider = str(user.get("provider") or "").strip().lower()
        claimed = bool(owner) and owner not in {"boot", "controller", "anon"} and provider not in {"boot"}
        out["owner_key"] = owner
        out["identity_claimed"] = claimed
        # Mesh WS up without a claimed Hayabusa identity is not a full link.
        if out.get("granted") and not claimed and out.get("mode") == "live":
            out["granted_unclaimed"] = True
        return out

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=64)
        self._listeners.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._listeners.discard(q)

    async def _emit(self, event: dict[str, Any]) -> None:
        dead = []
        for q in self._listeners:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self._listeners.discard(q)

    async def start_for_user(self, user: dict[str, Any], vpn_ip: str = "") -> dict[str, Any]:
        self._user = dict(user or {})
        self._vpn_ip = vpn_ip or ""
        self._stop.clear()
        if self._task and not self._task.done():
            self._stop.set()
            try:
                await asyncio.wait_for(self._task, timeout=5)
            except (asyncio.TimeoutError, Exception):  # noqa: BLE001
                self._task.cancel()
        self._stop.clear()
        self._task = asyncio.create_task(self._run_loop())
        return self.status()

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5)
            except (asyncio.TimeoutError, Exception):  # noqa: BLE001
                self._task.cancel()
            self._task = None
        self._status["connected"] = False
        self._status["granted"] = False
        self._status["last_event"] = "stopped"

    async def _run_loop(self) -> None:
        ws_url = (self.settings.hayabusa_ws_url or "").strip()
        if not ws_url:
            if bridge_simulate_allowed():
                # Test-only: VPN simulate paths clear the WS URL; grant locally so
                # five-pass HTTP suites can exercise the join → bridge pipeline.
                logger.warning(
                    "Bridge simulate grant (test-only; not available in production)"
                )
                self._status.update(
                    {
                        "mode": "simulated",
                        "connected": True,
                        "granted": True,
                        "token_preview": "sim…ulate",
                        "last_event": "simulated_grant",
                        "last_error": "",
                        "ws_url": "",
                    }
                )
                await self._emit({"type": "bridge", "status": self.status()})
                while not self._stop.is_set():
                    await asyncio.sleep(1)
                return
            # No control URL configured — not linked. Never fake a grant in production.
            self._status.update(
                {
                    "mode": "standby",
                    "connected": False,
                    "granted": False,
                    "token_preview": "",
                    "last_event": "standby_no_ws",
                    "last_error": "Hayabusa control WebSocket URL not configured",
                    "ws_url": "",
                }
            )
            await self._emit({"type": "bridge", "status": self.status()})
            while not self._stop.is_set():
                await asyncio.sleep(1)
            return

        self._status["mode"] = "live"
        self._status["ws_url"] = ws_url
        backoff = 1.0
        while not self._stop.is_set():
            urls: list[str] = []
            # LAN URL first when mesh CGNAT is flaky (lab/docker).
            for env_key in ("HAYABUSA_WS_URL", "HAYABUSA_WS_MESH_URL"):
                c = (os.environ.get(env_key) or "").strip()
                if c and c not in urls:
                    urls.append(c)
            for cand in (ws_url, self._ws_url_fallback, getattr(self.settings, "hayabusa_ws_url", "")):
                c = (cand or "").strip()
                if c and c not in urls:
                    urls.append(c)
            if not urls:
                urls = [ws_url]
            last_exc: Exception | None = None
            connected_ok = False
            for attempt_url in urls:
                if self._stop.is_set():
                    break
                try:
                    self._status["ws_url"] = attempt_url
                    await self._session(attempt_url)
                    connected_ok = True
                    backoff = 1.0
                    break
                except Exception as exc:  # noqa: BLE001
                    last_exc = exc
                    logger.warning("bridge session failed url=%s err=%s", attempt_url, exc)
                    self._status["connected"] = False
                    self._status["granted"] = False
                    self._ws = None
                    self._status["last_error"] = str(exc)[:500]
                    self._status["last_event"] = "ws_failover" if attempt_url != urls[-1] else "reconnect_wait"
                    await self._emit({"type": "bridge", "status": self.status()})
            if connected_ok:
                continue
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=backoff)
            except asyncio.TimeoutError:
                pass
            backoff = min(backoff * 2, 30.0)
            if last_exc and not self._status.get("last_error"):
                self._status["last_error"] = str(last_exc)[:500]

    async def _session(self, ws_url: str) -> None:
        logger.info("Connecting Hayabusa bridge WS %s", ws_url)
        headers = {}
        if self._bridge_token:
            headers["Authorization"] = f"Bearer {self._bridge_token}"
        # Mesh CGNAT targets need a Tailscale path (SOCKS or kernel TUN); see mesh_dial.
        mesh_sock = await open_ws_socket_for_url(ws_url, timeout=15.0)
        connect_kwargs: dict[str, Any] = {
            "open_timeout": 15,
            "ping_interval": 20,
            "additional_headers": headers or None,
        }
        if mesh_sock is not None:
            connect_kwargs["sock"] = mesh_sock
        async with websockets.connect(ws_url, **connect_kwargs) as ws:
            self._ws = ws
            self._status["connected"] = True
            self._status["last_error"] = ""
            self._status["last_event"] = "connected"
            loc = await asyncio.to_thread(self._location_fields, force=True)
            hello = {
                "type": "hello",
                "role": "controller",
                "user": self._user or {},
                "vpn_ip": self._vpn_ip,
                "bridge_token": self._bridge_token,
                "capabilities": ["iac", "secrets", "vpn", "jobs", "lan", "ztp-edge"],
                "ts": int(time.time()),
                **loc,
            }
            await ws.send(json.dumps(hello))
            await ws.send(
                json.dumps(
                    {
                        "type": "access_request",
                        "user": self._user or {},
                        "capabilities": ["iac", "secrets", "vpn", "jobs", "lan", "ztp-edge"],
                        "bridge_token": self._bridge_token,
                        "vpn_ip": self._vpn_ip,
                        "ts": int(time.time()),
                        **loc,
                    }
                )
            )
            self._last_presence_sent = time.time()
            self._last_keepalive_ping = time.time()
            await self._emit({"type": "bridge", "status": self.status()})
            while not self._stop.is_set():
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=1.0)
                except asyncio.TimeoutError:
                    now = time.time()
                    # App-level keepalive so Hayabusa can mark the node up/down for the live map.
                    if now - self._last_keepalive_ping >= _KEEPALIVE_PING_INTERVAL_SEC:
                        try:
                            await ws.send(json.dumps({"type": "ping", "ts": int(now), "role": "controller"}))
                            self._last_keepalive_ping = now
                            self._status["last_event"] = "keepalive_ping"
                        except Exception as exc:  # noqa: BLE001
                            logger.debug("keepalive ping failed: %s", exc)
                            raise
                    if now - self._last_presence_sent >= _PRESENCE_INTERVAL_SEC:
                        await self._send_presence(ws)
                    continue
                except ConnectionClosed:
                    self._status["connected"] = False
                    self._status["granted"] = False
                    raise
                await self._handle_message(ws, raw)
            self._status["connected"] = False
            self._status["granted"] = False
            self._ws = None
            self._status["last_event"] = "disconnected"
            await self._emit({"type": "bridge", "status": self.status()})

    async def push_presence(self) -> bool:
        """Tell Hayabusa the current site display name (branch picker on Hayabusa core)."""
        ws = self._ws
        if ws is None:
            return False
        try:
            await self._send_presence(ws)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.debug("push_presence failed: %s", exc)
            return False

    async def _send_presence(self, ws: Any) -> None:
        try:
            loc = await asyncio.to_thread(self._location_fields, force=False)
            payload = {
                "type": "presence",
                "role": "controller",
                "user": self._user or {},
                "vpn_ip": self._vpn_ip,
                "ts": int(time.time()),
                **loc,
            }
            await ws.send(json.dumps(payload))
            self._last_presence_sent = time.time()
            self._status["last_event"] = "presence"
            await self._emit({"type": "bridge", "status": self.status()})
        except Exception as exc:  # noqa: BLE001
            logger.debug("presence send failed: %s", exc)

    async def _handle_message(self, ws: Any, raw: str | bytes) -> None:
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            return
        if not isinstance(msg, dict):
            return
        mtype = msg.get("type")
        self._status["last_event"] = str(mtype or "message")
        if mtype in ("hello_ack", "access_grant"):
            granted = bool(msg.get("granted", mtype == "access_grant"))
            self._status["granted"] = granted
            token = str(msg.get("token") or "")
            if token:
                self._status["token_preview"] = token[:6] + "…" + token[-4:] if len(token) > 12 else "••••"
        elif mtype == "pong":
            self._status["last_event"] = "keepalive_pong"
            self._status["last_keepalive_pong_ts"] = int(msg.get("ts") or time.time())
        elif mtype == "rpc_request":
            await self._handle_rpc(ws, msg)
        elif mtype == "error":
            self._status["last_error"] = str(msg.get("message") or "error")[:500]
        await self._emit({"type": "bridge", "status": self.status(), "message": {"type": mtype}})

    async def _handle_rpc(self, ws: Any, msg: dict[str, Any]) -> None:
        req_id = str(msg.get("id") or "").strip()
        method = str(msg.get("method") or "").strip()
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        if not req_id:
            return
        if not self._rpc_handler:
            result: dict[str, Any] = {"ok": False, "error": "rpc handler not configured"}
        else:
            try:
                result = await self._rpc_handler(method, params)
                if not isinstance(result, dict):
                    result = {"ok": False, "error": "invalid handler result"}
            except Exception as exc:  # noqa: BLE001
                result = {"ok": False, "error": str(exc)[:400]}
        if result.get("ok"):
            self._status["rpc_ok"] = int(self._status.get("rpc_ok") or 0) + 1
        else:
            self._status["rpc_err"] = int(self._status.get("rpc_err") or 0) + 1
        # Never echo raw secret maps into local status/events
        safe_meta = {
            "type": "rpc_response",
            "id": req_id,
            "method": method,
            "ok": bool(result.get("ok")),
        }
        await self._emit({"type": "bridge", "status": self.status(), "message": safe_meta})
        try:
            await ws.send(json.dumps({"type": "rpc_response", "id": req_id, "result": result}))
        except Exception as exc:  # noqa: BLE001
            logger.warning("rpc response send failed: %s", exc)
