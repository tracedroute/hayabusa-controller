"""Hayabusa Controller — user-installed appliance for secrets, IaC, and Hayabusa VPN access."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
import urllib.parse
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, File, Form, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .bridge import HayabusaBridge
from .bridge_rpc import BridgeRpcHandler, ZTP_JOB_KINDS
from .config import Settings, get_settings
from .connection_progress import ConnectionProgress, public_connection_view
from .devops_iac import DevopsIacWorkspace
from .gitops_store import GitOpsStore
from .setup_store import SetupStore
from .enroll import HayabusaEnroller, public_enroll_view
from .iac_store import IacStore
from .image_nest import ImageNestStore
from .job_queue import JobQueue
from .rbac_store import RbacStore, _norm_user_key
from .oauth_creds import OAuthCredentialStore
from .secrets_vault import SecretsVault, is_reserved_secret_key
from . import security as ctrl_security
from .lan import browser_public_base
from .vpn import VpnClient
from .ztp_edge import ZtpEdge

logger = logging.getLogger("hayabusa-controller")

APP_DIR = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(APP_DIR / "templates"))


def _is_mesh_cgnat_ip(ip: str) -> bool:
    """Tailscale/Headscale CGNAT (100.64.0.0/10)."""
    try:
        import ipaddress

        addr = ipaddress.ip_address((ip or "").strip())
        return addr in ipaddress.ip_network("100.64.0.0/10")
    except ValueError:
        return False


async def lifespan(_app: FastAPI):
    """Join mesh + open control bridge over VPN as soon as the appliance boots."""
    task = asyncio.create_task(_boot_mesh_control_plane())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass


app = FastAPI(title="Hayabusa Controller", version="0.1.0", lifespan=lifespan)
_settings = get_settings()
ctrl_security.set_abuse_db_path(str(_settings.data_dir / "edge_abuse.sqlite3"))


def _controller_session_lifetime_sec() -> int:
    try:
        v = int((os.environ.get("CONTROLLER_SESSION_LIFETIME_SEC") or "").strip() or str(8 * 3600))
    except (TypeError, ValueError):
        v = 8 * 3600
    return max(60, v)


def _controller_session_warn_before_sec() -> int:
    life = _controller_session_lifetime_sec()
    try:
        v = int((os.environ.get("CONTROLLER_SESSION_WARN_BEFORE_SEC") or "").strip() or str(5 * 60))
    except (TypeError, ValueError):
        v = 5 * 60
    return max(30, min(v, max(60, life // 2)))


CONTROLLER_SESSION_LIFETIME_SEC = _controller_session_lifetime_sec()
CONTROLLER_SESSION_WARN_BEFORE_SEC = _controller_session_warn_before_sec()

# Inner → outer: security (needs session) then SessionMiddleware, then optional TrustedHost.
app.add_middleware(ctrl_security.ControllerSecurityMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=_settings.secret_key,
    session_cookie="hayabusa_controller_session",
    same_site="lax",
    https_only=bool(_settings.session_https_only),
    max_age=CONTROLLER_SESSION_LIFETIME_SEC,
)
_hosts = ctrl_security.allowed_hosts()
if _hosts:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=_hosts)
# Intentionally no CORSMiddleware: browser same-origin only (LAN appliance UI).
app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")

vault = SecretsVault(_settings)
oauth_store = OAuthCredentialStore(vault)
# Default: broker IdP login through Hayabusa — do not keep client secrets on the
# customer host. Purge any previously sealed copies.
_oauth_mode = (os.environ.get("CONTROLLER_OAUTH_MODE") or "broker").strip().lower()
if _oauth_mode in {"broker", "hayabusa", "proxy", ""}:
    removed = oauth_store.purge_all()
    if removed:
        logging.getLogger("hayabusa-controller").info(
            "purged %s sealed oauth provider secret(s); broker mode keeps IdP secrets off this host",
            removed,
        )
elif _oauth_mode == "local":
    # Explicit opt-in only (air-gapped / custom IdP registration on this node).
    oauth_store.seal_from_env_map(dict(os.environ))
iac = IacStore(_settings)
vpn = VpnClient(_settings)
devops = DevopsIacWorkspace(_settings.devops_workspace, _settings.devops_defaults)
gitops = GitOpsStore(_settings.data_dir)
setup = SetupStore(_settings.data_dir)
if not gitops.enabled():
    devops.seed_from_defaults()
ztp_edge = ZtpEdge(
    _settings.data_dir,
    public_base_url=_settings.public_base_url,
    devops_workspace=_settings.devops_workspace,
)
connection = ConnectionProgress()


def _rpc_read_file(rel: str) -> str:
    out = devops.read_file(rel)
    if not out.get("ok"):
        raise ValueError(str(out.get("error") or "read failed"))
    return str(out.get("content") or "")


def _rpc_list_tree(rel: str) -> list:
    out = devops.ls(rel)
    if not out.get("ok"):
        raise ValueError(str(out.get("error") or "list failed"))
    return list(out.get("entries") or [])


def _rpc_import_sync(params: dict) -> dict:
    user_key = str((params or {}).get("user_key") or "").strip()
    files = (params or {}).get("files") if isinstance((params or {}).get("files"), list) else []
    return devops.import_sync(files, owner_id=user_key or (_settings.manual_username or "admin"))


def _rpc_inventory_summary() -> dict:
    return devops.inventory_summary()


_rpc = BridgeRpcHandler(
    vault=vault,
    devops_root=_settings.devops_workspace,
    list_tree=_rpc_list_tree,
    read_file=_rpc_read_file,
    import_sync=_rpc_import_sync,
    inventory_summary=_rpc_inventory_summary,
    ztp_edge=ztp_edge,
    ztp_status=ztp_edge.status,
    gitops=gitops,
)
job_queue = JobQueue(_settings.data_dir, hydrator=_rpc._hydrate_job)
_rpc.set_job_queue(job_queue)
rbac = RbacStore(_settings.data_dir)
_rpc.set_rbac(rbac)
image_nest = ImageNestStore(_settings.data_dir)
_rpc.set_image_nest(image_nest)
bridge = HayabusaBridge(_settings, rpc_handler=_rpc.handle)
enroller = HayabusaEnroller(_settings, vault)


def _mesh_hostname_from_display(display: str) -> str:
    """DNS-safe mesh hostname (``name#2`` → ``name-2``)."""
    h = (display or "").strip() or "hayabusa-controller"
    h = h.replace("#", "-")
    h = re.sub(r"[^a-zA-Z0-9._-]+", "-", h).strip("-._") or "hayabusa-controller"
    return h[:63]


def _site_display_name() -> str:
    saved = str(getattr(_settings, "controller_display_name", "") or "").strip()
    if saved:
        return saved
    try:
        st = enroller.status()
        return str(st.get("display_hostname") or st.get("hostname") or "").strip()
    except Exception:  # noqa: BLE001
        return ""


def _apply_enrollment_site_name() -> None:
    """Load persisted site display name into runtime settings (Hayabusa branch picker)."""
    try:
        display = _site_display_name() or str(_settings.controller_mesh_hostname or "").strip()
        if not display:
            return
        mesh = _mesh_hostname_from_display(display)
        _settings.controller_mesh_hostname = mesh
        setattr(_settings, "controller_display_name", display)
        if hasattr(vpn, "_status") and isinstance(vpn._status, dict):
            vpn._status["hostname"] = display
    except Exception as exc:  # noqa: BLE001
        logger.debug("site name load skipped: %s", exc)


def _save_site_display_name(display: str) -> dict[str, str]:
    name = str(display or "").strip()
    if not name:
        raise ValueError("name required")
    if len(name) > 80:
        raise ValueError("name too long (max 80)")
    if not re.fullmatch(r"[A-Za-z0-9 _.\-:/@()#]+", name):
        raise ValueError("name contains unsupported characters")
    mesh = _mesh_hostname_from_display(name)
    path = _settings.state_dir / "enrollment.json"
    data: dict[str, Any] = {}
    if path.is_file():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                data = raw
        except (OSError, json.JSONDecodeError):
            data = {}
    data["display_hostname"] = name
    data["hostname"] = name
    data["mesh_hostname"] = mesh
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)
    _settings.controller_mesh_hostname = mesh
    setattr(_settings, "controller_display_name", name)
    if hasattr(vpn, "_status") and isinstance(vpn._status, dict):
        vpn._status["hostname"] = name
    return {"display_name": name, "mesh_hostname": mesh}


_apply_enrollment_site_name()


async def _emit_connection_event(event: dict[str, Any]) -> None:
    """Push connection pipeline updates onto the same bus as bridge status WS.

    Always emit the reconciled public connection view (live VPN/bridge truth),
    not the raw in-memory step snapshot — a recovered mesh must not keep showing
    a stale ``mesh failed`` / Mesh join failed state.
    """
    payload = dict(event)
    vpn_st = vpn.status()
    br_st = bridge.status()
    enroll_st = enroller.status()
    payload["vpn"] = vpn_st
    payload["bridge"] = br_st
    payload["enroll"] = enroll_st
    payload["connection"] = public_connection_view(
        connection.snapshot(),
        enroll=enroll_st,
        vpn=vpn_st,
        bridge=br_st,
    )
    await bridge._emit(payload)


connection.set_emitter(_emit_connection_event)


def _control_ws_urls_from_enroll(enrolled: dict[str, Any] | None) -> tuple[str, str]:
    """Return (mesh_ws_url, public_ws_url) from enroll payload / settings."""
    data = enrolled if isinstance(enrolled, dict) else {}
    cp = data.get("control_plane") if isinstance(data.get("control_plane"), dict) else {}
    mesh = (
        str(data.get("ws_url_mesh") or cp.get("websocket_mesh") or "").strip()
        or (os.environ.get("HAYABUSA_WS_MESH_URL") or "").strip()
    )
    public = (
        str(data.get("ws_url") or cp.get("websocket") or "").strip()
        or (_settings.hayabusa_ws_url or "").strip()
    )
    return mesh, public


def _prefer_mesh_ws_url(*, mesh_url: str, public_url: str, vpn_connected: bool) -> str:
    """Prefer LAN WS when configured; mesh SOCKS often fails in lab/docker."""
    lan = (os.environ.get("HAYABUSA_WS_URL") or "").strip()
    if lan and "100.64." not in lan:
        return lan
    if vpn_connected and mesh_url and "100.64." not in mesh_url:
        return mesh_url
    if vpn_connected and mesh_url:
        logger.warning(
            "mesh is up but CGNAT ws %s may be unreachable; trying public WS %s",
            mesh_url,
            public_url,
        )
    if public_url:
        return public_url
    return mesh_url or lan


async def _wait_bridge_ready(*, timeout: float = 25.0) -> dict[str, Any]:
    """Poll until the control bridge is granted (or timeout). Do not fail after 150ms."""
    deadline = time.monotonic() + max(3.0, timeout)
    last: dict[str, Any] = bridge.status()
    while time.monotonic() < deadline:
        last = bridge.status()
        if last.get("granted") and last.get("connected"):
            return last
        if last.get("granted"):
            return last
        await asyncio.sleep(0.4)
    return last


def _bridge_step_detail(br: dict[str, Any]) -> str:
    ws = str(br.get("ws_url") or "").strip()
    if ws.startswith("ws://100.") or "100.64." in ws:
        transport = "mesh VPN (WireGuard-encrypted; ws:// inside the tunnel is expected)"
    elif ws.startswith("wss://"):
        transport = "public TLS WebSocket"
    else:
        transport = "control channel"
    if br.get("granted"):
        return f"Granted via {transport}"
    if br.get("connected"):
        return f"Connected via {transport} — waiting for grant"
    err = str(br.get("last_error") or "").strip()
    if err:
        return f"{err} ({transport})"
    return f"Opening {transport}…"


async def _boot_mesh_control_plane() -> None:
    """On power-on: if already enrolled, join VPN and open the mesh control bridge."""
    await asyncio.sleep(1.5)
    try:
        st = enroller.status()
        preauth = enroller.load_preauth()
        mesh = str(st.get("mesh_server_url") or _settings.hayabusa_mesh_server_url or "").strip()
        if not (st.get("enrolled") and preauth and mesh):
            logger.info("boot mesh: not enrolled yet — waiting for first sign-in phone-home")
            return
        logger.info("boot mesh: enrolled — joining VPN and opening control plane over mesh")
        await connection.set_step("enroll", "ok", "Previously enrolled")
        vpn.configure(mesh_server=mesh, preauth_key=preauth, hostname=_settings.controller_mesh_hostname)
        await connection.set_step("mesh", "running", "Joining mesh VPN…")
        vpn_st = await vpn.join_mesh()
        if not vpn_st.get("connected"):
            detail = vpn_st.get("error") or vpn_st.get("error_code") or "Mesh join failed"
            logger.warning("boot mesh: join failed — %s", detail)
            await connection.set_step("mesh", "failed", str(detail)[:300])
            return
        await connection.set_step("mesh", "ok", "Mesh VPN up")
        mesh_ws, public_ws = _control_ws_urls_from_enroll(st)
        chosen = _prefer_mesh_ws_url(mesh_url=mesh_ws, public_url=public_ws, vpn_connected=True)
        logger.warning(
            "boot mesh: joined ip=%s opening bridge ws=%s",
            vpn_st.get("ip") or "",
            chosen or "(none)",
        )
        if chosen:
            bridge.settings.hayabusa_ws_url = chosen
            bridge._status["ws_url"] = chosen
        # Keep the configured bridge token for a reliable authenticated boot
        # reconnect. Mesh membership remains the primary transport boundary.
        bridge._bridge_token = (_settings.controller_bridge_token or "").strip()
        await connection.set_step("bridge", "running", "Opening control bridge via mesh VPN…")
        # Prefer the last authenticated Hayabusa owner so map/branches bind correctly.
        # Never advertise a boot placeholder as a fully linked account controller.
        owner = enroller.load_owner_identity()
        if owner:
            bridge_user = {
                "username": owner.get("username") or "controller",
                "email": owner.get("email") or "",
                "provider": owner.get("provider") or "saved",
                "sub": owner.get("sub") or owner.get("username") or "",
            }
        else:
            bridge_user = {"username": "controller", "provider": "boot", "sub": "boot"}
        await bridge.start_for_user(
            bridge_user,
            vpn_ip=str(vpn_st.get("ip") or ""),
        )
        br = await _wait_bridge_ready(timeout=25.0)
        if br.get("granted") and br.get("identity_claimed"):
            await connection.set_step("bridge", "ok", _bridge_step_detail(br))
        elif br.get("granted") or br.get("connected"):
            await connection.set_step(
                "bridge",
                "pending",
                "Mesh bridge up — sign in on this controller to claim it for your Hayabusa account",
            )
        else:
            await connection.set_step(
                "bridge",
                "failed" if br.get("last_error") else "pending",
                _bridge_step_detail(br),
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("boot mesh control plane failed: %s", exc)
        try:
            await connection.set_step("bridge", "failed", str(exc)[:300])
        except Exception:  # noqa: BLE001
            pass


def _local_manual_mesh_override_allowed() -> bool:
    """Lab/unit-test escape hatch when Hayabusa is unreachable."""
    return (os.environ.get("CONTROLLER_MANUAL_MESH_OVERRIDE_LOCAL") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _session_can_manual_mesh_override(request: Request) -> bool:
    if _local_manual_mesh_override_allowed():
        return True
    return bool(request.session.get("can_manual_mesh_override"))


def _apply_capabilities_to_session(request: Request, caps: dict[str, Any] | None) -> None:
    if not isinstance(caps, dict):
        return
    if "can_manual_mesh_override" in caps:
        request.session["can_manual_mesh_override"] = bool(caps.get("can_manual_mesh_override"))
    request.session["capabilities_checked_at"] = int(time.time())


async def _refresh_user_capabilities(
    request: Request,
    user: dict[str, Any] | None = None,
    *,
    fail_closed: bool = True,
) -> dict[str, Any]:
    """Ask Hayabusa which global permissions apply to the controller session user.

    Fail closed: if Hayabusa cannot be reached, deny manual mesh override
    (unless CONTROLLER_MANUAL_MESH_OVERRIDE_LOCAL is set for lab/tests).
    """
    if _local_manual_mesh_override_allowed():
        caps = {"can_manual_mesh_override": True, "local_override": True}
        _apply_capabilities_to_session(request, caps)
        return caps
    base = (_settings.hayabusa_public_url or "").rstrip("/")
    token = (_settings.controller_bridge_token or "").strip()
    if not base or not token:
        if fail_closed:
            request.session["can_manual_mesh_override"] = False
        return {
            "can_manual_mesh_override": False if fail_closed else _session_can_manual_mesh_override(request),
            "error": "capabilities_unavailable",
            "reason": "missing_bridge_config",
        }
    u = user or _user(request)
    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
            resp = await client.post(
                f"{base}/api/controller/capabilities",
                json={"user": u},
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        caps = data.get("capabilities") if isinstance(data, dict) else None
        if resp.status_code < 400 and isinstance(caps, dict):
            _apply_capabilities_to_session(request, caps)
            return caps
        if fail_closed:
            request.session["can_manual_mesh_override"] = False
        return {
            "can_manual_mesh_override": False,
            "error": "capabilities_unavailable",
            "reason": f"http_{resp.status_code}",
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("capabilities refresh failed: %s", exc)
        if fail_closed:
            request.session["can_manual_mesh_override"] = False
        return {
            "can_manual_mesh_override": False,
            "error": "capabilities_unavailable",
            "reason": str(exc)[:200],
        }


def _connection_public() -> dict[str, Any]:
    """Connection-tab status. Mesh IP alone is never ``ready`` / fully connected."""
    return public_connection_view(
        connection.snapshot(),
        enroll=enroller.status(),
        vpn=vpn.status(),
        bridge=bridge.status(),
    )


async def _connect_to_hayabusa(user: dict[str, Any], request: Request | None = None) -> dict[str, Any]:
    """Phone-home enroll (like SD-WAN → vBond), join mesh VPN, open control WS."""
    await connection.reset()
    await connection.set_step("enroll", "running", "Phoning home to Hayabusa…")
    enrolled = await enroller.enroll(user=user)
    if request is not None and isinstance(enrolled.get("capabilities"), dict):
        _apply_capabilities_to_session(request, enrolled.get("capabilities"))
    if not enrolled.get("ok") and not enrolled.get("enrolled"):
        err = str(enrolled.get("error") or "Enrollment failed")
        await connection.set_step("enroll", "failed", err)
        await connection.set_step("mesh", "idle", "")
        await connection.set_step("bridge", "idle", "")
        return {
            "enroll": public_enroll_view(enrolled),
            "vpn": vpn.status(),
            "bridge": bridge.status(),
            "connection": _connection_public(),
            "capabilities": {
                "can_manual_mesh_override": bool(
                    (enrolled.get("capabilities") or {}).get("can_manual_mesh_override")
                )
                if isinstance(enrolled.get("capabilities"), dict)
                else False
            },
        }
    await connection.set_step("enroll", "ok", "Enrolled with introducer")

    mesh = str(enrolled.get("mesh_server_url") or _settings.hayabusa_mesh_server_url or "").strip()
    preauth = enroller.load_preauth()
    if mesh and preauth:
        vpn.configure(mesh_server=mesh, preauth_key=preauth, hostname=_settings.controller_mesh_hostname)

    mesh_ws, public_ws = _control_ws_urls_from_enroll(enrolled)

    await connection.set_step("mesh", "running", "Joining mesh VPN…")
    vpn_st = await vpn.join_mesh()
    if vpn_st.get("connected"):
        await connection.set_step("mesh", "ok", "Mesh VPN up")
    else:
        detail = vpn_st.get("error") or vpn_st.get("error_code") or "Mesh join failed"
        fix = vpn_st.get("fix") or ""
        await connection.set_step("mesh", "failed", f"{detail}" + (f" — {fix}" if fix else ""))

    chosen = _prefer_mesh_ws_url(
        mesh_url=mesh_ws,
        public_url=public_ws,
        vpn_connected=bool(vpn_st.get("connected")),
    )
    if chosen:
        # Prefer mesh when healthy; always keep public WSS as failover if mesh dial fails.
        bridge.set_ws_urls(chosen, fallback=public_ws if public_ws and public_ws != chosen else "")
    # LAN / public failover still needs the bridge token when Hayabusa requires it.
    bridge._bridge_token = (_settings.controller_bridge_token or "").strip()

    await connection.set_step("bridge", "running", "Opening control bridge via mesh VPN…")
    br_st = await bridge.start_for_user(user, vpn_ip=vpn_st.get("ip") or "")
    br_st = await _wait_bridge_ready(timeout=25.0)
    if br_st.get("granted") and br_st.get("identity_claimed", True):
        enroller.save_owner_identity(user)
        await connection.set_step("bridge", "ok", _bridge_step_detail(br_st))
    elif br_st.get("granted") or br_st.get("connected"):
        # Persist owner even if grant race is still settling — next boot can reclaim.
        enroller.save_owner_identity(user)
        await connection.set_step("bridge", "pending", _bridge_step_detail(br_st))
    else:
        await connection.set_step(
            "bridge",
            "failed" if br_st.get("last_error") else "pending",
            _bridge_step_detail(br_st),
        )

    return {
        "enroll": public_enroll_view(enrolled),
        "vpn": vpn_st,
        "bridge": br_st,
        "connection": _connection_public(),
        "capabilities": {
            "can_manual_mesh_override": bool(
                (enrolled.get("capabilities") or {}).get("can_manual_mesh_override")
            )
            if isinstance(enrolled.get("capabilities"), dict)
            else False
        },
    }


def _session_begin(request: Request) -> None:
    now = int(time.time())
    request.session["_session_started_at"] = now
    request.session["_session_expires_at"] = now + CONTROLLER_SESSION_LIFETIME_SEC
    request.session["_session_lifetime_sec"] = CONTROLLER_SESSION_LIFETIME_SEC
    request.session["_session_warn_before_sec"] = CONTROLLER_SESSION_WARN_BEFORE_SEC


def _liability_require_on_login(request: Request) -> None:
    """Reset risk acknowledgment for each new sign-in (not session renew)."""
    request.session["liability_ack"] = False
    request.session.pop("liability_ack_at", None)


def _liability_acknowledged(request: Request) -> bool:
    return bool(request.session.get("liability_ack"))


_LIABILITY_GATE_ALLOW_EXACT = frozenset(
    {
        "/logout",
        "/api/session/status",
        "/api/session/renew",
        "/api/liability/acknowledge",
        "/healthz",
        "/health",
    }
)
_LIABILITY_GATE_ALLOW_PREFIXES = (
    "/static/",
    "/login",
    "/auth/",
)


def _liability_gate_allowed(path: str, method: str) -> bool:
    p = path or "/"
    if p in _LIABILITY_GATE_ALLOW_EXACT:
        return True
    if any(p.startswith(pref) for pref in _LIABILITY_GATE_ALLOW_PREFIXES):
        return True
    if method == "GET" and not p.startswith("/api/"):
        return True
    return False


def _session_expired(request: Request) -> bool:
    if not request.session.get("authenticated"):
        return True
    exp = request.session.get("_session_expires_at")
    if exp is None:
        return False
    try:
        return int(time.time()) >= int(exp)
    except (TypeError, ValueError):
        return True


def _session_status(request: Request) -> dict[str, Any]:
    now = int(time.time())
    exp = request.session.get("_session_expires_at")
    try:
        exp_i = int(exp) if exp is not None else now + CONTROLLER_SESSION_LIFETIME_SEC
    except (TypeError, ValueError):
        exp_i = now + CONTROLLER_SESSION_LIFETIME_SEC
    remaining = max(0, exp_i - now)
    warn_before = int(request.session.get("_session_warn_before_sec") or CONTROLLER_SESSION_WARN_BEFORE_SEC)
    return {
        "ok": True,
        "authenticated": True,
        "expires_at": exp_i,
        "server_now": now,
        "remaining_sec": remaining,
        "lifetime_sec": int(request.session.get("_session_lifetime_sec") or CONTROLLER_SESSION_LIFETIME_SEC),
        "warn_before_sec": warn_before,
        "should_warn": remaining > 0 and remaining <= warn_before,
        "liability_acknowledged": _liability_acknowledged(request),
    }


def _authed(request: Request) -> bool:
    if not bool(request.session.get("authenticated")):
        return False
    if _session_expired(request):
        request.session.clear()
        return False
    if request.session.get("_session_expires_at") is None:
        _session_begin(request)
    return True


def _looks_like_oauth_subject(value: str) -> bool:
    """True for Google/Discord-style numeric subject IDs mistaken for a display name."""
    s = str(value or "").strip()
    if not s:
        return False
    if s.isdigit() and len(s) >= 15:
        return True
    return False


def _human_login_name(*, username: str = "", email: str = "", sub: str = "") -> str:
    """Prefer email (or a non-subject username) for UI display names."""
    u = str(username or "").strip()
    e = str(email or "").strip()
    s = str(sub or "").strip()
    if e and (not u or u == s or _looks_like_oauth_subject(u)):
        return e
    if u and not _looks_like_oauth_subject(u):
        return u
    if e:
        return e
    if u:
        return u
    return s or "user"


def _user(request: Request) -> dict[str, Any]:
    username = str(request.session.get("username") or "").strip()
    email = str(request.session.get("email") or "").strip()
    sub = str(request.session.get("sub") or "").strip()
    display = _human_login_name(username=username, email=email, sub=sub)
    # Heal session if a prior login stored the OAuth subject as username.
    if email and username != display and (_looks_like_oauth_subject(username) or username == sub):
        request.session["username"] = display
        username = display
    return {
        "username": display or username,
        "email": email,
        "provider": request.session.get("provider") or "",
        "sub": sub,
    }


def _require_auth(request: Request) -> RedirectResponse | None:
    if _authed(request):
        return None
    return RedirectResponse("/login", status_code=302)


@app.middleware("http")
async def enforce_liability_ack(request: Request, call_next):
    """Block API/mutations until the post-login risk dialog is accepted."""
    try:
        session = request.session
    except AssertionError:
        return await call_next(request)
    if not bool(session.get("authenticated")):
        return await call_next(request)
    if _session_expired(request):
        return await call_next(request)
    if _liability_acknowledged(request):
        return await call_next(request)
    path = request.url.path or "/"
    method = request.method or "GET"
    if _liability_gate_allowed(path, method):
        return await call_next(request)
    if path.startswith("/api/") or path.startswith("/ws"):
        return JSONResponse(
            {
                "ok": False,
                "error": "Please accept the Hayabusa platform risk acknowledgment to continue.",
                "code": "liability_ack_required",
            },
            status_code=403,
        )
    # Prefer setup when first-run is incomplete so the dialog appears there.
    try:
        home = "/setup" if not setup.completed() else "/"
    except Exception:
        home = "/"
    return RedirectResponse(home, status_code=302)


def _post_login_home() -> str:
    """After sign-in: first-run setup for a fresh volume, otherwise the dashboard."""
    return "/setup" if not setup.completed() else "/"


def _require_setup_complete(request: Request) -> RedirectResponse | None:
    """Gate protected HTML pages until the admin finishes /setup."""
    if setup.completed():
        return None
    return RedirectResponse("/setup", status_code=302)


def _can_manage_setup(request: Request) -> bool:
    """First signer is bootstrap admin; only Owner/admins may complete or redo setup."""
    if not _authed(request):
        return False
    key = _rbac_key(request)
    rbac.ensure_bootstrap_admin(
        username=request.session.get("username") or key,
        email=request.session.get("email") or "",
        sub=request.session.get("sub") or "",
    )
    return rbac.is_owner_or_admin(key)

def _rbac_key(request: Request) -> str:
    u = _user(request)
    return rbac.resolve_user_key(
        username=u.get("username") or "",
        email=u.get("email") or "",
        sub=u.get("sub") or "",
    )


def _require_perm(request: Request, permission: str) -> JSONResponse | None:
    if not _authed(request):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    key = _rbac_key(request)
    rbac.ensure_bootstrap_admin(
        username=request.session.get("username") or key,
        email=request.session.get("email") or "",
        sub=request.session.get("sub") or "",
    )
    if not rbac.has_permission(key, permission):
        return JSONResponse(
            {
                "ok": False,
                "error": f"missing permission: {permission}",
                "code": "forbidden",
                "required_permission": permission,
            },
            status_code=403,
        )
    return None


def _require_any_perm(request: Request, *permissions: str) -> JSONResponse | None:
    if not _authed(request):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    key = _rbac_key(request)
    rbac.ensure_bootstrap_admin(
        username=request.session.get("username") or key,
        email=request.session.get("email") or "",
        sub=request.session.get("sub") or "",
    )
    if any(rbac.has_permission(key, p) for p in permissions):
        return None
    return JSONResponse(
        {
            "ok": False,
            "error": f"missing permission: one of {', '.join(permissions)}",
            "code": "forbidden",
            "required_permissions": list(permissions),
        },
        status_code=403,
    )


def _is_owner_or_admin(request: Request) -> bool:
    if not _authed(request):
        return False
    key = _rbac_key(request)
    rbac.ensure_bootstrap_admin(
        username=request.session.get("username") or key,
        email=request.session.get("email") or "",
        sub=request.session.get("sub") or "",
    )
    return rbac.is_owner_or_admin(key)


def _require_owner_or_admin(request: Request) -> JSONResponse | RedirectResponse | None:
    """Administration surface — Owner/admin only."""
    if not _authed(request):
        return RedirectResponse("/login", status_code=302)
    if _is_owner_or_admin(request):
        return None
    path = request.url.path or "/"
    if path.startswith("/api/"):
        return JSONResponse(
            {
                "ok": False,
                "error": "Administration is limited to Owners and admins",
                "code": "admin_only",
            },
            status_code=403,
        )
    return RedirectResponse("/", status_code=302)


def _can_read_secrets(request: Request) -> bool:
    key = _rbac_key(request)
    return rbac.has_permission(key, "read_secrets") or rbac.has_permission(key, "manage_secrets")


def _can_manage_secrets(request: Request) -> bool:
    return rbac.has_permission(_rbac_key(request), "manage_secrets")


def _gitops_blocks_workspace_writes() -> JSONResponse | None:
    if gitops.enabled():
        return JSONResponse(
            {
                "ok": False,
                "error": "GitOps mode is enabled — local Ansible/OpenTofu workspace is read-only. Edit the GitHub/GitLab repository instead.",
                "code": "gitops_readonly",
            },
            status_code=409,
        )
    return None


async def _push_gitops_config_to_hayabusa(*, trigger_pull: bool = False) -> dict[str, Any]:
    """Push GitOps config (no secret values) to Hayabusa over the mesh bridge."""
    payload = {
        "type": "gitops.config.set",
        "config": gitops.bridge_config_payload(),
        "user": {},
        "ts": int(time.time()),
        "trigger_pull": bool(trigger_pull),
    }
    sent = await bridge.send_event(payload)
    return {"sent": bool(sent), "enabled": gitops.enabled()}


def _secrets_public_for_request(request: Request) -> dict[str, Any]:
    body = vault.public_status()
    if _authed(request):
        body["can_manage"] = _can_manage_secrets(request)
        body["can_read"] = _can_read_secrets(request)
    return body


def _oauth_cfg(provider: str) -> dict[str, Any]:
    """Merge sealed vault credentials into runtime OAuth config (secrets never leave server)."""
    base = dict(_settings.oauth.get(provider) or {})
    sealed = oauth_store.get(provider)
    if sealed.get("client_id"):
        base["client_id"] = sealed["client_id"]
    if sealed.get("client_secret"):
        base["client_secret"] = sealed["client_secret"]
    if provider == "microsoft" and sealed.get("tenant_id"):
        base["tenant_id"] = sealed["tenant_id"]
    base["redirect_uri"] = f"{_settings.public_base_url}/auth/{provider}/callback"
    if provider == "microsoft":
        base["redirect_uri"] = f"{_settings.public_base_url}/auth/microsoft/callback"
    return base


def _provider_ready(provider: str) -> bool:
    cfg = _oauth_cfg(provider)
    return bool(cfg.get("client_id") and cfg.get("client_secret"))


def _oauth_broker_mode() -> bool:
    mode = (os.environ.get("CONTROLLER_OAUTH_MODE") or "broker").strip().lower()
    return mode in {"broker", "hayabusa", "proxy", ""}


def _controller_oauth_hmac(msg: str) -> str:
    # Legacy only — preferred path redeems tickets at Hayabusa (no shared secret).
    key = (_settings.controller_bridge_token or _settings.secret_key or "").encode("utf-8")
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).hexdigest()


async def _redeem_oauth_ticket(ticket: str, sig: str) -> dict[str, Any] | None:
    """Ask Hayabusa to verify a broker ticket (signing key stays on Hayabusa)."""
    base = (_settings.hayabusa_public_url or "https://hayabusa.tracedroute.net").rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            resp = await client.post(
                f"{base}/api/controller/oauth/redeem",
                json={"ticket": ticket, "sig": sig},
                headers={"Accept": "application/json", "Content-Type": "application/json"},
            )
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        if resp.status_code >= 400 or not isinstance(data, dict) or not data.get("ok"):
            return None
        return data
    except Exception as exc:  # noqa: BLE001
        logger.warning("oauth ticket redeem failed: %s", exc)
        return None


async def _finish_login(request: Request, *, username: str, email: str, provider: str, sub: str = "") -> RedirectResponse:
    now = int(time.time())
    email_n = str(email or "").strip()
    sub_n = str(sub or "").strip()
    username_n = _human_login_name(username=str(username or "").strip(), email=email_n, sub=sub_n)
    request.session["authenticated"] = True
    request.session["username"] = username_n
    request.session["email"] = email_n
    request.session["provider"] = provider
    request.session["sub"] = sub_n or username_n
    request.session["login_at"] = now
    request.session["can_manual_mesh_override"] = False
    _liability_require_on_login(request)
    _session_begin(request)
    try:
        rbac.ensure_bootstrap_admin(
            username=username_n,
            email=email_n,
            sub=sub_n or username_n,
            provider=str(provider or "").strip().lower(),
            touch_activity=True,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("rbac bootstrap failed: %s", exc)
    # Phone-home in background so login is not blocked on mesh join (can take ~30–90s).
    # Progress streams to the dashboard via /ws/status (connection pipeline).
    user = _user(request)
    skip_connect = (os.environ.get("CONTROLLER_SKIP_POST_LOGIN_CONNECT") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if skip_connect:
        return RedirectResponse(_post_login_home(), status_code=302)

    async def _bg_connect() -> None:
        try:
            await connection.set_step("enroll", "pending", "Starting after sign-in…")
            # Capture identity now; do not rely on request.session after redirect returns.
            await _refresh_user_capabilities(request, user)
            enroller.save_owner_identity(user)
            await _connect_to_hayabusa(user, request=request)
        except Exception as exc:  # noqa: BLE001
            logger.warning("hayabusa phone-home after login failed: %s", exc)
            await connection.set_step("enroll", "failed", str(exc)[:300])

    asyncio.create_task(_bg_connect())
    return RedirectResponse(_post_login_home(), status_code=302)


@app.get("/api/session/status")
async def api_session_status(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"ok": False, "authenticated": False, "code": "not_authenticated"}, status_code=401)
    return JSONResponse(_session_status(request))


@app.post("/api/session/renew")
async def api_session_renew(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"ok": False, "authenticated": False, "code": "not_authenticated"}, status_code=401)
    _session_begin(request)
    try:
        rbac.ensure_bootstrap_admin(
            username=request.session.get("username") or "",
            email=request.session.get("email") or "",
            sub=request.session.get("sub") or "",
            provider=str(request.session.get("provider") or "").strip().lower(),
            touch_activity=True,
        )
    except Exception:  # noqa: BLE001
        pass
    payload = _session_status(request)
    payload["renewed"] = True
    return JSONResponse(payload)


@app.post("/api/liability/acknowledge")
async def api_liability_acknowledge(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"ok": False, "authenticated": False, "code": "not_authenticated"}, status_code=401)
    request.session["liability_ack"] = True
    request.session["liability_ack_at"] = int(time.time())
    return JSONResponse(
        {
            "ok": True,
            "authenticated": True,
            "liability_acknowledged": True,
            "liability_ack_at": request.session.get("liability_ack_at"),
        }
    )


@app.get("/api/rbac")
async def api_rbac_catalog(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    key = _rbac_key(request)
    rbac.ensure_bootstrap_admin(
        username=request.session.get("username") or key,
        email=request.session.get("email") or "",
        sub=request.session.get("sub") or "",
    )
    cat = rbac.public_catalog()
    highest = rbac.highest_rank(key)
    ceiling = rbac.grant_ceiling(key)
    cat["me"] = {
        "user_key": key,
        "username": request.session.get("username") or "",
        "email": request.session.get("email") or "",
        "display_name": _human_login_name(
            username=str(request.session.get("username") or ""),
            email=str(request.session.get("email") or ""),
            sub=str(request.session.get("sub") or ""),
        ),
        "permissions": sorted(rbac.user_permissions(key)),
        "highest_rank": highest,
        "grant_ceiling": ceiling,
        "grantable_roles": rbac.grantable_roles(key),
        "can_manage_rbac": rbac.has_permission(key, "manage_rbac"),
        "is_owner_or_admin": rbac.is_owner_or_admin(key),
        "roles": rbac.user_roles(key),
    }
    return JSONResponse(cat)


@app.put("/api/rbac/roles/order")
async def api_rbac_reorder_roles(request: Request) -> JSONResponse:
    admin_gate = _require_owner_or_admin(request)
    if isinstance(admin_gate, (JSONResponse, RedirectResponse)):
        return admin_gate
    denied = _require_perm(request, "manage_rbac")
    if denied:
        return denied
    body = await request.json()
    if not isinstance(body, dict):
        body = {}
    order = body.get("order") or body.get("roles") or []
    if not isinstance(order, list):
        return JSONResponse({"ok": False, "error": "order must be a list"}, status_code=400)
    out = rbac.reorder_roles(actor_key=_rbac_key(request), order=[str(x) for x in order])
    code = 200 if out.get("ok") else 400
    if out.get("code") in {"forbidden", "forbidden_perm"}:
        code = 403
    if out.get("code") == "not_found":
        code = 404
    return JSONResponse(out, status_code=code)


@app.post("/api/rbac/roles")
async def api_rbac_create_role(request: Request) -> JSONResponse:
    admin_gate = _require_owner_or_admin(request)
    if isinstance(admin_gate, (JSONResponse, RedirectResponse)):
        return admin_gate
    denied = _require_perm(request, "manage_rbac")
    if denied:
        return denied
    body = await request.json()
    if not isinstance(body, dict):
        body = {}
    out = rbac.create_role(
        actor_key=_rbac_key(request),
        name=str(body.get("name") or body.get("id") or ""),
        permissions=list(body.get("permissions") or []),
        rank=body.get("rank"),
        label=str(body.get("label") or ""),
    )
    code = 200 if out.get("ok") else 400
    if out.get("code") == "forbidden" or out.get("code") == "forbidden_perm":
        code = 403
    return JSONResponse(out, status_code=code)


@app.patch("/api/rbac/roles/{role_name}")
async def api_rbac_update_role(request: Request, role_name: str) -> JSONResponse:
    admin_gate = _require_owner_or_admin(request)
    if isinstance(admin_gate, (JSONResponse, RedirectResponse)):
        return admin_gate
    denied = _require_perm(request, "manage_rbac")
    if denied:
        return denied
    body = await request.json()
    if not isinstance(body, dict):
        body = {}
    kwargs: dict[str, Any] = {
        "actor_key": _rbac_key(request),
        "name": role_name,
    }
    if "permissions" in body:
        kwargs["permissions"] = list(body.get("permissions") or [])
    if "rank" in body:
        kwargs["rank"] = body.get("rank")
    if "label" in body:
        kwargs["label"] = str(body.get("label") or "")
    out = rbac.update_role(**kwargs)
    code = 200 if out.get("ok") else 400
    if out.get("code") in {"forbidden", "forbidden_perm"}:
        code = 403
    if out.get("code") == "not_found":
        code = 404
    return JSONResponse(out, status_code=code)


@app.delete("/api/rbac/roles/{role_name}")
async def api_rbac_delete_role(request: Request, role_name: str) -> JSONResponse:
    admin_gate = _require_owner_or_admin(request)
    if isinstance(admin_gate, (JSONResponse, RedirectResponse)):
        return admin_gate
    denied = _require_perm(request, "manage_rbac")
    if denied:
        return denied
    out = rbac.delete_role(actor_key=_rbac_key(request), name=role_name)
    code = 200 if out.get("ok") else 400
    if out.get("code") == "forbidden":
        code = 403
    if out.get("code") == "not_found":
        code = 404
    return JSONResponse(out, status_code=code)


@app.post("/api/rbac/users")
async def api_rbac_upsert_user(request: Request) -> JSONResponse:
    admin_gate = _require_owner_or_admin(request)
    if isinstance(admin_gate, (JSONResponse, RedirectResponse)):
        return admin_gate
    denied = _require_perm(request, "manage_rbac")
    if denied:
        return denied
    body = await request.json()
    if not isinstance(body, dict):
        body = {}
    roles = body.get("roles")
    if isinstance(roles, str):
        roles = [roles]
    out = rbac.upsert_user(
        username=str(body.get("username") or ""),
        email=str(body.get("email") or ""),
        sub=str(body.get("sub") or ""),
        roles=list(roles) if isinstance(roles, list) else None,
        team_ids=list(body.get("team_ids") or []) if "team_ids" in body else None,
        actor_key=_rbac_key(request),
        user_key=str(body.get("user_key") or ""),
        provider=str(body.get("provider") or ""),
    )
    code = 200 if out.get("ok") else 400
    if out.get("code") in {"forbidden", "forbidden_role"}:
        code = 403
    return JSONResponse(out, status_code=code)


@app.post("/api/rbac/teams")
async def api_rbac_create_team(request: Request) -> JSONResponse:
    admin_gate = _require_owner_or_admin(request)
    if isinstance(admin_gate, (JSONResponse, RedirectResponse)):
        return admin_gate
    denied = _require_perm(request, "manage_rbac")
    if denied:
        return denied
    body = await request.json()
    if not isinstance(body, dict):
        body = {}
    return JSONResponse(
        rbac.create_team(
            name=str(body.get("name") or ""),
            member_keys=list(body.get("member_keys") or []),
        )
    )


@app.post("/api/rbac/playbook-owner")
async def api_rbac_playbook_owner(request: Request) -> JSONResponse:
    denied = _require_perm(request, "write_playbooks")
    if denied:
        # admins with write_all also ok
        if not rbac.has_permission(_rbac_key(request), "write_all_playbooks"):
            return denied
    body = await request.json()
    if not isinstance(body, dict):
        body = {}
    key = _rbac_key(request)
    owner_type = str(body.get("owner_type") or "user")
    owner_id = str(body.get("owner_id") or key)
    # Non-admins can only assign to themselves or their teams
    if not rbac.has_permission(key, "manage_rbac") and not rbac.has_permission(key, "write_all_playbooks"):
        if owner_type == "user" and _norm_user_key(owner_id) != key:
            return JSONResponse({"ok": False, "error": "can only own as yourself"}, status_code=403)
        if owner_type == "team":
            cat = rbac.public_catalog()
            me = next((u for u in cat["users"] if u.get("user_key") == key or _norm_user_key(u.get("username") or "") == key), {})
            if owner_id not in (me.get("team_ids") or []):
                return JSONResponse({"ok": False, "error": "not a member of that team"}, status_code=403)
    out = rbac.set_playbook_owner(str(body.get("path") or ""), owner_type=owner_type, owner_id=owner_id)
    code = 200 if out.get("ok") else 400
    return JSONResponse(out, status_code=code)


@app.post("/api/playbooks/sync-hayabusa")
async def api_playbooks_sync_hayabusa(request: Request) -> JSONResponse:
    """Push owned playbooks (secret names only) to this user's Hayabusa workspace via mesh bridge."""
    if gitops.enabled():
        return JSONResponse(
            {
                "ok": False,
                "error": "GitOps mode is enabled — playbooks sync from GitHub/GitLab via Hayabusa, not from the local workspace.",
                "code": "gitops_enabled",
            },
            status_code=409,
        )
    denied = _require_perm(request, "sync_hayabusa")
    if denied:
        # allow read_all as well
        if not rbac.has_permission(_rbac_key(request), "read_all_playbooks"):
            return denied
    key = _rbac_key(request)
    exported = rbac.export_owned_files(
        key,
        read_file=_rpc_read_file,
        list_tree=_rpc_list_tree,
    )
    if not exported.get("ok"):
        return JSONResponse(exported, status_code=400)
    payload = {
        "type": "iac_sync",
        "user": _user(request),
        "user_key": key,
        "files": exported.get("files") or [],
        "count": exported.get("count") or 0,
        "ts": int(time.time()),
        "hayabusa_saw_secret_values": False,
    }
    sent = await bridge.send_event(payload)
    if not sent:
        return JSONResponse(
            {
                "ok": False,
                "error": "Controller is not connected to Hayabusa over the mesh bridge",
                "code": "bridge_disconnected",
                "exported_count": exported.get("count") or 0,
            },
            status_code=503,
        )
    return JSONResponse(
        {
            "ok": True,
            "synced": True,
            "count": exported.get("count") or 0,
            "bytes": exported.get("bytes") or 0,
            "message": "Playbooks pushed to Hayabusa for your authenticated session workspace.",
            "hayabusa_saw_secret_values": False,
        }
    )


@app.get("/api/gitops/config")
async def api_gitops_config_get(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    out = gitops.public_config()
    # Hint webhook URL for admins (Hayabusa public base if known).
    st = bridge.status()
    mesh_hint = str((st or {}).get("ws_url") or "")
    out["webhook_paths"] = {
        "github": "/api/gitops/webhook/github",
        "gitlab": "/api/gitops/webhook/gitlab",
    }
    out["webhook_note"] = (
        "Register the webhook on your GitHub/GitLab repo pointing at your Hayabusa hub URL "
        "+ the path above. Use the vault webhook secret value as the webhook secret / token."
    )
    out["bridge_connected"] = bool((st or {}).get("connected") and (st or {}).get("granted"))
    out["can_manage"] = rbac.has_permission(_rbac_key(request), "manage_gitops") or rbac.has_permission(
        _rbac_key(request), "manage_rbac"
    )
    out["mesh_ws_hint"] = mesh_hint[:200]
    return JSONResponse(out)


@app.put("/api/gitops/config")
async def api_gitops_config_put(request: Request) -> JSONResponse:
    denied = _require_perm(request, "manage_gitops")
    if denied:
        if not rbac.has_permission(_rbac_key(request), "manage_rbac"):
            return denied
    body = await request.json()
    if not isinstance(body, dict):
        body = {}
    # Validate secret keys exist when enabling
    if body.get("enabled"):
        for field in ("auth_secret_key", "webhook_secret_key"):
            sk = str(body.get(field) or "").strip()
            if sk and vault.get(sk) is None:
                return JSONResponse(
                    {"ok": False, "error": f"vault secret not found: {sk}", "code": "secret_missing", "field": field},
                    status_code=400,
                )
    out = gitops.update(body, updated_by=_rbac_key(request))
    if not out.get("ok"):
        return JSONResponse(out, status_code=400)
    push = await _push_gitops_config_to_hayabusa(trigger_pull=bool(out.get("enabled")))
    out["hayabusa_push"] = push
    if out.get("enabled") and not push.get("sent"):
        out["warning"] = "Config saved locally, but Hayabusa bridge is disconnected — push will retry on Sync now."
    return JSONResponse(out)


@app.post("/api/gitops/test")
async def api_gitops_test(request: Request) -> JSONResponse:
    denied = _require_perm(request, "manage_gitops")
    if denied:
        if not rbac.has_permission(_rbac_key(request), "manage_rbac"):
            return denied
    cfg = gitops.get()
    auth_key = str(cfg.get("auth_secret_key") or "").strip()
    if not auth_key:
        return JSONResponse({"ok": False, "error": "auth_secret_key not configured"}, status_code=400)
    token = vault.get(auth_key)
    if not token:
        return JSONResponse({"ok": False, "error": "auth vault secret missing or empty"}, status_code=400)
    provider = str(cfg.get("provider") or "github")
    base = str(cfg.get("base_url") or "").rstrip("/")
    repo = str(cfg.get("repo") or "").strip("/")
    if not repo:
        return JSONResponse({"ok": False, "error": "repo not configured"}, status_code=400)
    headers = {"Accept": "application/json", "User-Agent": "hayabusa-controller-gitops"}
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            if provider == "gitlab":
                # GitLab API: /api/v4/projects/:id — project path URL-encoded
                api_base = base
                if "gitlab.com" in base or base.endswith("/gitlab"):
                    pass
                # Self-hosted and gitlab.com both expose /api/v4
                project = urllib.parse.quote(repo, safe="")
                url = f"{api_base}/api/v4/projects/{project}"
                headers["PRIVATE-TOKEN"] = token
            else:
                # GitHub API (cloud or GHE): derive api host
                if "github.com" in base:
                    url = f"https://api.github.com/repos/{repo}"
                else:
                    url = f"{base}/api/v3/repos/{repo}"
                headers["Authorization"] = f"Bearer {token}"
            resp = await client.get(url, headers=headers)
            if resp.status_code >= 400:
                return JSONResponse(
                    {
                        "ok": False,
                        "error": f"remote returned HTTP {resp.status_code}",
                        "detail": (resp.text or "")[:300],
                        "url": url,
                    },
                    status_code=400,
                )
            data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            name = ""
            if isinstance(data, dict):
                name = str(data.get("full_name") or data.get("path_with_namespace") or data.get("name") or "")
            return JSONResponse(
                {
                    "ok": True,
                    "reachable": True,
                    "provider": provider,
                    "repo": repo,
                    "remote_name": name,
                    "message": "Repository reachable with the configured token.",
                }
            )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"ok": False, "error": str(exc)[:300]}, status_code=400)


@app.post("/api/gitops/sync-now")
async def api_gitops_sync_now(request: Request) -> JSONResponse:
    denied = _require_perm(request, "manage_gitops")
    if denied:
        if not rbac.has_permission(_rbac_key(request), "manage_rbac"):
            return denied
    if not gitops.enabled():
        return JSONResponse({"ok": False, "error": "GitOps is not enabled"}, status_code=400)
    push = await _push_gitops_config_to_hayabusa(trigger_pull=False)
    if not push.get("sent"):
        return JSONResponse(
            {"ok": False, "error": "Controller is not connected to Hayabusa over the mesh bridge", "code": "bridge_disconnected"},
            status_code=503,
        )
    sent = await bridge.send_event(
        {
            "type": "gitops.pull",
            "config": gitops.bridge_config_payload(),
            "source": "controller_sync_now",
            "ts": int(time.time()),
        }
    )
    if not sent:
        return JSONResponse({"ok": False, "error": "failed to send gitops.pull", "code": "bridge_disconnected"}, status_code=503)
    return JSONResponse({"ok": True, "message": "Pull requested on Hayabusa", "config_pushed": True})


@app.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request) -> HTMLResponse:
    """One-time first-run wizard — admin only; inaccessible after completion."""
    redir = _require_auth(request)
    if redir:
        return redir
    if setup.completed():
        return RedirectResponse("/", status_code=302)
    # Ensure first signer is bootstrap admin before rendering.
    _can_manage_setup(request)
    return TEMPLATES.TemplateResponse(
        request,
        "setup.html",
        {
            "user": _user(request),
            "csrf_token": ctrl_security.ensure_csrf_token(request.session),
            "can_manage": _can_manage_setup(request),
        },
    )


@app.get("/api/setup/status")
async def api_setup_status(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    out = setup.public_status()
    out["can_manage"] = _can_manage_setup(request)
    return JSONResponse(out)


@app.post("/api/setup/reset")
async def api_setup_reset(request: Request) -> JSONResponse:
    """Admin-only: clear first-run completion so the setup wizard can be run again."""
    if not _authed(request):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    if not _can_manage_setup(request):
        return JSONResponse(
            {
                "ok": False,
                "error": "only administrators can redo first-run setup",
                "code": "forbidden",
            },
            status_code=403,
        )
    actor = str(request.session.get("username") or request.session.get("email") or "")[:128]
    out = setup.reset(reset_by=actor)
    out["redirect"] = "/setup"
    return JSONResponse(out)


@app.post("/api/setup/complete")
async def api_setup_complete(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    if setup.completed():
        return JSONResponse(
            {"ok": False, "error": "setup already completed", "code": "already_complete"},
            status_code=409,
        )
    if not _can_manage_setup(request):
        return JSONResponse(
            {
                "ok": False,
                "error": "only the administrator can complete first-run setup",
                "code": "forbidden",
            },
            status_code=403,
        )
    body = await request.json()
    if not isinstance(body, dict):
        body = {}
    mode = str(body.get("mode") or "").strip().lower()
    actor = _rbac_key(request)

    if mode == "novice":
        # Keep GitOps off; seed local Ansible/OpenTofu defaults.
        if gitops.enabled():
            gitops.update({"enabled": False}, updated_by=actor)
        devops.seed_from_defaults()
        out = setup.mark_complete(mode="novice", completed_by=actor)
        return JSONResponse(out)

    if mode != "advanced":
        return JSONResponse(
            {"ok": False, "error": "mode must be novice or advanced", "code": "invalid_mode"},
            status_code=400,
        )

    auth_key = str(body.get("auth_secret_key") or "gitops_github_pat").strip()
    webhook_key = str(body.get("webhook_secret_key") or "gitops_webhook_secret").strip()
    auth_token = str(body.get("auth_token") or "")
    webhook_secret = str(body.get("webhook_secret") or "")
    if not auth_token.strip():
        return JSONResponse(
            {"ok": False, "error": "auth_token is required", "code": "missing_token"},
            status_code=400,
        )
    if not webhook_secret.strip():
        return JSONResponse(
            {"ok": False, "error": "webhook_secret is required", "code": "missing_webhook_secret"},
            status_code=400,
        )
    try:
        vault.put(
            auth_key,
            auth_token,
            category="gitops",
            kind="token",
            label="GitOps auth token (setup)",
            updated_by=actor,
        )
        vault.put(
            webhook_key,
            webhook_secret,
            category="gitops",
            kind="webhook_secret",
            label="GitOps webhook secret (setup)",
            updated_by=actor,
        )
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    provider = str(body.get("provider") or "github").strip().lower() or "github"
    git_body = {
        "enabled": True,
        "provider": provider,
        "base_url": str(body.get("base_url") or "").strip(),
        "repo": str(body.get("repo") or "").strip(),
        "ref": str(body.get("ref") or "main").strip() or "main",
        "path_prefix": str(body.get("path_prefix") or "").strip(),
        "auth_secret_key": auth_key,
        "webhook_secret_key": webhook_key,
        "poll_seconds": body.get("poll_seconds") or 600,
    }
    gout = gitops.update(git_body, updated_by=actor)
    if not gout.get("ok"):
        return JSONResponse(gout, status_code=400)
    push = await _push_gitops_config_to_hayabusa(trigger_pull=True)
    out = setup.mark_complete(mode="advanced", completed_by=actor)
    out["gitops"] = gout
    out["hayabusa_push"] = push
    if not push.get("sent"):
        out["warning"] = (
            "Setup saved. Hayabusa bridge is not connected yet — GitOps config will push when the mesh is up "
            "(use Sync now on the GitOps tab)."
        )
    return JSONResponse(out)


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    vpn_st = vpn.status()
    br = bridge.status()
    vpn_health = vpn_st.get("health") or vpn.health_state()
    from .wan_public_ip import discover_wan_public_identity

    loc = await asyncio.to_thread(discover_wan_public_identity)
    conn = _connection_public()
    return {
        "ok": True,
        "service": "hayabusa-controller",
        "version": "0.1.0",
        "public_base_url": _settings.public_base_url,
        "public_base_auto": bool(getattr(_settings, "public_base_auto", False)),
        "tls": bool(getattr(_settings, "tls_enabled", False)),
        "vpn": vpn_health,
        "vpn_connected": bool(vpn_st.get("connected")),
        "vpn_error_code": vpn_st.get("error_code") or "",
        "bridge": "granted" if br.get("granted") else ("connected" if br.get("connected") else "disconnected"),
        "bridge_granted": bool(br.get("granted")),
        # Use live-enriched phase so a Tailscale IP cannot report ready without grant.
        "connection_phase": conn.get("phase"),
        "connection_ready": bool(conn.get("ready")),
        "public_ip": loc.get("public_ip") or "",
        "wan_public_ip": loc.get("wan_public_ip") or "",
        "vpn_endpoint_ip": loc.get("vpn_endpoint_ip") or "",
        "geo_ip": loc.get("geo_ip") or "",
    }


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> HTMLResponse:
    if _authed(request):
        return RedirectResponse(_post_login_home(), status_code=302)
    # Broker mode: IdP apps live on Hayabusa — never require local client secrets.
    if _oauth_broker_mode():
        any_oauth = True
        google_ok = True
    else:
        any_oauth = any(_provider_ready(p) for p in ("google", "github", "discord", "slack", "microsoft"))
        google_ok = _provider_ready("google")
    turnstile_on = ctrl_security.turnstile_configured()
    return TEMPLATES.TemplateResponse(
        request,
        "login.html",
        {
            "manual_login_enabled": bool(_settings.manual_password),
            "manual_admin_login_enabled": bool(_settings.manual_password),
            # Authenticator (Hayabusa Auth / TOTP) is brokered through Hayabusa.
            # Password remains a local break-glass for CONTROLLER_MANUAL_USERNAME.
            "hayabusa_auth_enabled": True,
            "google_oauth_configured": google_ok,
            "sso_enabled": False,
            "manual_login_error": request.query_params.get("error") or "",
            "flash_messages": [],
            "turnstile_enabled": turnstile_on,
            "turnstile_site_key": ctrl_security.turnstile_site_key() if turnstile_on else "",
            "csrf_token": ctrl_security.ensure_csrf_token(request.session),
            "oauth_broker": _oauth_broker_mode(),
            "oauth_broker_ready": True if _oauth_broker_mode() else bool((_settings.controller_bridge_token or "").strip()),
        },
    )


@app.post("/login/manual")
async def login_manual(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
) -> RedirectResponse:
    u = (username or "").strip()
    p = password or ""
    ip = ctrl_security.client_ip(request)
    if not _settings.manual_password:
        return RedirectResponse("/login?error=Manual%20sign-in%20is%20not%20configured", status_code=302)
    if ctrl_security.turnstile_configured():
        ts = await ctrl_security.extract_turnstile_from_request(request)
        ok_ts, msg_ts = ctrl_security.verify_turnstile(ts, ip)
        if not ok_ts:
            ctrl_security.log_auth_failure(ip, "turnstile")
            return RedirectResponse(
                f"/login?error={urllib.parse.quote(msg_ts or 'Bot check failed')}",
                status_code=302,
            )
    if u == _settings.manual_username and secrets.compare_digest(p, _settings.manual_password):
        return await _finish_login(request, username=u, email="", provider="manual", sub=u)
    ok_fail, msg_fail = ctrl_security.check_ip_rate_limit("login_fail", ip)
    ctrl_security.log_auth_failure(ip, "bad_credentials")
    if not ok_fail:
        return RedirectResponse(
            f"/login?error={urllib.parse.quote(msg_fail or 'Too many failed attempts')}",
            status_code=302,
        )
    return RedirectResponse("/login?error=Invalid%20username%20or%20password", status_code=302)


# Compatibility with Hayabusa login form field names
@app.post("/auth/manual")
async def login_manual_alias(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    admin_username: str = Form(""),
    admin_password: str = Form(""),
) -> RedirectResponse:
    return await login_manual(
        request,
        username=admin_username or username,
        password=admin_password or password,
    )


def _hayabusa_http_base() -> str:
    """Hub the controller can actually reach for Hayabusa Auth (prefer LAN from WS URL)."""
    ws = (os.environ.get("HAYABUSA_WS_URL") or os.environ.get("HAYABUSA_WS_MESH_URL") or "").strip()
    host = ""
    if ws.startswith("ws://"):
        host = ws[5:].split("/")[0]
        if ":" in host:
            host = host.rsplit(":", 1)[0]
        if host:
            return f"http://{host}:8086"
    if ws.startswith("wss://"):
        host = ws[6:].split("/")[0]
        if ":" in host:
            host = host.rsplit(":", 1)[0]
        if host:
            return f"https://{host}"
    raw = (_settings.hayabusa_public_url or "").strip().rstrip("/")
    if raw:
        return raw
    return "https://hayabusa.tracedroute.net"


async def _hayabusa_totp_proxy(request: Request, hay_path: str, payload: dict[str, Any]) -> JSONResponse:
    """Forward Hayabusa Auth to the hub; keep Hayabusa cookies on this appliance session."""
    base = _hayabusa_http_base()
    cookies = dict(request.session.get("hayabusa_totp_cookies") or {})
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    csrf = str(request.session.get("hayabusa_totp_csrf") or "").strip()
    if csrf:
        headers["X-CSRF-Token"] = csrf
    try:
        async with httpx.AsyncClient(timeout=25.0, follow_redirects=False) as client:
            resp = await client.post(
                f"{base}{hay_path}",
                json=payload,
                headers=headers,
                cookies=cookies,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("hayabusa totp proxy failed: %s", exc)
        return JSONResponse(
            {"success": False, "error": "Unable to reach Hayabusa for authenticator sign-in."},
            status_code=502,
        )
    jar = dict(cookies)
    for name, value in resp.cookies.items():
        jar[str(name)] = str(value)
    request.session["hayabusa_totp_cookies"] = jar
    nt = resp.headers.get("X-CSRF-Token") or resp.headers.get("X-CSRFToken")
    if nt:
        request.session["hayabusa_totp_csrf"] = nt
    try:
        data = resp.json()
        if not isinstance(data, dict):
            data = {"success": False, "error": "Invalid response from Hayabusa."}
    except Exception:  # noqa: BLE001
        data = {"success": False, "error": f"Hayabusa returned HTTP {resp.status_code}."}
    return JSONResponse(data, status_code=resp.status_code if resp.status_code < 500 else resp.status_code)


def _totp_broker_envelope(request: Request, body: dict[str, Any]) -> dict[str, Any]:
    state = str(request.session.get("oauth_state_totp") or "").strip()
    if not state:
        state = secrets.token_urlsafe(24)
        request.session["oauth_state_totp"] = state
    return_to = f"{_browser_base(request)}/auth/oauth/finish"
    exp = str(int(time.time()) + 600)
    out = dict(body or {})
    out["return_to"] = return_to
    out["state"] = state
    out["exp"] = exp
    if (_settings.controller_bridge_token or "").strip():
        out["sig"] = _controller_oauth_hmac(f"totp|{return_to}|{state}|{exp}")
    return out


@app.post("/api/auth/totp/begin")
async def api_auth_totp_begin(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = {}
    if not isinstance(body, dict):
        body = {}
    request.session["oauth_state_totp"] = secrets.token_urlsafe(24)
    payload = _totp_broker_envelope(request, body)
    return await _hayabusa_totp_proxy(request, "/api/controller/auth/totp/begin", payload)


@app.post("/api/auth/totp/setup")
async def api_auth_totp_setup(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = {}
    if not isinstance(body, dict):
        body = {}
    payload = _totp_broker_envelope(request, body)
    return await _hayabusa_totp_proxy(request, "/api/controller/auth/totp/setup", payload)


@app.post("/api/auth/totp/verify")
async def api_auth_totp_verify(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = {}
    if not isinstance(body, dict):
        body = {}
    payload = _totp_broker_envelope(request, body)
    return await _hayabusa_totp_proxy(request, "/api/controller/auth/totp/verify", payload)


@app.post("/api/auth/totp/re-enroll")
async def api_auth_totp_re_enroll(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = {}
    if not isinstance(body, dict):
        body = {}
    payload = _totp_broker_envelope(request, body)
    return await _hayabusa_totp_proxy(request, "/api/controller/auth/totp/re-enroll", payload)


@app.get("/logout")
async def logout(request: Request) -> RedirectResponse:
    request.session.clear()
    await bridge.stop()
    return RedirectResponse("/login", status_code=302)


def _browser_base(request: Request) -> str:
    """Public origin for OAuth finish / redirects — follows the Host the user opened."""
    scheme = request.url.scheme or "http"
    if _settings.tls_enabled:
        scheme = "https"
    return browser_public_base(
        request.headers.get("host") or "",
        scheme,
        _settings.public_base_url,
    )


async def _oauth_start(request: Request, provider: str) -> RedirectResponse:
    # Broker via Hayabusa so IdP redirect URIs already registered there keep working.
    # In broker mode never fall through to local client secrets (those stay off the appliance).
    if _oauth_broker_mode():
        hayabusa = (_settings.hayabusa_public_url or "https://hayabusa.tracedroute.net").rstrip("/")
        state = secrets.token_urlsafe(24)
        request.session[f"oauth_state_{provider}"] = state
        return_to = f"{_browser_base(request)}/auth/oauth/finish"
        exp = str(int(time.time()) + 600)
        hay_provider = "teams" if provider == "microsoft" else provider
        params: dict[str, str] = {"return_to": return_to, "state": state, "exp": exp}
        # Legacy optional HMAC — only if an operator still sets the shared token.
        if (_settings.controller_bridge_token or "").strip():
            msg = f"{hay_provider}|{return_to}|{state}|{exp}"
            params["sig"] = _controller_oauth_hmac(msg)
        q = urllib.parse.urlencode(params)
        return RedirectResponse(
            f"{hayabusa}/api/controller/oauth/{hay_provider}/start?{q}",
            status_code=302,
        )

    cfg = _oauth_cfg(provider)
    if not cfg.get("client_id") or not cfg.get("client_secret"):
        return RedirectResponse(
            f"/login?error={urllib.parse.quote(provider + ' OAuth is not configured (local mode)')}",
            status_code=302,
        )
    state = secrets.token_urlsafe(24)
    request.session[f"oauth_state_{provider}"] = state
    if provider == "microsoft":
        tenant = urllib.parse.quote(cfg.get("tenant_id") or "common", safe="")
        authorize = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
        params = {
            "client_id": cfg["client_id"],
            "response_type": "code",
            "response_mode": "query",
            "scope": cfg.get("scope") or "openid profile email User.Read",
            "state": state,
            "redirect_uri": cfg["redirect_uri"],
        }
        return RedirectResponse(authorize + "?" + urllib.parse.urlencode(params), status_code=302)
    params = {
        "client_id": cfg["client_id"],
        "response_type": "code",
        "scope": cfg.get("scope") or "",
        "state": state,
        "redirect_uri": cfg["redirect_uri"],
    }
    if provider == "google":
        params["access_type"] = "offline"
        params["prompt"] = "select_account"
    if provider == "github":
        params["allow_signup"] = "true"
    if provider == "discord":
        params["prompt"] = "consent"
    return RedirectResponse(cfg["authorize"] + "?" + urllib.parse.urlencode(params), status_code=302)


@app.get("/auth/oauth/finish")
async def auth_oauth_finish(request: Request) -> RedirectResponse:
    """Accept identity ticket from Hayabusa OAuth broker (redeemed at Hayabusa)."""
    ticket = (request.query_params.get("ticket") or "").strip()
    sig = (request.query_params.get("sig") or "").strip().lower()
    state = (request.query_params.get("state") or "").strip()
    if not ticket or not sig:
        return RedirectResponse("/login?error=Missing%20OAuth%20ticket", status_code=302)

    body: dict[str, Any] | None = None
    # Preferred: Hayabusa verifies its own signature (no shared fleet secret on LAN).
    redeemed = await _redeem_oauth_ticket(ticket, sig)
    if redeemed:
        body = redeemed
    elif (_settings.controller_bridge_token or "").strip():
        # Legacy local HMAC verify when operators still share a bridge token.
        expect = _controller_oauth_hmac(f"ticket|{ticket}")
        if hmac.compare_digest(expect, sig):
            pad = "=" * (-len(ticket) % 4)
            try:
                raw = base64.urlsafe_b64decode(ticket + pad)
                parsed = json.loads(raw.decode("utf-8"))
                if isinstance(parsed, dict):
                    body = parsed
            except Exception:  # noqa: BLE001
                body = None
    if not body:
        return RedirectResponse("/login?error=Invalid%20OAuth%20ticket", status_code=302)
    try:
        exp = int(body.get("exp") or 0)
    except (TypeError, ValueError):
        exp = 0
    if exp and exp < int(time.time()) - 5:
        return RedirectResponse("/login?error=OAuth%20ticket%20expired", status_code=302)
    provider = str(body.get("provider") or "").strip().lower()
    if provider == "teams":
        provider = "microsoft"
    if state and state != str(body.get("state") or ""):
        return RedirectResponse("/login?error=Invalid%20OAuth%20state", status_code=302)
    # Match against any provider state we stored
    matched = False
    for p in ("google", "github", "discord", "slack", "microsoft", "totp"):
        if state and state == request.session.get(f"oauth_state_{p}"):
            request.session.pop(f"oauth_state_{p}", None)
            matched = True
            break
    if state and not matched:
        return RedirectResponse("/login?error=Invalid%20OAuth%20state", status_code=302)
    username = str(body.get("username") or "").strip()
    email = str(body.get("email") or "").strip()
    sub = str(body.get("oauth_id") or body.get("sub") or "").strip()
    username = _human_login_name(username=username, email=email, sub=sub)
    return await _finish_login(request, username=username, email=email, provider=provider or "oauth", sub=sub)


async def _oauth_callback(request: Request, provider: str) -> RedirectResponse:
    cfg = _oauth_cfg(provider)
    err = request.query_params.get("error")
    if err:
        return RedirectResponse(f"/login?error={urllib.parse.quote(err)}", status_code=302)
    code = (request.query_params.get("code") or "").strip()
    state = (request.query_params.get("state") or "").strip()
    if not code or state != request.session.get(f"oauth_state_{provider}"):
        return RedirectResponse("/login?error=Invalid%20OAuth%20state", status_code=302)
    request.session.pop(f"oauth_state_{provider}", None)

    async with httpx.AsyncClient(timeout=30.0) as client:
        if provider == "microsoft":
            tenant = urllib.parse.quote(cfg.get("tenant_id") or "common", safe="")
            token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
            token_resp = await client.post(
                token_url,
                data={
                    "client_id": cfg["client_id"],
                    "client_secret": cfg["client_secret"],
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": cfg["redirect_uri"],
                },
            )
        elif provider == "github":
            token_resp = await client.post(
                cfg["token"],
                headers={"Accept": "application/json"},
                data={
                    "client_id": cfg["client_id"],
                    "client_secret": cfg["client_secret"],
                    "code": code,
                    "redirect_uri": cfg["redirect_uri"],
                },
            )
        else:
            token_resp = await client.post(
                cfg["token"],
                data={
                    "client_id": cfg["client_id"],
                    "client_secret": cfg["client_secret"],
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": cfg["redirect_uri"],
                },
            )
        token_resp.raise_for_status()
        token_data = token_resp.json()
        access = (token_data.get("access_token") or "").strip()
        if not access:
            return RedirectResponse("/login?error=Missing%20access%20token", status_code=302)

        headers = {"Authorization": f"Bearer {access}"}
        if provider == "github":
            headers["Accept"] = "application/vnd.github+json"
        if provider == "microsoft":
            user_resp = await client.get("https://graph.microsoft.com/oidc/userinfo", headers=headers)
        else:
            user_resp = await client.get(cfg["userinfo"], headers=headers)
        user_resp.raise_for_status()
        profile = user_resp.json()

    username = (
        profile.get("login")
        or profile.get("preferred_username")
        or profile.get("name")
        or profile.get("username")
        or profile.get("global_name")
        or ""
    )
    email = profile.get("email") or ""
    if provider == "discord" and not email and profile.get("id"):
        email = f"{profile.get('id')}@discord.local"
    sub = str(profile.get("sub") or profile.get("id") or "").strip()
    username = _human_login_name(username=str(username or ""), email=str(email or ""), sub=sub)
    return await _finish_login(
        request,
        username=str(username),
        email=str(email or ""),
        provider=provider,
        sub=sub,
    )


@app.get("/auth/google/start")
async def auth_google_start(request: Request) -> RedirectResponse:
    return await _oauth_start(request, "google")


@app.get("/auth/google/callback")
async def auth_google_callback(request: Request) -> RedirectResponse:
    return await _oauth_callback(request, "google")


@app.get("/auth/github/start")
async def auth_github_start(request: Request) -> RedirectResponse:
    return await _oauth_start(request, "github")


@app.get("/auth/github/callback")
async def auth_github_callback(request: Request) -> RedirectResponse:
    return await _oauth_callback(request, "github")


@app.get("/auth/discord/start")
async def auth_discord_start(request: Request) -> RedirectResponse:
    return await _oauth_start(request, "discord")


@app.get("/auth/discord/callback")
async def auth_discord_callback(request: Request) -> RedirectResponse:
    return await _oauth_callback(request, "discord")


@app.get("/auth/slack/start")
async def auth_slack_start(request: Request) -> RedirectResponse:
    return await _oauth_start(request, "slack")


@app.get("/auth/slack/callback")
async def auth_slack_callback(request: Request) -> RedirectResponse:
    return await _oauth_callback(request, "slack")


@app.get("/auth/microsoft/start")
@app.get("/auth/teams/start")
async def auth_microsoft_start(request: Request) -> RedirectResponse:
    return await _oauth_start(request, "microsoft")


@app.get("/auth/microsoft/callback")
@app.get("/auth/teams/callback")
async def auth_microsoft_callback(request: Request) -> RedirectResponse:
    return await _oauth_callback(request, "microsoft")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon_ico() -> FileResponse:
    path = APP_DIR / "static" / "favicon.svg"
    return FileResponse(path, media_type="image/svg+xml")


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    redir = _require_auth(request)
    if redir:
        return redir
    setup_redir = _require_setup_complete(request)
    if setup_redir:
        return setup_redir
    # Best-effort refresh so permission changes on Hayabusa show up without re-login.
    try:
        await _refresh_user_capabilities(request)
    except Exception:  # noqa: BLE001
        pass
    from .wan_public_ip import discover_wan_public_identity

    br = bridge.status()
    loc = await asyncio.to_thread(discover_wan_public_identity)
    public_ip = str(br.get("public_ip") or loc.get("public_ip") or loc.get("wan_public_ip") or "")
    key = _rbac_key(request)
    rbac.ensure_bootstrap_admin(
        username=request.session.get("username") or key,
        email=request.session.get("email") or "",
        sub=request.session.get("sub") or "",
    )
    return TEMPLATES.TemplateResponse(
        request,
        "dashboard.html",
        {
            "user": _user(request),
            "vpn": vpn.status(),
            "bridge": br,
            "secrets": _secrets_public_for_request(request),
            "iac": iac.status(),
            "hayabusa_public_url": _settings.hayabusa_public_url,
            "can_manual_mesh_override": _session_can_manual_mesh_override(request),
            "public_ip": public_ip,
            "is_owner_or_admin": rbac.is_owner_or_admin(key),
        },
    )


@app.get("/administration", response_class=HTMLResponse)
async def administration_page(request: Request) -> HTMLResponse:
    """Owner/admin-only: roles, users, teams, site name, setup redo."""
    redir = _require_auth(request)
    if redir:
        return redir
    setup_redir = _require_setup_complete(request)
    if setup_redir:
        return setup_redir
    admin_gate = _require_owner_or_admin(request)
    if isinstance(admin_gate, (JSONResponse, RedirectResponse)):
        return admin_gate
    try:
        await _refresh_user_capabilities(request)
    except Exception:  # noqa: BLE001
        pass
    return TEMPLATES.TemplateResponse(
        request,
        "administration.html",
        {
            "user": _user(request),
            "hayabusa_public_url": _settings.hayabusa_public_url,
        },
    )


@app.get("/devops-iac", response_class=HTMLResponse)
async def devops_iac_page(request: Request) -> HTMLResponse:
    redir = _require_auth(request)
    if redir:
        return redir
    setup_redir = _require_setup_complete(request)
    if setup_redir:
        return setup_redir
    devops.seed_from_defaults()
    return TEMPLATES.TemplateResponse(request, "devops_iac.html", {"user": _user(request)})


@app.get("/image-nest", response_class=HTMLResponse)
async def image_nest_page(request: Request) -> HTMLResponse:
    """Dedicated Image Nest portal — user-supplied Windows ISO → dated bank."""
    redir = _require_auth(request)
    if redir:
        return redir
    setup_redir = _require_setup_complete(request)
    if setup_redir:
        return setup_redir
    key = _rbac_key(request)
    rbac.ensure_bootstrap_admin(
        username=request.session.get("username") or key,
        email=request.session.get("email") or "",
        sub=request.session.get("sub") or "",
    )
    can_manage = rbac.has_permission(key, "manage_image_nest")
    can_read = can_manage or rbac.has_permission(key, "read_image_nest")
    if not can_read:
        return HTMLResponse(
            "<!DOCTYPE html><html><body style='font-family:sans-serif;padding:2rem'>"
            "<h1>Image Nest</h1><p>Missing permission <code>read_image_nest</code> "
            "or <code>manage_image_nest</code>.</p>"
            "<p><a href='/'>Back</a></p></body></html>",
            status_code=403,
        )
    return TEMPLATES.TemplateResponse(
        request,
        "image_nest.html",
        {
            "user": _user(request),
            "can_manage": can_manage,
            "disk": image_nest.disk_status(),
        },
    )


@app.get("/api/image-nest/status")
async def api_image_nest_status(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    denied = _require_any_perm(request, "read_image_nest", "manage_image_nest")
    if denied:
        return denied
    return JSONResponse({"ok": True, **image_nest.disk_status()})


@app.get("/api/image-nest/bank")
async def api_image_nest_bank(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    denied = _require_any_perm(request, "read_image_nest", "manage_image_nest")
    if denied:
        return denied
    await asyncio.to_thread(image_nest.reconcile_iso_cache)
    return JSONResponse(
        {
            "ok": True,
            "images": image_nest.list_bank(),
            "isos": image_nest.list_isos(),
            "jobs": image_nest.list_jobs(limit=30),
            "registry": image_nest.list_registry(),
            "disk": image_nest.disk_status(),
        }
    )


@app.post("/api/image-nest/upload")
async def api_image_nest_upload(request: Request, file: UploadFile = File(...)) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    denied = _require_perm(request, "manage_image_nest")
    if denied:
        return denied
    u = _user(request)
    expected: int | None = None
    xexp = request.headers.get("x-expected-upload-bytes")
    cl = request.headers.get("content-length")
    if xexp and str(xexp).isdigit():
        expected = int(xexp)
    elif cl and str(cl).isdigit():
        expected = int(cl)
    result = await asyncio.to_thread(
        image_nest.save_upload,
        filename=str(file.filename or "upload.iso"),
        stream=file.file,
        uploaded_by={"username": u.get("username"), "email": u.get("email"), "provider": u.get("provider")},
        expected_bytes=expected,
    )
    code = 200 if result.get("ok") else 400
    return JSONResponse(result, status_code=code)


@app.get("/api/image-nest/strip-options")
async def api_image_nest_strip_options(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    denied = _require_any_perm(request, "read_image_nest", "manage_image_nest")
    if denied:
        return denied
    family = str(request.query_params.get("os_family") or request.query_params.get("family") or "")
    return JSONResponse(image_nest.list_strip_options(os_family=family))


@app.get("/api/image-nest/isos/{iso_id}/packages")
async def api_image_nest_iso_packages(iso_id: str, request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    denied = _require_any_perm(request, "read_image_nest", "manage_image_nest")
    if denied:
        return denied
    refresh = str(request.query_params.get("refresh") or "").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    try:
        wim_index = int(request.query_params.get("wim_index") or 0)
    except (TypeError, ValueError):
        wim_index = 0
    return JSONResponse(
        image_nest.inventory_iso_packages(iso_id, refresh=refresh, wim_index=wim_index)
    )


@app.post("/api/image-nest/publish-bare-metal")
async def api_image_nest_publish_bare_metal(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    denied = _require_perm(request, "manage_image_nest")
    if denied:
        return denied
    body = await request.json()
    if not isinstance(body, dict):
        body = {}
    u = _user(request)
    result = image_nest.publish_bare_metal(
        iso_id=str(body.get("iso_id") or ""),
        requested_by={"username": u.get("username"), "email": u.get("email"), "provider": u.get("provider")},
    )
    code = 200 if result.get("ok") else 400
    return JSONResponse(result, status_code=code)


@app.post("/api/image-nest/build")
async def api_image_nest_build(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    denied = _require_perm(request, "manage_image_nest")
    if denied:
        return denied
    body = await request.json()
    if not isinstance(body, dict):
        body = {}
    u = _user(request)
    strip_option_ids = body.get("strip_option_ids")
    if not isinstance(strip_option_ids, list):
        strip_option_ids = None
    strip_packages = body.get("strip_packages")
    if not isinstance(strip_packages, list):
        strip_packages = None
    result = image_nest.start_build(
        iso_id=str(body.get("iso_id") or ""),
        flavor=str(body.get("flavor") or body.get("mode") or ""),
        requested_by={"username": u.get("username"), "email": u.get("email"), "provider": u.get("provider")},
        wim_index=int(body.get("wim_index") or 6),
        disk_gb=int(body.get("disk_gb") or 60),
        strip_option_ids=strip_option_ids,
        strip_packages=strip_packages,
        deploy_target=str(body.get("deploy_target") or body.get("target") or "hypervisor"),
    )
    code = 200 if result.get("ok") else 400
    return JSONResponse(result, status_code=code)


@app.get("/api/image-nest/jobs/{job_id}")
async def api_image_nest_job(job_id: str, request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    denied = _require_any_perm(request, "read_image_nest", "manage_image_nest")
    if denied:
        return denied
    job = image_nest.get_job(job_id)
    if not job:
        return JSONResponse({"ok": False, "error": "not found"}, status_code=404)
    image = image_nest.get_image(str(job.get("image_id") or ""))
    return JSONResponse({"ok": True, "job": job, "image": image})


@app.get("/api/image-nest/manifest/{name}")
async def api_image_nest_manifest(name: str, request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    denied = _require_any_perm(request, "read_image_nest", "manage_image_nest")
    if denied:
        return denied
    out = image_nest.read_manifest(name)
    return JSONResponse(out, status_code=200 if out.get("ok") else 404)


@app.post("/api/image-nest/bank/{image_id}/tofu-handoff")
async def api_image_nest_tofu_handoff(image_id: str, request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    denied = _require_perm(request, "manage_image_nest")
    if denied:
        return denied
    body = await request.json()
    if not isinstance(body, dict):
        body = {}
    out = image_nest.write_tofu_handoff(
        image_id=image_id,
        target_vm_name=str(body.get("target_vm_name") or body.get("name") or ""),
    )
    return JSONResponse(out, status_code=200 if out.get("ok") else 400)


@app.post("/api/image-nest/bank/{image_id}/delete")
async def api_image_nest_delete(image_id: str, request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    denied = _require_perm(request, "manage_image_nest")
    if denied:
        return denied
    out = image_nest.delete_image(image_id)
    return JSONResponse(out, status_code=200 if out.get("ok") else 404)


@app.get("/api/image-nest/registry")
async def api_image_nest_registry(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    denied = _require_any_perm(request, "read_image_nest", "manage_image_nest")
    if denied:
        return denied
    return JSONResponse(image_nest.list_registry())


@app.get("/api/image-nest/registry/{ref}")
async def api_image_nest_registry_ref(ref: str, request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    denied = _require_any_perm(request, "read_image_nest", "manage_image_nest")
    if denied:
        return denied
    row = image_nest.get_registry_ref(ref)
    if not row:
        return JSONResponse({"ok": False, "error": "not found"}, status_code=404)
    return JSONResponse({"ok": True, "ref": ref, "entry": row})


@app.get("/api/devops-iac/whoami")
async def api_devops_whoami(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    out = devops.whoami(username=_user(request).get("username") or "controller")
    if isinstance(out, dict):
        out["gitops_enabled"] = gitops.enabled()
        out["local_workspace_writable"] = not gitops.enabled()
    return JSONResponse(out)


@app.get("/api/devops-iac/ls")
async def api_devops_ls(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    path = request.query_params.get("path") or ""
    try:
        out = devops.ls(path)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    code = 200 if out.get("ok") else 400
    return JSONResponse(out, status_code=code)


@app.get("/api/devops-iac/file")
async def api_devops_file_get(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    path = request.query_params.get("path") or ""
    try:
        out = devops.read_file(path)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    return JSONResponse(out, status_code=200 if out.get("ok") else 404)


@app.post("/api/devops-iac/file")
async def api_devops_file_post(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    blocked = _gitops_blocks_workspace_writes()
    if blocked:
        return blocked
    body = await request.json()
    try:
        rel_path = str(body.get("path") or "")
        out = devops.write_file(rel_path, str(body.get("content") or ""))
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    if out.get("ok"):
        norm = rel_path.replace("\\", "/").lstrip("/")
        low = norm.lower()
        if low.endswith((".yml", ".yaml")) and low.startswith(("ansible/", "opentofu/")):
            try:
                key = _rbac_key(request)
                rbac.set_playbook_owner(norm, owner_type="user", owner_id=key)
            except Exception:
                pass
        elif any(
            low.startswith(p)
            for p in ("ztp/", "bare-metal-ztp/", "ansible/ztp/", "ansible/bare-metal-ztp/")
        ):
            try:
                key = _rbac_key(request)
                rbac.set_playbook_owner(norm, owner_type="user", owner_id=key)
            except Exception:
                pass
    return JSONResponse(out, status_code=200 if out.get("ok") else 400)


@app.post("/api/devops-iac/mkdir")
async def api_devops_mkdir(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    blocked = _gitops_blocks_workspace_writes()
    if blocked:
        return blocked
    body = await request.json()
    try:
        out = devops.mkdir(str(body.get("path") or ""))
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    return JSONResponse(out)


@app.post("/api/devops-iac/mv")
async def api_devops_mv(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    blocked = _gitops_blocks_workspace_writes()
    if blocked:
        return blocked
    body = await request.json()
    try:
        out = devops.mv(str(body.get("src") or body.get("from") or ""), str(body.get("dst") or body.get("to") or ""))
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    code = 200 if out.get("ok") else (403 if out.get("code") == "protected_default" else 400)
    return JSONResponse(out, status_code=code)


@app.post("/api/devops-iac/rm")
async def api_devops_rm(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    blocked = _gitops_blocks_workspace_writes()
    if blocked:
        return blocked
    body = await request.json()
    try:
        out = devops.rm(str(body.get("path") or ""))
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    code = 200 if out.get("ok") else (403 if out.get("code") == "protected_default" else 400)
    return JSONResponse(out, status_code=code)


@app.get("/api/devops-iac/opentofu-state-summary")
async def api_devops_tofu_summary(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    return JSONResponse(devops.opentofu_state_summary())


@app.get("/api/devops-iac/opentofu-state-inventory")
async def api_devops_tofu_inventory(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    summary = devops.inventory_summary()
    return JSONResponse(
        {
            "ok": True,
            "hosts": summary.get("hosts") or [],
            "count": summary.get("count") or 0,
            "state_path": summary.get("state_path"),
            "workspace": summary.get("workspace"),
        }
    )


@app.post("/api/devops-iac/opentofu-sync-inventory")
@app.post("/api/devops-iac/run")
@app.get("/api/devops-iac/run/queue")
async def api_devops_stub(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    return JSONResponse(
        {
            "ok": True,
            "items": [],
            "hosts": [],
            "message": "Run/queue on Hayabusa after mesh access is granted. Controller only approves and hydrates secrets into playbooks as they pass through.",
        }
    )


@app.get("/api/user-ssh-keys")
async def api_ssh_keys_stub(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    return JSONResponse({"ok": True, "personal": None, "org": None, "keys": []})


@app.get("/api/status")
async def api_status(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        tree = devops.ls("")
        iac_status = {
            "workspace": str(_settings.devops_workspace),
            "entries": len(tree.get("entries") or []),
            "ok": bool(tree.get("ok")),
        }
    except Exception:  # noqa: BLE001
        iac_status = {"workspace": str(_settings.devops_workspace), "entries": 0, "ok": False}
    from .wan_public_ip import discover_wan_public_identity

    loc = await asyncio.to_thread(discover_wan_public_identity)
    return JSONResponse(
        {
            "user": _user(request),
            "vpn": vpn.status(),
            "bridge": bridge.status(),
            "enroll": enroller.status(),
            "connection": _connection_public(),
            "secrets": _secrets_public_for_request(request),
            "iac": iac_status,
            "lan": {"capability": "lan", "rpc": ["lan.inventory", "lan.topology", "lan.telemetry"]},
            "ztp_edge": {
                "running": ztp_edge.running(),
                "dnsmasq_installed": ztp_edge.dnsmasq_available(),
                "lease_count": len(ztp_edge.leases()),
            },
            "hayabusa_public_url": _settings.hayabusa_public_url,
            "location": loc,
            "public_ip": loc.get("public_ip") or "",
            "wan_public_ip": loc.get("wan_public_ip") or "",
            "vpn_endpoint_ip": loc.get("vpn_endpoint_ip") or "",
            "capabilities": {
                "can_manual_mesh_override": _session_can_manual_mesh_override(request),
            },
        }
    )


@app.get("/api/lan/inventory")
async def api_lan_inventory(request: Request) -> JSONResponse:
    """What this controller sees on its LAN (for Hayabusa map merge / local debug)."""
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from . import lan_discover

    probe = str(request.query_params.get("probe") or "1").lower() not in ("0", "false", "no", "off")
    return JSONResponse(lan_discover.build_inventory(probe=probe))


@app.get("/api/lan/topology")
async def api_lan_topology(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from . import lan_discover

    return JSONResponse(lan_discover.build_topology())


@app.get("/api/lan/telemetry")
async def api_lan_telemetry(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from . import lan_discover

    return JSONResponse(lan_discover.build_telemetry())


def _guacamole_internal_base() -> str:
    base = (os.environ.get("CONTROLLER_GUACAMOLE_INTERNAL_URL") or "http://127.0.0.1:9000").rstrip("/")
    if base.endswith("/guacamole"):
        return base
    return f"{base}/guacamole"


def _guacamole_internal_target(subpath: str) -> str:
    base = _guacamole_internal_base()
    sub = (subpath or "").lstrip("/")
    if not sub:
        return f"{base}/"
    return f"{base}/{sub}"


def _guacamole_rewrite_html(body: bytes) -> bytes:
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return body
    text = re.sub(r'<base\s+href=["\']/guacamole/["\']\s*/?>', '<base href="/guacamole/">', text, count=1, flags=re.I)
    text = re.sub(r'<base\s+href=["\']/["\']\s*/?>', '<base href="/guacamole/">', text, count=1, flags=re.I)
    if '<base href="/guacamole/">' not in text:
        text = text.replace("<head>", '<head><base href="/guacamole/">', 1)
    internal = _guacamole_internal_base()
    text = text.replace(internal, "/guacamole")
    text = text.replace("http://127.0.0.1:9000/guacamole", "/guacamole")
    return text.encode("utf-8")


@app.api_route(
    "/guacamole/",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
@app.api_route(
    "/guacamole/{subpath:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def guacamole_proxy(request: Request, subpath: str = "") -> Response:
    """Same-origin reverse proxy for Apache Guacamole on this controller node."""
    if not _authed(request):
        return RedirectResponse("/login", status_code=302)
    if (request.headers.get("upgrade") or "").lower() == "websocket":
        return HTMLResponse(
            "WebSocket tunnel is not available through this path; Guacamole will use HTTP tunnel.",
            status_code=426,
        )
    import urllib.error
    import urllib.request

    target = _guacamole_internal_target(subpath)
    data = await request.body() if request.method not in {"GET", "HEAD", "OPTIONS"} else None
    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in {"host", "content-length", "connection", "accept-encoding"}
    }
    headers["Host"] = urllib.parse.urlparse(
        os.environ.get("CONTROLLER_GUACAMOLE_INTERNAL_URL") or "http://127.0.0.1:9000"
    ).netloc
    req = urllib.request.Request(target, data=data, headers=headers, method=request.method)

    def _fetch() -> tuple[int, bytes, Any]:
        try:
            upstream = urllib.request.urlopen(req, timeout=60)
            return upstream.status, upstream.read(), upstream.headers
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), exc.headers

    try:
        status_code, body, upstream_headers = await asyncio.to_thread(_fetch)
    except Exception as exc:  # noqa: BLE001
        return HTMLResponse(f"Guacamole proxy error: {exc}", status_code=502)

    content_type = upstream_headers.get("Content-Type", "application/octet-stream") if upstream_headers else "application/octet-stream"
    if "text/html" in str(content_type).lower():
        body = _guacamole_rewrite_html(body)
    resp = Response(content=body, status_code=status_code, media_type=content_type)
    if "text/html" in str(content_type).lower():
        resp.headers["Cache-Control"] = "no-store"
    location = upstream_headers.get("Location") if upstream_headers else None
    if location:
        internal = _guacamole_internal_base()
        resp.headers["Location"] = str(location).replace(internal, "/guacamole").replace(
            "http://127.0.0.1:9000/guacamole", "/guacamole"
        )
    resp.headers.pop("x-frame-options", None)
    return resp


@app.get("/console/guacamole/embed", response_class=HTMLResponse)
async def console_guacamole_embed(request: Request) -> HTMLResponse:
    if not _authed(request):
        return RedirectResponse("/login", status_code=302)
    from . import guacamole_sync, lan_discover

    user = _user(request)
    account_id = str(user.get("sub") or user.get("email") or user.get("username") or "controller").strip()
    try:
        inv = await asyncio.to_thread(lan_discover.build_inventory, probe=False)
        data = await asyncio.to_thread(
            guacamole_sync.guacamole_sync_for_user,
            account_id=account_id,
            display_name=str(user.get("username") or ""),
            vault=vault,
            data_dir=str(_settings.data_dir),
            lan_hosts=list(inv.get("hosts") or []),
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("guacamole embed sync failed")
        return HTMLResponse(f"Guacamole setup failed: {exc}", status_code=502)
    token = data.get("authToken")
    if not token:
        return RedirectResponse("/guacamole/", status_code=302)
    auth_obj = {
        "authToken": token,
        "username": data.get("username"),
        "dataSource": data.get("dataSource") or "postgresql",
        "availableDataSources": data.get("availableDataSources") or ["postgresql"],
    }
    auth_js = json.dumps(auth_obj)
    html = (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Console</title></head><body>"
        "<p style=\"font-family:sans-serif\">Opening controller console…</p><script>"
        "try{localStorage.setItem('GUAC_AUTH',"
        + auth_js
        + ");}catch(e){}"
        "window.location.replace('/guacamole/');"
        "</script></body></html>"
    )
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})


@app.api_route("/api/console/guacamole/bootstrap", methods=["GET", "POST"])
async def guacamole_console_bootstrap(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"success": False, "error": "unauthorized"}, status_code=401)
    from . import guacamole_sync, lan_discover

    user = _user(request)
    account_id = str(user.get("sub") or user.get("email") or user.get("username") or "controller").strip()
    try:
        inv = await asyncio.to_thread(lan_discover.build_inventory, probe=False)
        data = await asyncio.to_thread(
            guacamole_sync.guacamole_sync_for_user,
            account_id=account_id,
            display_name=str(user.get("username") or ""),
            vault=vault,
            data_dir=str(_settings.data_dir),
            lan_hosts=list(inv.get("hosts") or []),
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("guacamole bootstrap failed")
        return JSONResponse({"success": False, "error": str(exc), "synced": False}, status_code=500)
    if not data.get("success"):
        return JSONResponse(data, status_code=502)
    return JSONResponse(
        {
            "success": True,
            "synced": bool(data.get("synced")),
            "username": data.get("username"),
            "connections": data.get("connections") or [],
            "url": "/guacamole/",
            "embed_url": "/console/guacamole/embed",
        }
    )


@app.get("/api/console/guacamole/status")
async def guacamole_console_status(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from . import guacamole_sync

    return JSONResponse(
        {
            "ok": True,
            "provider": "apache-guacamole",
            "url": "/guacamole/",
            "embed_url": "/console/guacamole/embed",
            "sync_enabled": guacamole_sync.guacamole_sync_enabled(),
            "location": "controller",
        }
    )


@app.get("/api/ztp/status")
async def api_ztp_status(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return JSONResponse(ztp_edge.status())


@app.get("/api/ztp/config")
async def api_ztp_config_get(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return JSONResponse({"ok": True, "config": ztp_edge.load_config()})


@app.put("/api/ztp/config")
async def api_ztp_config_put(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    body = await request.json()
    cfg = body.get("config") if isinstance(body, dict) and isinstance(body.get("config"), dict) else body
    if not isinstance(cfg, dict):
        return JSONResponse({"ok": False, "error": "config object required"}, status_code=400)
    saved = ztp_edge.save_config(cfg)
    return JSONResponse({"ok": True, "config": saved})


@app.post("/api/ztp/start")
async def api_ztp_start(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    denied = _require_perm(request, "approve_ztp")
    if denied:
        return denied
    return JSONResponse(ztp_edge.start())


@app.post("/api/ztp/stop")
async def api_ztp_stop(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    denied = _require_perm(request, "approve_ztp")
    if denied:
        return denied
    return JSONResponse(ztp_edge.stop())


@app.get("/api/ztp/leases")
async def api_ztp_leases(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    leases = ztp_edge.leases()
    return JSONResponse({"ok": True, "leases": leases, "count": len(leases)})


@app.get("/api/ztp/interfaces")
async def api_ztp_interfaces(request: Request) -> JSONResponse:
    """LAN NICs the operator can bind DHCP to (host networking)."""
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from . import lan_discover

    addrs = lan_discover.collect_addresses()
    by_name: dict[str, list[str]] = {}
    for row in addrs:
        if not isinstance(row, dict):
            continue
        name = str(row.get("ifname") or row.get("dev") or row.get("name") or "").strip()
        if not name or name == "lo":
            continue
        ip = str(row.get("ip") or row.get("local") or row.get("address") or "").strip()
        by_name.setdefault(name, [])
        if ip and ip not in by_name[name]:
            by_name[name].append(ip)
    # Also include ifaces that only appear in telemetry (no addr yet)
    for row in lan_discover.collect_iface_telemetry():
        if not isinstance(row, dict):
            continue
        name = str(row.get("iface") or row.get("ifname") or row.get("dev") or row.get("name") or "").strip()
        if not name or name == "lo" or name.startswith("docker") or name.startswith("br-") or name.startswith("veth"):
            continue
        by_name.setdefault(name, [])
    interfaces = [{"name": n, "addrs": by_name[n]} for n in sorted(by_name.keys())]
    return JSONResponse({"ok": True, "interfaces": interfaces})


@app.get("/api/controller/site-name")
async def api_controller_site_name_get(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    display = _site_display_name() or str(_settings.controller_mesh_hostname or "hayabusa-controller")
    return JSONResponse(
        {
            "ok": True,
            "display_name": display,
            "mesh_hostname": str(_settings.controller_mesh_hostname or ""),
        }
    )


@app.post("/api/controller/site-name")
async def api_controller_site_name_set(request: Request) -> JSONResponse:
    admin_gate = _require_owner_or_admin(request)
    if isinstance(admin_gate, (JSONResponse, RedirectResponse)):
        return admin_gate
    denied = _require_perm(request, "manage_rbac")
    if denied:
        return denied
    body = await request.json()
    name = str(body.get("name") or body.get("display_name") or "").strip()
    try:
        saved = _save_site_display_name(name)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    pushed = await bridge.push_presence()
    return JSONResponse({"ok": True, **saved, "presence_pushed": bool(pushed)})


@app.get("/ztp/fetch/{path:path}")
async def ztp_fetch(path: str):
    """Auth-exempt fetch for LAN devices being provisioned on this site."""
    from fastapi.responses import FileResponse, PlainTextResponse

    target = ztp_edge.resolve_fetch_file(path)
    if target is None:
        return PlainTextResponse("not found", status_code=404)
    return FileResponse(str(target))


@app.post("/api/vpn/configure")
async def api_vpn_configure(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if not _session_can_manual_mesh_override(request):
        return JSONResponse(
            {
                "error": "manual_mesh_override_denied",
                "message": (
                    "Manual mesh override requires the global permission "
                    "'Controller manual mesh override' on Hayabusa."
                ),
            },
            status_code=403,
        )
    body = await request.json()
    st = vpn.configure(
        mesh_server=str(body.get("mesh_server") or ""),
        preauth_key=str(body.get("preauth_key") or ""),
        hostname=str(body.get("hostname") or "") or None,
    )
    return JSONResponse({"ok": True, "vpn": st})


@app.post("/api/vpn/join")
async def api_vpn_join(request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if not _session_can_manual_mesh_override(request):
        return JSONResponse(
            {
                "error": "manual_mesh_override_denied",
                "message": (
                    "Manual mesh override requires the global permission "
                    "'Controller manual mesh override' on Hayabusa."
                ),
            },
            status_code=403,
        )
    st = await vpn.join_mesh()
    if not st.get("connected"):
        await connection.set_step("mesh", "failed", st.get("error") or st.get("error_code") or "Mesh join failed")
        return JSONResponse(
            {
                "ok": False,
                "error": st.get("error") or "Mesh join failed",
                "error_code": st.get("error_code") or "",
                "fix": st.get("fix") or "",
                "vpn": st,
                "bridge": bridge.status(),
                "connection": _connection_public(),
            },
            status_code=502,
        )
    await connection.set_step("mesh", "ok", "Mesh VPN up")
    await connection.set_step("bridge", "running", "Opening control bridge…")
    await bridge.start_for_user(_user(request), vpn_ip=st.get("ip") or "")
    await asyncio.sleep(0.15)
    br = bridge.status()
    if br.get("granted"):
        await connection.set_step("bridge", "ok", "Access granted")
    else:
        await connection.set_step("bridge", "pending", br.get("last_event") or "Waiting for grant")
    return JSONResponse(
        {"ok": True, "vpn": st, "bridge": br, "connection": _connection_public()}
    )


@app.post("/api/vpn/enroll")
async def api_vpn_enroll(request: Request) -> JSONResponse:
    """Re-run phone-home enrollment against hayabusa.tracedroute.net.

    Response never includes mesh preauth/join keys — those stay on this appliance.
    """
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    result = await _connect_to_hayabusa(_user(request), request=request)
    vpn_st = result.get("vpn") or {}
    br_st = result.get("bridge") or {}
    conn = result.get("connection") or _connection_public()
    enroll_ok = bool((result.get("enroll") or {}).get("ok"))
    mesh_ok = bool(vpn_st.get("connected"))
    bridge_ok = bool(br_st.get("granted"))
    err = ""
    err_code = vpn_st.get("error_code") or None
    if not enroll_ok:
        err = str((result.get("enroll") or {}).get("error") or "Enrollment failed")
    elif not mesh_ok:
        err = str(vpn_st.get("error") or "Mesh join failed after enrollment")
    elif not bridge_ok:
        err = str(br_st.get("last_error") or "Mesh VPN is up, but the control bridge was not granted")
        err_code = "bridge_not_granted"
    return JSONResponse(
        {
            "ok": enroll_ok and mesh_ok and bridge_ok,
            "error": err or None,
            "error_code": err_code,
            "fix": vpn_st.get("fix") or (
                "Re-run Enroll & connect, or check Hayabusa controller registry / mesh WS."
                if enroll_ok and mesh_ok and not bridge_ok
                else None
            ),
            "enroll": public_enroll_view(result.get("enroll")),
            "vpn": vpn_st,
            "bridge": br_st,
            "connection": conn,
            "capabilities": result.get("capabilities")
            or {"can_manual_mesh_override": _session_can_manual_mesh_override(request)},
        },
        status_code=200 if enroll_ok else 502,
    )


@app.get("/api/secrets")
async def api_secrets_list(request: Request) -> JSONResponse:
    denied = _require_any_perm(request, "read_secrets", "manage_secrets")
    if denied:
        return denied
    body = vault.public_status()
    body["can_manage"] = _can_manage_secrets(request)
    body["can_read"] = _can_read_secrets(request)
    body["can_read_values"] = _can_manage_secrets(request)
    return JSONResponse(body)


@app.put("/api/secrets/{key}")
async def api_secrets_put(key: str, request: Request) -> JSONResponse:
    denied = _require_perm(request, "manage_secrets")
    if denied:
        return denied
    if is_reserved_secret_key(key):
        return JSONResponse({"error": "reserved secret key"}, status_code=403)
    body = await request.json()
    if not isinstance(body, dict):
        body = {}
    try:
        vault.put(
            key,
            str(body.get("value") or ""),
            category=str(body.get("category") or ""),
            kind=str(body.get("kind") or ""),
            host=str(body.get("host") or ""),
            label=str(body.get("label") or ""),
            updated_by=_rbac_key(request),
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    meta = vault.get_meta(key) or {}
    return JSONResponse({"ok": True, "key": key, "meta": meta})


@app.patch("/api/secrets/{key}")
async def api_secrets_patch(key: str, request: Request) -> JSONResponse:
    """Update category/host/label/kind without rotating the secret value."""
    denied = _require_perm(request, "manage_secrets")
    if denied:
        return denied
    if is_reserved_secret_key(key):
        return JSONResponse({"error": "reserved secret key"}, status_code=403)
    body = await request.json()
    if not isinstance(body, dict):
        body = {}
    ok = vault.update_meta(
        key,
        category=body.get("category") if "category" in body else None,
        kind=body.get("kind") if "kind" in body else None,
        host=body.get("host") if "host" in body else None,
        label=body.get("label") if "label" in body else None,
        updated_by=_rbac_key(request),
    )
    if not ok:
        return JSONResponse({"error": "not found"}, status_code=404)
    if "value" in body and _can_manage_secrets(request):
        try:
            vault.put(
                key,
                str(body.get("value") or ""),
                updated_by=_rbac_key(request),
            )
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
    meta = vault.get_meta(key) or {}
    return JSONResponse({"ok": True, "key": key, "meta": meta})


@app.get("/api/secrets/{key}")
async def api_secrets_get(key: str, request: Request) -> JSONResponse:
    denied = _require_any_perm(request, "read_secrets", "manage_secrets")
    if denied:
        return denied
    if is_reserved_secret_key(key):
        return JSONResponse({"error": "not found"}, status_code=404)
    meta = vault.get_meta(key)
    if meta is None and vault.get(key) is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    out: dict[str, Any] = {"key": key, "meta": meta or {}}
    if _can_manage_secrets(request):
        val = vault.get(key)
        if val is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        out["value"] = val
        out["can_read_value"] = True
    else:
        out["can_read_value"] = False
    return JSONResponse(out)


@app.delete("/api/secrets/{key}")
async def api_secrets_delete(key: str, request: Request) -> JSONResponse:
    denied = _require_perm(request, "manage_secrets")
    if denied:
        return denied
    if is_reserved_secret_key(key):
        return JSONResponse({"ok": False, "error": "reserved secret key"}, status_code=403)
    ok = vault.delete(key)
    return JSONResponse({"ok": ok})


@app.get("/api/jobs")
async def api_jobs_list(request: Request) -> JSONResponse:
    """LAN UI: list jobs (default pending_approval). status may be comma-separated."""
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    status = (request.query_params.get("status") or "pending_approval").strip()
    if status in {"", "all", "*"}:
        status = None
    try:
        limit = int(request.query_params.get("limit") or 50)
    except (TypeError, ValueError):
        limit = 50
    jobs = job_queue.list_jobs(status=status, limit=max(1, min(limit, 100)))
    return JSONResponse({"ok": True, "jobs": jobs, "count": len(jobs)})


@app.get("/api/jobs/{job_id}")
async def api_jobs_get(job_id: str, request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    job = job_queue.get(job_id)
    if not job:
        return JSONResponse({"ok": False, "error": "not found"}, status_code=404)
    return JSONResponse({"ok": True, **job})


@app.post("/api/jobs/{job_id}/approve")
async def api_jobs_approve(job_id: str, request: Request) -> JSONResponse:
    """On-LAN approval: hydrate secrets and run Ansible/OpenTofu on this controller (Core never receives vault values)."""
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    job = job_queue.get(job_id)
    kind = str((job or {}).get("kind") or "").strip().lower()
    if kind in ZTP_JOB_KINDS:
        denied = _require_perm(request, "approve_ztp")
    else:
        denied = _require_any_perm(request, "approve_jobs", "approve_playbooks")
    if denied:
        return denied
    u = _user(request)
    result = await asyncio.to_thread(
        job_queue.approve,
        job_id,
        approved_by={
            "username": u.get("username") or "",
            "email": u.get("email") or "",
            "provider": u.get("provider") or "",
        },
    )
    code = 200 if result.get("ok") or result.get("status") in {"hydrated", "completed", "failed"} else 400
    if result.get("code") == "not_found":
        code = 404
    return JSONResponse(result, status_code=code)


@app.post("/api/jobs/{job_id}/deny")
async def api_jobs_deny(job_id: str, request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    job = job_queue.get(job_id)
    kind = str((job or {}).get("kind") or "").strip().lower()
    if kind in ZTP_JOB_KINDS:
        denied = _require_perm(request, "approve_ztp")
    else:
        denied = _require_any_perm(request, "approve_jobs", "approve_playbooks")
    if denied:
        return denied
    body = {}
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = {}
    if not isinstance(body, dict):
        body = {}
    u = _user(request)
    result = job_queue.deny(
        job_id,
        denied_by={
            "username": u.get("username") or "",
            "email": u.get("email") or "",
            "provider": u.get("provider") or "",
        },
        reason=str(body.get("reason") or "")[:400],
    )
    code = 200 if result.get("ok") else 400
    if result.get("code") == "not_found":
        code = 404
    return JSONResponse(result, status_code=code)


@app.get("/api/iac/{kind}")
async def api_iac_list(kind: str, request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if kind not in ("ansible", "opentofu"):
        return JSONResponse({"error": "invalid kind"}, status_code=400)
    return JSONResponse({"kind": kind, "files": iac.list_tree(kind)})


@app.get("/api/iac/{kind}/file")
async def api_iac_read(kind: str, request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    path = request.query_params.get("path") or ""
    try:
        content = iac.read_text(kind, path)
    except FileNotFoundError:
        return JSONResponse({"error": "not found"}, status_code=404)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return JSONResponse({"kind": kind, "path": path, "content": content})


@app.put("/api/iac/{kind}/file")
async def api_iac_write(kind: str, request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    body = await request.json()
    path = str(body.get("path") or "")
    try:
        meta = iac.write_text(kind, path, str(body.get("content") or ""))
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return JSONResponse({"ok": True, **meta})


@app.delete("/api/iac/{kind}/file")
async def api_iac_delete(kind: str, request: Request) -> JSONResponse:
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    path = request.query_params.get("path") or ""
    try:
        ok = iac.delete(kind, path)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return JSONResponse({"ok": ok})


@app.websocket("/ws/status")
async def ws_status(websocket: WebSocket) -> None:
    await websocket.accept()
    sess = websocket.scope.get("session") or {}
    if not sess.get("authenticated"):
        await websocket.send_json({"type": "error", "message": "unauthorized"})
        await websocket.close(code=4401)
        return
    q = bridge.subscribe()
    try:
        await websocket.send_json(
            {
                "type": "status",
                "vpn": vpn.status(),
                "bridge": bridge.status(),
                "enroll": enroller.status(),
                "connection": _connection_public(),
                "secrets": _secrets_public_for_request(request),
                "iac": iac.status(),
            }
        )
        while True:
            # multiplex: client pings + bridge events
            try:
                msg = await asyncio_wait_message(websocket, q)
                if msg is None:
                    break
                await websocket.send_json(msg)
            except WebSocketDisconnect:
                break
    finally:
        bridge.unsubscribe(q)


async def asyncio_wait_message(websocket: WebSocket, q) -> dict[str, Any] | None:
    import asyncio

    ws_task = asyncio.create_task(websocket.receive_text())
    q_task = asyncio.create_task(q.get())
    done, pending = await asyncio.wait({ws_task, q_task}, return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
        t.cancel()
    if ws_task in done:
        try:
            raw = ws_task.result()
            data = __import__("json").loads(raw) if raw else {}
            if data.get("type") == "ping":
                return {
                    "type": "pong",
                    "vpn": vpn.status(),
                    "bridge": bridge.status(),
                    "enroll": enroller.status(),
                    "connection": _connection_public(),
                }
            return {
                "type": "ack",
                "vpn": vpn.status(),
                "bridge": bridge.status(),
                "enroll": enroller.status(),
                "connection": _connection_public(),
            }
        except WebSocketDisconnect:
            return None
        except Exception:  # noqa: BLE001
            return {"type": "ack"}
    if q_task in done:
        return q_task.result()
    return None


# Fix login form action: Hayabusa posts to a named form — ensure template has form
# Injected via dashboard; for login, map common post target
@app.post("/")
async def root_post_compat(request: Request) -> RedirectResponse:
    form = await request.form()
    return await login_manual(
        request,
        username=str(form.get("admin_username") or form.get("username") or ""),
        password=str(form.get("admin_password") or form.get("password") or ""),
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    global _settings, vault, iac, vpn, bridge, devops, enroller, oauth_store, ztp_edge, connection
    if settings is not None:
        _settings = settings
        _settings.ensure_dirs()
        ctrl_security.set_abuse_db_path(str(_settings.data_dir / "edge_abuse.sqlite3"))
        vault = SecretsVault(_settings)
        oauth_store = OAuthCredentialStore(vault)
        mode = (os.environ.get("CONTROLLER_OAUTH_MODE") or "broker").strip().lower()
        if mode in {"broker", "hayabusa", "proxy", ""}:
            oauth_store.purge_all()
        elif mode == "local":
            oauth_store.seal_from_env_map(dict(os.environ))
        iac = IacStore(_settings)
        vpn = VpnClient(_settings)
        devops = DevopsIacWorkspace(_settings.devops_workspace, _settings.devops_defaults)
        devops.seed_from_defaults()
        ztp_edge = ZtpEdge(
            _settings.data_dir,
            public_base_url=_settings.public_base_url,
            devops_workspace=_settings.devops_workspace,
        )

        def _rf(rel: str) -> str:
            out = devops.read_file(rel)
            if not out.get("ok"):
                raise ValueError(str(out.get("error") or "read failed"))
            return str(out.get("content") or "")

        def _lt(rel: str) -> list:
            out = devops.ls(rel)
            if not out.get("ok"):
                raise ValueError(str(out.get("error") or "list failed"))
            return list(out.get("entries") or [])

        def _isync(params: dict) -> dict:
            user_key = str((params or {}).get("user_key") or "").strip()
            files = (params or {}).get("files") if isinstance((params or {}).get("files"), list) else []
            return devops.import_sync(files, owner_id=user_key or (_settings.manual_username or "admin"))

        rpc = BridgeRpcHandler(
            vault=vault,
            devops_root=_settings.devops_workspace,
            list_tree=_lt,
            read_file=_rf,
            import_sync=_isync,
            inventory_summary=devops.inventory_summary,
            ztp_edge=ztp_edge,
            ztp_status=ztp_edge.status,
        )
        job_queue = JobQueue(_settings.data_dir, hydrator=rpc._hydrate_job)
        rpc.set_job_queue(job_queue)
        global rbac
        rbac = RbacStore(_settings.data_dir)
        rpc.set_rbac(rbac)
        from .image_nest import ImageNestStore as _ImageNestStore

        rpc.set_image_nest(_ImageNestStore(_settings.data_dir))
        bridge = HayabusaBridge(_settings, rpc_handler=rpc.handle)
        enroller = HayabusaEnroller(_settings, vault)
        _apply_enrollment_site_name()
        connection = ConnectionProgress()
        connection.set_emitter(_emit_connection_event)
    return app
