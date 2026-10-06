"""Track Enroll → Mesh → Bridge progress for the controller dashboard / WS."""

from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable


EmitFn = Callable[[dict[str, Any]], Awaitable[None]]


def phase_from_steps(steps: dict[str, dict[str, str]]) -> str:
    """Derive pipeline phase. ``ready`` only when enroll+mesh+bridge are all ok."""
    for step in ("enroll", "mesh", "bridge"):
        st = str((steps.get(step) or {}).get("state") or "idle")
        if st in {"failed", "error"}:
            return f"{step}_failed"
        if st in {"pending", "running"}:
            return f"{step}_running"
    if all(str((steps.get(s) or {}).get("state") or "") == "ok" for s in ("enroll", "mesh", "bridge")):
        return "ready"
    if any(str((steps.get(s) or {}).get("state") or "") == "ok" for s in ("enroll", "mesh", "bridge")):
        return "partial"
    return "idle"


def enrich_connection_steps(
    steps_in: dict[str, Any] | None,
    *,
    enroll: dict[str, Any] | None,
    vpn: dict[str, Any] | None,
    bridge: dict[str, Any] | None,
) -> dict[str, dict[str, str]]:
    """Reconcile pipeline steps with live enroll/VPN/bridge truth.

    A Tailscale mesh IP alone must never make the pipeline look fully connected.
    ``bridge`` is ``ok`` only when Hayabusa has granted the control session.
    """
    enroll = enroll if isinstance(enroll, dict) else {}
    vpn = vpn if isinstance(vpn, dict) else {}
    bridge = bridge if isinstance(bridge, dict) else {}

    steps: dict[str, dict[str, str]] = {
        "enroll": {"state": "idle", "detail": ""},
        "mesh": {"state": "idle", "detail": ""},
        "bridge": {"state": "idle", "detail": ""},
    }
    if isinstance(steps_in, dict):
        for key in steps:
            raw = steps_in.get(key)
            if isinstance(raw, dict):
                steps[key] = {
                    "state": str(raw.get("state") or "idle"),
                    "detail": str(raw.get("detail") or "")[:400],
                }

    enrolled = bool(enroll.get("enrolled") or enroll.get("ok"))
    if enrolled:
        if steps["enroll"]["state"] in {"idle", "pending", "running"}:
            steps["enroll"] = {"state": "ok", "detail": steps["enroll"]["detail"] or "Enrolled"}
    elif enroll.get("error"):
        if steps["enroll"]["state"] not in {"failed", "error"}:
            steps["enroll"] = {
                "state": "failed",
                "detail": str(enroll.get("error") or "Enrollment failed")[:400],
            }

    if vpn.get("connected"):
        # Mesh up is real progress — always clear a stale failed/error step.
        # Do not present the CGNAT mesh address as the controller's site/public
        # identity — that lives in public_ip / WAN fields.
        steps["mesh"] = {"state": "ok", "detail": "Mesh VPN up"}
    elif vpn.get("error") or vpn.get("error_code"):
        steps["mesh"] = {
            "state": "failed",
            "detail": str(vpn.get("error") or vpn.get("error_code") or "Mesh failed")[:400],
        }
    elif steps["mesh"]["state"] == "ok":
        # Stale tracker: had an IP earlier but Tailscale is down now.
        steps["mesh"] = {"state": "failed", "detail": "Mesh VPN disconnected"}

    granted = bool(bridge.get("granted"))
    if "identity_claimed" in bridge:
        claimed = bool(bridge.get("identity_claimed"))
    else:
        # Legacy callers/tests without the field: a grant counts as claimed.
        claimed = granted
    # Unclaimed boot/mesh sessions are not fully linked for Hayabusa map ownership.
    if granted and not claimed:
        granted = False
        if vpn.get("connected"):
            steps["bridge"] = {
                "state": "pending",
                "detail": "Mesh bridge up — sign in to claim this controller for your Hayabusa account",
            }
    br_connected = bool(bridge.get("connected"))
    br_err = str(bridge.get("last_error") or "").strip()
    if granted and claimed:
        steps["bridge"] = {"state": "ok", "detail": "Granted"}
    elif br_err and not br_connected:
        steps["bridge"] = {"state": "failed", "detail": br_err[:400]}
    elif br_connected and not claimed:
        steps["bridge"] = {
            "state": "pending",
            "detail": "WebSocket up — sign in to claim this controller for your Hayabusa account",
        }
    elif br_connected:
        steps["bridge"] = {
            "state": "pending",
            "detail": "WebSocket up — waiting for Hayabusa grant",
        }
    elif vpn.get("connected"):
        # Mesh IP present is not enough: control plane still needs a grant.
        steps["bridge"] = {
            "state": "pending",
            "detail": "Mesh VPN up — control bridge not granted",
        }
    elif steps["bridge"]["state"] == "ok":
        steps["bridge"] = {"state": "idle", "detail": "Control bridge not granted"}

    return steps


def public_connection_view(
    snap: dict[str, Any] | None,
    *,
    enroll: dict[str, Any] | None,
    vpn: dict[str, Any] | None,
    bridge: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build Connection-tab payload. Ready/linked require bridge grant + claimed identity."""
    snap = dict(snap) if isinstance(snap, dict) else {}
    bridge = bridge if isinstance(bridge, dict) else {}
    vpn = vpn if isinstance(vpn, dict) else {}
    steps = enrich_connection_steps(snap.get("steps"), enroll=enroll, vpn=vpn, bridge=bridge)
    phase = phase_from_steps(steps)
    if "identity_claimed" in bridge:
        claimed = bool(bridge.get("identity_claimed"))
    else:
        claimed = bool(bridge.get("granted"))
    granted = bool(bridge.get("granted")) and claimed
    mesh_up = bool(vpn.get("connected"))
    # Hard rule: never advertise ready/linked on mesh IP alone or unclaimed boot sessions.
    if phase == "ready" and not granted:
        phase = "bridge_running" if mesh_up else "partial"
        if steps["bridge"]["state"] == "ok":
            steps["bridge"] = {
                "state": "pending",
                "detail": "Mesh VPN up — control bridge not granted",
            }
            phase = phase_from_steps(steps)
    linked = bool(granted and bridge.get("connected") and claimed)
    ready = phase == "ready" and granted
    return {
        "phase": phase,
        "updated_at": snap.get("updated_at") or 0,
        "steps": steps,
        "ready": ready,
        "linked": linked,
        "bridge_granted": granted,
        "identity_claimed": claimed,
        "mesh_connected": mesh_up,
    }


class ConnectionProgress:
    """In-memory pipeline status (not secrets). Broadcast to WS listeners."""

    STEPS = ("enroll", "mesh", "bridge")

    def __init__(self) -> None:
        self._steps: dict[str, dict[str, str]] = {
            "enroll": {"state": "idle", "detail": ""},
            "mesh": {"state": "idle", "detail": ""},
            "bridge": {"state": "idle", "detail": ""},
        }
        self._phase = "idle"
        self._updated_at = 0
        self._emit: EmitFn | None = None
        self._lock = asyncio.Lock()

    def set_emitter(self, emit: EmitFn | None) -> None:
        self._emit = emit

    def snapshot(self) -> dict[str, Any]:
        return {
            "phase": self._phase,
            "updated_at": self._updated_at,
            "steps": {k: dict(v) for k, v in self._steps.items()},
        }

    async def reset(self) -> None:
        async with self._lock:
            for k in self.STEPS:
                self._steps[k] = {"state": "idle", "detail": ""}
            self._phase = "idle"
            self._updated_at = int(time.time())
        await self._broadcast()

    async def set_step(self, step: str, state: str, detail: str = "") -> None:
        if step not in self.STEPS:
            return
        async with self._lock:
            self._steps[step] = {"state": state, "detail": (detail or "")[:400]}
            self._phase = self._derive_phase()
            self._updated_at = int(time.time())
        await self._broadcast()

    def _derive_phase(self) -> str:
        return phase_from_steps(self._steps)

    async def _broadcast(self) -> None:
        if not self._emit:
            return
        try:
            await self._emit({"type": "connection", "connection": self.snapshot()})
        except Exception:  # noqa: BLE001
            pass
