"""Controller-edge RF / MAVLink / ADS-B runtime.

Hayabusa Core is the cockpit (UI + stream URLs). This module hosts transmit /
capture on the controller appliance and exposes it over bridge RPC.

Monetization guardrail: mutating and product edge methods require a live,
granted Core control bridge. Standalone local import without Core fails closed
unless ``CONTROLLER_EDGE_ALLOW_OFFLINE=1`` (lab/dev only).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger("hayabusa.controller.edge_radio")

_LOCK = threading.RLock()
_SDR_PROC: subprocess.Popen | None = None
_SDR_STATE: dict[str, Any] = {
    "running": False,
    "area": "",
    "channel": "weather",
    "freq_hz": 0,
    "started_at": 0.0,
    "last_error": "",
    "audio_path": "",
}
_SDR_AUDIO_PATH = Path(
    os.environ.get("CONTROLLER_EDGE_SDR_AUDIO")
    or "/tmp/hayabusa-edge-sdr-audio.mp3"
)
_MAV_LOCK = threading.RLock()
_MAV_STATE: dict[str, Any] = {
    "connected": False,
    "endpoint": "",
    "vehicle_id": "default",
    "telemetry": {},
    "last_error": "",
    "last_command": None,
}
_MAV_THREAD: threading.Thread | None = None
_MAV_STOP = threading.Event()
_MAV_MASTER = None

# Wired from main after HayabusaBridge is constructed.
_BRIDGE_STATUS_FN: Callable[[], dict[str, Any]] | None = None

# Probe-only: safe without Core so operators can inventory local tools.
_CORE_OPTIONAL_METHODS = frozenset({"edge.capabilities"})


def set_bridge_status_provider(fn: Callable[[], dict[str, Any]] | None) -> None:
    """Register ``bridge.status`` so edge dispatch can require a live Core link."""
    global _BRIDGE_STATUS_FN
    _BRIDGE_STATUS_FN = fn


def _core_bridge_live() -> bool:
    if str(os.environ.get("CONTROLLER_EDGE_ALLOW_OFFLINE") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        return True
    fn = _BRIDGE_STATUS_FN
    if fn is None:
        return False
    try:
        st = fn() or {}
        return bool(st.get("connected") and st.get("granted"))
    except Exception:
        return False


def _require_core(method: str) -> dict[str, Any] | None:
    m = (method or "").strip().lower()
    if m in _CORE_OPTIONAL_METHODS:
        return None
    if _core_bridge_live():
        return None
    return {
        "ok": False,
        "success": False,
        "error": (
            "Hayabusa Core bridge required — enroll this controller and keep "
            "the control bridge granted. Edge RF/MAVLink is not available offline."
        ),
        "code": "core_required",
        "executed_on": "none",
    }


def _which(*names: str) -> str:
    for n in names:
        if n.startswith("/") and os.path.isfile(n) and os.access(n, os.X_OK):
            return n
        p = shutil.which(n)
        if p:
            return p
    return ""


def capabilities(_params: dict[str, Any] | None = None) -> dict[str, Any]:
    rtl = _which("rtl_fm", "/usr/bin/rtl_fm")
    ffmpeg = _which("ffmpeg", "/usr/bin/ffmpeg")
    dump1090 = ""
    for cand in (
        os.environ.get("CONTROLLER_DUMP1090_JSON") or "",
        "/run/dump1090-fa/aircraft.json",
        "/var/run/dump1090-fa/aircraft.json",
        "/tmp/aircraft.json",
    ):
        if cand and os.path.isfile(cand):
            dump1090 = cand
            break
    mav = False
    try:
        from pymavlink import mavutil  # noqa: F401

        mav = True
    except Exception:
        mav = False
    return {
        "ok": True,
        "platform": os.name,
        "sys_platform": getattr(__import__("sys"), "platform", ""),
        "sdr": {
            "rtl_fm": bool(rtl),
            "rtl_fm_path": rtl,
            "ffmpeg": bool(ffmpeg),
            "ffmpeg_path": ffmpeg,
            "available": bool(rtl and ffmpeg),
        },
        "adsb": {
            "dump1090_json": dump1090,
            "available": bool(dump1090),
        },
        "mavlink": {"pymavlink": mav, "available": mav},
        "running": {
            "sdr": bool(_SDR_STATE.get("running")),
            "mavlink": bool(_MAV_STATE.get("connected")),
        },
        "core_bridge_live": _core_bridge_live(),
        "core_required_for_edge": True,
    }


def _wx_freq_hz(area: str) -> int:
    # NOAA WX common channel 1–7 approx; prefer CH3/162.475 as default mid.
    # Area table is approximate; operators can pass freq_hz explicitly.
    table = {
        "CT": 162_475_000,
        "MA": 162_550_000,
        "NY": 162_550_000,
        "NJ": 162_400_000,
        "PA": 162_550_000,
    }
    return int(table.get((area or "").upper()[:2], 162_550_000))


def sdr_stop(_params: dict[str, Any] | None = None) -> dict[str, Any]:
    global _SDR_PROC
    with _LOCK:
        proc = _SDR_PROC
        _SDR_PROC = None
        _SDR_STATE["running"] = False
    if proc and proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    return {"ok": True, "success": True, "stopped": True, **sdr_status()}


def sdr_status(_params: dict[str, Any] | None = None) -> dict[str, Any]:
    with _LOCK:
        st = dict(_SDR_STATE)
        proc = _SDR_PROC
    running = bool(st.get("running")) and proc is not None and proc.poll() is None
    audio = str(st.get("audio_path") or _SDR_AUDIO_PATH)
    size = 0
    try:
        if audio and os.path.isfile(audio):
            size = int(os.path.getsize(audio))
    except OSError:
        size = 0
    return {
        "ok": True,
        "success": True,
        "running": running,
        "area": st.get("area") or "",
        "channel": st.get("channel") or "",
        "freq_hz": st.get("freq_hz") or 0,
        "started_at": st.get("started_at") or 0,
        "last_error": st.get("last_error") or "",
        "audio_bytes": size,
        "audio_path": audio,
        "executed_on": "controller",
    }


def sdr_start(params: dict[str, Any] | None = None) -> dict[str, Any]:
    global _SDR_PROC
    params = params if isinstance(params, dict) else {}
    caps = capabilities()
    if not caps.get("sdr", {}).get("available"):
        return {
            "ok": False,
            "success": False,
            "error": "SDR tools not installed on controller (need rtl_fm + ffmpeg)",
            "code": "unavailable",
            "capabilities": caps,
        }
    area = str(params.get("area") or "CT").strip().upper()[:8]
    channel = str(params.get("channel") or "weather").strip().lower()
    try:
        freq_hz = int(params.get("freq_hz") or 0)
    except (TypeError, ValueError):
        freq_hz = 0
    if freq_hz <= 0:
        freq_hz = _wx_freq_hz(area)

    sdr_stop({})
    rtl = caps["sdr"]["rtl_fm_path"]
    ffmpeg = caps["sdr"]["ffmpeg_path"]
    out_path = _SDR_AUDIO_PATH
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if out_path.is_file():
            out_path.unlink()
    except OSError:
        pass

    # rtl_fm → ffmpeg mp3 append to a rolling file Core can pull chunks from.
    rtl_cmd = [
        rtl,
        "-f",
        str(freq_hz),
        "-M",
        "fm",
        "-s",
        "22050",
        "-g",
        str(params.get("gain") or "40"),
        "-l",
        "0",
        "-E",
        "deemp",
    ]
    ff_cmd = [
        ffmpeg,
        "-hide_banner",
        "-loglevel",
        "error",
        "-f",
        "s16le",
        "-ar",
        "22050",
        "-ac",
        "1",
        "-i",
        "pipe:0",
        "-c:a",
        "libmp3lame",
        "-b:a",
        "48k",
        "-f",
        "mp3",
        str(out_path),
    ]
    try:
        rtl_p = subprocess.Popen(
            rtl_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        ff_p = subprocess.Popen(
            ff_cmd,
            stdin=rtl_p.stdout,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        if rtl_p.stdout:
            rtl_p.stdout.close()
        # Keep both; store ffmpeg as primary (dies if rtl dies via pipe).
        with _LOCK:
            _SDR_PROC = ff_p
            _SDR_STATE.update(
                {
                    "running": True,
                    "area": area,
                    "channel": channel,
                    "freq_hz": freq_hz,
                    "started_at": time.time(),
                    "last_error": "",
                    "audio_path": str(out_path),
                    "rtl_pid": rtl_p.pid,
                }
            )
            # Retain rtl handle on state for cleanup
            _SDR_STATE["_rtl_proc"] = rtl_p
    except Exception as exc:
        logger.exception("edge sdr start failed")
        return {"ok": False, "success": False, "error": str(exc)[:400], "code": "start_failed"}

    return {
        "ok": True,
        "success": True,
        "area": area,
        "channel": channel,
        "freq_hz": freq_hz,
        "stream_hint": "pull via edge.sdr.audio_chunk",
        "executed_on": "controller",
        **sdr_status(),
    }


def sdr_control(params: dict[str, Any] | None = None) -> dict[str, Any]:
    params = params if isinstance(params, dict) else {}
    action = str(params.get("action") or "").strip().lower()
    if action in {"stop", "cancel"}:
        return sdr_stop(params)
    if action in {"hold", "pause", "resume", "unhold", "next", "prev"}:
        # Minimal scanner control stub — retune on next/prev via weather table offset.
        if action in {"next", "prev"} and _SDR_STATE.get("running"):
            freqs = [162_400_000, 162_425_000, 162_450_000, 162_475_000, 162_500_000, 162_525_000, 162_550_000]
            cur = int(_SDR_STATE.get("freq_hz") or freqs[0])
            try:
                idx = freqs.index(cur)
            except ValueError:
                idx = 0
            idx = (idx + (1 if action == "next" else -1)) % len(freqs)
            return sdr_start({**params, "freq_hz": freqs[idx], "area": _SDR_STATE.get("area") or "CT"})
        return {"ok": True, "success": True, "action": action, **sdr_status()}
    return {"ok": False, "success": False, "error": f"unsupported action: {action}", "code": "bad_action"}


def sdr_audio_chunk(params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a base64 slice of the MP3 file for Core to re-stream."""
    params = params if isinstance(params, dict) else {}
    try:
        offset = max(0, int(params.get("offset") or 0))
    except (TypeError, ValueError):
        offset = 0
    try:
        max_bytes = min(max(1024, int(params.get("max_bytes") or 65536)), 512_000)
    except (TypeError, ValueError):
        max_bytes = 65536
    path = str(_SDR_STATE.get("audio_path") or _SDR_AUDIO_PATH)
    if not path or not os.path.isfile(path):
        return {
            "ok": True,
            "success": True,
            "eof": True,
            "offset": offset,
            "next_offset": offset,
            "data_b64": "",
            "running": bool(_SDR_STATE.get("running")),
        }
    try:
        size = os.path.getsize(path)
        if offset > size:
            offset = size
        with open(path, "rb") as fh:
            fh.seek(offset)
            chunk = fh.read(max_bytes)
        next_off = offset + len(chunk)
        return {
            "ok": True,
            "success": True,
            "eof": False,
            "offset": offset,
            "next_offset": next_off,
            "size": size,
            "data_b64": base64.b64encode(chunk).decode("ascii") if chunk else "",
            "content_type": "audio/mpeg",
            "running": bool(_SDR_STATE.get("running")),
            "executed_on": "controller",
        }
    except Exception as exc:
        return {"ok": False, "success": False, "error": str(exc)[:240]}


def adsb_tracks(params: dict[str, Any] | None = None) -> dict[str, Any]:
    params = params if isinstance(params, dict) else {}
    path = str(params.get("path") or "").strip()
    if not path:
        path = str(capabilities().get("adsb", {}).get("dump1090_json") or "")
    if not path or not os.path.isfile(path):
        return {
            "ok": True,
            "success": True,
            "tracks": [],
            "available": False,
            "error": "dump1090 aircraft.json not found on controller",
            "code": "unavailable",
            "executed_on": "controller",
        }
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        aircraft = data.get("aircraft") if isinstance(data, dict) else data
        tracks = []
        if isinstance(aircraft, list):
            for row in aircraft[:400]:
                if not isinstance(row, dict):
                    continue
                lat, lon = row.get("lat"), row.get("lon")
                if lat is None or lon is None:
                    continue
                tracks.append(
                    {
                        "source": "adsb",
                        "id": str(row.get("hex") or row.get("icao") or ""),
                        "hex": str(row.get("hex") or ""),
                        "label": str(row.get("flight") or row.get("hex") or "").strip(),
                        "lat": float(lat),
                        "lon": float(lon),
                        "alt_m": row.get("alt_baro") or row.get("alt_geom"),
                        "heading_deg": row.get("track"),
                        "provider": "dump1090-controller",
                    }
                )
        return {
            "ok": True,
            "success": True,
            "tracks": tracks,
            "count": len(tracks),
            "path": path,
            "available": True,
            "executed_on": "controller",
        }
    except Exception as exc:
        return {"ok": False, "success": False, "error": str(exc)[:240], "tracks": []}


def _mav_loop(endpoint: str, vehicle_id: str) -> None:
    global _MAV_MASTER
    try:
        from pymavlink import mavutil
    except Exception as exc:
        with _MAV_LOCK:
            _MAV_STATE["connected"] = False
            _MAV_STATE["last_error"] = f"pymavlink missing: {exc}"
        return
    try:
        master = mavutil.mavlink_connection(endpoint, source_system=255, autoreconnect=True)
        _MAV_MASTER = master
        with _MAV_LOCK:
            _MAV_STATE["connected"] = True
            _MAV_STATE["endpoint"] = endpoint
            _MAV_STATE["vehicle_id"] = vehicle_id
            _MAV_STATE["last_error"] = ""
        master.wait_heartbeat(timeout=12)
        try:
            master.mav.request_data_stream_send(
                master.target_system or 1,
                master.target_component or 1,
                mavutil.mavlink.MAV_DATA_STREAM_ALL,
                4,
                1,
            )
        except Exception:
            pass
        while not _MAV_STOP.is_set():
            msg = master.recv_match(blocking=True, timeout=0.5)
            if not msg:
                continue
            mtype = msg.get_type()
            tel: dict[str, Any] = {}
            with _MAV_LOCK:
                tel = dict(_MAV_STATE.get("telemetry") or {})
            if mtype == "GLOBAL_POSITION_INT":
                tel["lat"] = float(msg.lat) / 1e7
                tel["lon"] = float(msg.lon) / 1e7
                tel["relative_alt_m"] = float(msg.relative_alt) / 1000.0
                tel["heading_deg"] = float(msg.hdg) / 100.0 if getattr(msg, "hdg", None) not in (None, 65535) else tel.get("heading_deg")
            elif mtype == "HEARTBEAT":
                tel["heartbeat_at"] = time.time()
                tel["autopilot"] = int(getattr(msg, "autopilot", 0) or 0)
                tel["base_mode"] = int(getattr(msg, "base_mode", 0) or 0)
            elif mtype == "SYS_STATUS":
                tel["battery_remaining_pct"] = int(getattr(msg, "battery_remaining", -1) or -1)
            elif mtype == "ATTITUDE":
                tel["roll"] = float(getattr(msg, "roll", 0) or 0)
                tel["pitch"] = float(getattr(msg, "pitch", 0) or 0)
                tel["yaw"] = float(getattr(msg, "yaw", 0) or 0)
            with _MAV_LOCK:
                _MAV_STATE["telemetry"] = tel
                _MAV_STATE["connected"] = True
    except Exception as exc:
        logger.exception("mavlink loop failed")
        with _MAV_LOCK:
            _MAV_STATE["connected"] = False
            _MAV_STATE["last_error"] = str(exc)[:400]
    finally:
        _MAV_MASTER = None


def mavlink_disconnect(_params: dict[str, Any] | None = None) -> dict[str, Any]:
    global _MAV_THREAD, _MAV_MASTER
    _MAV_STOP.set()
    master = _MAV_MASTER
    _MAV_MASTER = None
    if master is not None:
        try:
            master.close()
        except Exception:
            pass
    thr = _MAV_THREAD
    _MAV_THREAD = None
    if thr and thr.is_alive():
        thr.join(timeout=2)
    with _MAV_LOCK:
        _MAV_STATE["connected"] = False
    return {"ok": True, "success": True, "connected": False, "executed_on": "controller"}


def mavlink_connect(params: dict[str, Any] | None = None) -> dict[str, Any]:
    global _MAV_THREAD
    params = params if isinstance(params, dict) else {}
    caps = capabilities()
    if not caps.get("mavlink", {}).get("available"):
        return {
            "ok": False,
            "success": False,
            "error": "pymavlink not installed on controller",
            "code": "unavailable",
        }
    endpoint = str(params.get("endpoint") or params.get("connection") or "").strip()
    if not endpoint:
        return {"ok": False, "success": False, "error": "endpoint required", "code": "bad_endpoint"}
    vehicle_id = str(params.get("vehicle_id") or "default")[:64]
    mavlink_disconnect({})
    _MAV_STOP.clear()
    thr = threading.Thread(target=_mav_loop, args=(endpoint, vehicle_id), daemon=True)
    _MAV_THREAD = thr
    thr.start()
    time.sleep(0.3)
    return mavlink_status({"vehicle_id": vehicle_id})


def mavlink_status(params: dict[str, Any] | None = None) -> dict[str, Any]:
    with _MAV_LOCK:
        st = {
            "ok": True,
            "success": True,
            "connected": bool(_MAV_STATE.get("connected")),
            "endpoint": _MAV_STATE.get("endpoint") or "",
            "vehicle_id": _MAV_STATE.get("vehicle_id") or "default",
            "telemetry": dict(_MAV_STATE.get("telemetry") or {}),
            "last_error": _MAV_STATE.get("last_error") or "",
            "last_command": _MAV_STATE.get("last_command"),
            "executed_on": "controller",
        }
    return st


def mavlink_telemetry(params: dict[str, Any] | None = None) -> dict[str, Any]:
    return mavlink_status(params)


def mavlink_command(params: dict[str, Any] | None = None) -> dict[str, Any]:
    params = params if isinstance(params, dict) else {}
    action = str(params.get("action") or params.get("command") or "").strip().lower()
    if not action:
        return {"ok": False, "success": False, "error": "action required"}
    master = _MAV_MASTER
    if master is None or not _MAV_STATE.get("connected"):
        return {"ok": False, "success": False, "error": "mavlink not connected", "code": "not_connected"}
    try:
        from pymavlink import mavutil

        if action in {"arm", "disarm"}:
            master.mav.command_long_send(
                master.target_system or 1,
                master.target_component or 1,
                mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
                0,
                1.0 if action == "arm" else 0.0,
                0,
                0,
                0,
                0,
                0,
                0,
            )
        elif action in {"rtl", "return"}:
            master.mav.command_long_send(
                master.target_system or 1,
                master.target_component or 1,
                mavutil.mavlink.MAV_CMD_NAV_RETURN_TO_LAUNCH,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            )
        elif action == "set_mode":
            mode = str(params.get("mode") or "RTL")
            mode_map = master.mode_mapping() or {}
            mode_id = mode_map.get(mode) or mode_map.get(mode.upper())
            if mode_id is None:
                return {"ok": False, "success": False, "error": f"unknown mode {mode}"}
            master.set_mode(mode_id)
        else:
            return {"ok": False, "success": False, "error": f"unsupported action: {action}"}
        with _MAV_LOCK:
            _MAV_STATE["last_command"] = {"action": action, "at": time.time()}
        return {"ok": True, "success": True, "action": action, "executed_on": "controller"}
    except Exception as exc:
        return {"ok": False, "success": False, "error": str(exc)[:400]}


def mavlink_mission(params: dict[str, Any] | None = None) -> dict[str, Any]:
    # Placeholder — mission upload stays Core-orchestrated later; acknowledge path.
    return {
        "ok": False,
        "success": False,
        "error": "mission upload via edge RPC not implemented yet — use status/telemetry",
        "code": "not_implemented",
    }


def mavlink_joystick(params: dict[str, Any] | None = None) -> dict[str, Any]:
    params = params if isinstance(params, dict) else {}
    master = _MAV_MASTER
    if master is None or not _MAV_STATE.get("connected"):
        return {"ok": False, "success": False, "error": "mavlink not connected", "code": "not_connected"}
    if not params.get("enabled"):
        return {"ok": True, "success": True, "enabled": False}
    try:
        x = int(float(params.get("x") or 0))
        y = int(float(params.get("y") or 0))
        z = int(float(params.get("z") or 500))
        r = int(float(params.get("r") or 0))
        buttons = int(params.get("buttons") or 0)
        master.mav.manual_control_send(
            master.target_system or 1,
            x,
            y,
            z,
            r,
            buttons,
        )
        return {"ok": True, "success": True, "executed_on": "controller"}
    except Exception as exc:
        return {"ok": False, "success": False, "error": str(exc)[:240]}


def dispatch(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Route edge.* RPC methods."""
    m = (method or "").strip().lower()
    blocked = _require_core(m)
    if blocked is not None:
        return blocked
    p = params if isinstance(params, dict) else {}
    table = {
        "edge.capabilities": capabilities,
        "edge.sdr.start": sdr_start,
        "edge.sdr.stop": sdr_stop,
        "edge.sdr.status": sdr_status,
        "edge.sdr.control": sdr_control,
        "edge.sdr.audio_chunk": sdr_audio_chunk,
        "edge.adsb.tracks": adsb_tracks,
        "edge.mavlink.connect": mavlink_connect,
        "edge.mavlink.disconnect": mavlink_disconnect,
        "edge.mavlink.status": mavlink_status,
        "edge.mavlink.telemetry": mavlink_telemetry,
        "edge.mavlink.command": mavlink_command,
        "edge.mavlink.mission": mavlink_mission,
        "edge.mavlink.joystick": mavlink_joystick,
    }
    fn = table.get(m)
    if not fn:
        return {"ok": False, "error": f"unknown edge method: {method}", "code": "bad_method"}
    try:
        out = fn(p)
        if not isinstance(out, dict):
            return {"ok": False, "error": "invalid edge handler result"}
        out.setdefault("core_bridged", True)
        return out
    except Exception as exc:
        logger.exception("edge dispatch %s failed", m)
        return {"ok": False, "error": str(exc)[:400], "code": "edge_error"}
