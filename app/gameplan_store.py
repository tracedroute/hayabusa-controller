"""Gameplan Blueprints store — controller is source of truth for saved graphs.

JSON file under CONTROLLER_DATA_DIR/gameplan/blueprints.json.
Hayabusa Core pushes/pulls via bridge RPC (gameplan.*); the controller UI lists them.
Does not modify Ansible/ or OpenTofu/ workspaces.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Any

_LOCK = threading.RLock()
_MAX_PER_OWNER = 80
_MAX_NODES = 200
_MAX_EDGES = 400
_SAFE_OWNER = re.compile(r"[^a-zA-Z0-9._@+-]+")
_ALLOWED_KINDS = frozenset(
    {
        "discovery",
        "filter",
        "bootstrap",
        "recipe",
        "opentofu",
        "ansible",
        "custom",
    }
)


def _safe_owner(owner: str) -> str:
    cleaned = _SAFE_OWNER.sub("_", (owner or "").strip())[:120]
    return cleaned or "anonymous"


def _new_id(prefix: str = "bp") -> str:
    return f"{prefix}_{secrets.token_hex(6)}"


class GameplanStore:
    def __init__(self, data_dir: Path | str) -> None:
        self.root = Path(data_dir) / "gameplan"
        self.path = self.root / "blueprints.json"

    def _empty(self) -> dict[str, Any]:
        return {"version": 1, "blueprints": {}}

    def _load(self) -> dict[str, Any]:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                return self._empty()
            data.setdefault("version", 1)
            data.setdefault("blueprints", {})
            return data
        except FileNotFoundError:
            return self._empty()
        except Exception:
            return self._empty()

    def _save(self, data: dict[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(f".{os.getpid()}.tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, self.path)

    def _sanitize_graph(self, payload: dict[str, Any]) -> tuple[list[dict], list[dict]]:
        nodes_in = payload.get("nodes") if isinstance(payload.get("nodes"), list) else []
        edges_in = payload.get("edges") if isinstance(payload.get("edges"), list) else []
        nodes: list[dict] = []
        seen: set[str] = set()
        for raw in nodes_in[:_MAX_NODES]:
            if not isinstance(raw, dict):
                continue
            nid = str(raw.get("id") or "").strip() or _new_id("n")
            if nid in seen:
                continue
            seen.add(nid)
            kind = str(raw.get("kind") or "opentofu").strip().lower()
            if kind not in _ALLOWED_KINDS:
                kind = "opentofu"
            try:
                x = float(raw.get("x") or 0)
                y = float(raw.get("y") or 0)
            except (TypeError, ValueError):
                x, y = 40.0, 40.0
            nodes.append(
                {
                    "id": nid,
                    "kind": kind,
                    "label": str(raw.get("label") or kind).strip()[:120],
                    "x": max(-4000, min(8000, x)),
                    "y": max(-4000, min(8000, y)),
                    "config": raw.get("config") if isinstance(raw.get("config"), dict) else {},
                }
            )
        ids = {n["id"] for n in nodes}
        edges: list[dict] = []
        seen_e: set[tuple[str, str]] = set()
        for raw in edges_in[:_MAX_EDGES]:
            if not isinstance(raw, dict):
                continue
            frm = str(raw.get("from") or "").strip()
            to = str(raw.get("to") or "").strip()
            if not frm or not to or frm == to or frm not in ids or to not in ids:
                continue
            if (frm, to) in seen_e:
                continue
            seen_e.add((frm, to))
            edges.append(
                {
                    "id": str(raw.get("id") or "").strip() or _new_id("e"),
                    "from": frm,
                    "to": to,
                }
            )
        return nodes, edges

    def list_blueprints(self, owner: str) -> list[dict[str, Any]]:
        owner_key = _safe_owner(owner)
        with _LOCK:
            data = self._load()
            out = []
            for bp in data.get("blueprints", {}).values():
                if not isinstance(bp, dict):
                    continue
                if str(bp.get("owner") or "") != owner_key:
                    continue
                out.append(
                    {
                        "id": bp.get("id"),
                        "name": bp.get("name") or "Untitled",
                        "description": bp.get("description") or "",
                        "updated_at": bp.get("updated_at") or 0,
                        "created_at": bp.get("created_at") or 0,
                        "node_count": len(bp.get("nodes") or []),
                        "edge_count": len(bp.get("edges") or []),
                    }
                )
            out.sort(key=lambda r: (-float(r.get("updated_at") or 0), str(r.get("name") or "")))
            return out

    def get_blueprint(self, owner: str, blueprint_id: str) -> dict[str, Any] | None:
        owner_key = _safe_owner(owner)
        bp_id = str(blueprint_id or "").strip()
        with _LOCK:
            bp = self._load().get("blueprints", {}).get(bp_id)
            if not isinstance(bp, dict):
                return None
            if str(bp.get("owner") or "") != owner_key:
                return None
            return dict(bp)

    def save_blueprint(self, owner: str, payload: dict[str, Any]) -> dict[str, Any]:
        owner_key = _safe_owner(owner)
        nodes, edges = self._sanitize_graph(payload if isinstance(payload, dict) else {})
        name = str((payload or {}).get("name") or "Untitled blueprint").strip()[:120] or "Untitled blueprint"
        description = str((payload or {}).get("description") or "").strip()[:2000]
        bp_id = str((payload or {}).get("id") or "").strip()
        now = time.time()
        with _LOCK:
            data = self._load()
            owned = [
                b
                for b in data.get("blueprints", {}).values()
                if isinstance(b, dict) and str(b.get("owner") or "") == owner_key
            ]
            if bp_id and bp_id in data.get("blueprints", {}):
                existing = data["blueprints"][bp_id]
                if str(existing.get("owner") or "") != owner_key:
                    raise PermissionError("blueprint belongs to another owner")
            elif not bp_id:
                if len(owned) >= _MAX_PER_OWNER:
                    raise ValueError(f"blueprint limit ({_MAX_PER_OWNER}) reached")
                bp_id = _new_id("bp")
            elif len(owned) >= _MAX_PER_OWNER and bp_id not in {
                str(b.get("id") or "") for b in owned
            }:
                raise ValueError(f"blueprint limit ({_MAX_PER_OWNER}) reached")

            record = {
                "id": bp_id,
                "owner": owner_key,
                "name": name,
                "description": description,
                "nodes": nodes,
                "edges": edges,
                "updated_at": now,
                "created_at": float(
                    (data.get("blueprints", {}).get(bp_id) or {}).get("created_at") or now
                ),
                "source": "hayabusa-gameplan",
            }
            data.setdefault("blueprints", {})[bp_id] = record
            self._save(data)
            return dict(record)

    def delete_blueprint(self, owner: str, blueprint_id: str) -> bool:
        owner_key = _safe_owner(owner)
        bp_id = str(blueprint_id or "").strip()
        with _LOCK:
            data = self._load()
            bp = data.get("blueprints", {}).get(bp_id)
            if not isinstance(bp, dict) or str(bp.get("owner") or "") != owner_key:
                return False
            data["blueprints"].pop(bp_id, None)
            self._save(data)
            return True

    def status(self) -> dict[str, Any]:
        with _LOCK:
            data = self._load()
            n = len(data.get("blueprints") or {})
            return {"ok": True, "path": str(self.path), "count": n}
