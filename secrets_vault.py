"""Encrypted secrets store for Hayabusa Controller."""

from __future__ import annotations

import json
import os
import re
import threading
import time
from base64 import urlsafe_b64encode
from hashlib import sha256
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from .config import Settings

_LOCK = threading.Lock()

# Internal appliance secrets — never listed or readable via /api/secrets.
RESERVED_SECRET_PREFIX = "__hayabusa_"

SECRET_KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

SECRET_CATEGORIES: dict[str, str] = {
    "general": "General",
    "ssh": "SSH / console",
    "network": "Network device",
    "hypervisor": "Hypervisor / VM host",
    "database": "Database",
    "api": "API / service account",
    "cloud": "Cloud provider",
    "ansible": "Ansible / automation",
    "ztp": "ZTP provisioning",
    "iot": "IoT / embedded",
    "scada": "SCADA / industrial",
    "application": "Application login",
}

# Older vault entries may still use "proxmox"; treat as hypervisor.
_CATEGORY_ALIASES: dict[str, str] = {
    "proxmox": "hypervisor",
}

SECRET_KINDS: dict[str, str] = {
    "username": "Username",
    "password": "Password",
    "token": "Token / API key",
    "other": "Other",
}


def is_reserved_secret_key(key: str) -> bool:
    return (key or "").strip().startswith(RESERVED_SECRET_PREFIX)


def _fernet(secret_key: str) -> Fernet:
    k = urlsafe_b64encode(sha256((secret_key + "\x1ehayabusa-controller-vault-v1\x1e").encode()).digest())
    return Fernet(k)


def _now() -> float:
    return time.time()


def _norm_meta(raw: dict[str, Any] | None) -> dict[str, str]:
    raw = raw if isinstance(raw, dict) else {}
    cat = str(raw.get("category") or "general").strip().lower()
    cat = _CATEGORY_ALIASES.get(cat, cat)
    if cat not in SECRET_CATEGORIES:
        cat = "general"
    kind = str(raw.get("kind") or "other").strip().lower()
    if kind not in SECRET_KINDS:
        kind = "other"
    host = str(raw.get("host") or "").strip()[:256]
    label = str(raw.get("label") or "").strip()[:256]
    return {"category": cat, "kind": kind, "host": host, "label": label}


class SecretsVault:
    def __init__(self, settings: Settings) -> None:
        self.path = settings.secrets_dir / "vault.enc"
        self._f = _fernet(settings.secret_key)

    def _load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {"version": 2, "secrets": {}, "meta": {}}
        raw = self.path.read_bytes()
        try:
            data = json.loads(self._f.decrypt(raw).decode("utf-8"))
        except (InvalidToken, json.JSONDecodeError, UnicodeDecodeError):
            return {"version": 2, "secrets": {}, "meta": {}}
        if not isinstance(data, dict):
            return {"version": 2, "secrets": {}, "meta": {}}
        data.setdefault("secrets", {})
        data.setdefault("meta", {})
        if int(data.get("version") or 1) < 2:
            data["version"] = 2
            meta = data.setdefault("meta", {})
            if not isinstance(meta, dict):
                meta = {}
                data["meta"] = meta
            for k in list((data.get("secrets") or {}).keys()):
                if k not in meta:
                    meta[k] = _norm_meta({})
        return data

    def _save(self, data: dict[str, Any]) -> None:
        data["version"] = 2
        payload = self._f.encrypt(json.dumps(data, indent=2, sort_keys=True).encode("utf-8"))
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(payload)
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _validate_key(self, key: str) -> str:
        key = (key or "").strip()
        if not key or "/" in key or ".." in key or not SECRET_KEY_RE.match(key):
            raise ValueError("invalid secret key")
        return key

    def list_keys(self, *, include_reserved: bool = False) -> list[str]:
        with _LOCK:
            keys = list((self._load().get("secrets") or {}).keys())
        if not include_reserved:
            keys = [k for k in keys if not is_reserved_secret_key(str(k))]
        return sorted(keys)

    def get_meta(self, key: str) -> dict[str, Any] | None:
        key = (key or "").strip()
        if not key or is_reserved_secret_key(key):
            return None
        with _LOCK:
            data = self._load()
            if key not in (data.get("secrets") or {}):
                return None
            meta = (data.get("meta") or {}).get(key) or {}
            out = _norm_meta(meta if isinstance(meta, dict) else {})
            if isinstance(meta, dict):
                if meta.get("updated_at"):
                    out["updated_at"] = float(meta["updated_at"])
                if meta.get("updated_by"):
                    out["updated_by"] = str(meta["updated_by"])[:128]
            return out

    def list_catalog(self, *, include_reserved: bool = False) -> list[dict[str, Any]]:
        with _LOCK:
            data = self._load()
            secrets = data.get("secrets") or {}
            meta_root = data.get("meta") or {}
        out: list[dict[str, Any]] = []
        for key in sorted(secrets.keys()):
            if not include_reserved and is_reserved_secret_key(str(key)):
                continue
            m = meta_root.get(key) if isinstance(meta_root, dict) else {}
            nm = _norm_meta(m if isinstance(m, dict) else {})
            row: dict[str, Any] = {
                "key": key,
                "category": nm["category"],
                "category_label": SECRET_CATEGORIES.get(nm["category"], nm["category"]),
                "kind": nm["kind"],
                "kind_label": SECRET_KINDS.get(nm["kind"], nm["kind"]),
                "host": nm["host"],
                "label": nm["label"],
                "has_value": secrets.get(key) is not None and str(secrets.get(key)) != "",
            }
            if isinstance(m, dict) and m.get("updated_at"):
                row["updated_at"] = float(m["updated_at"])
            out.append(row)
        return out

    def get(self, key: str, *, allow_reserved: bool = False) -> str | None:
        key = (key or "").strip()
        if not key:
            return None
        if is_reserved_secret_key(key) and not allow_reserved:
            return None
        with _LOCK:
            secrets = self._load().get("secrets") or {}
            val = secrets.get(key)
            return str(val) if val is not None else None

    def put(
        self,
        key: str,
        value: str,
        *,
        category: str = "",
        kind: str = "",
        host: str = "",
        label: str = "",
        updated_by: str = "",
        allow_reserved: bool = False,
    ) -> None:
        key = self._validate_key(key)
        if is_reserved_secret_key(key) and not allow_reserved:
            raise ValueError("reserved secret key")
        with _LOCK:
            data = self._load()
            secrets = data.setdefault("secrets", {})
            meta_root = data.setdefault("meta", {})
            prev_meta = meta_root.get(key) if isinstance(meta_root.get(key), dict) else {}
            secrets[key] = value
            nm = _norm_meta(
                {
                    "category": category or (prev_meta.get("category") if prev_meta else "general"),
                    "kind": kind or (prev_meta.get("kind") if prev_meta else "other"),
                    "host": host if host != "" else (prev_meta.get("host") if prev_meta else ""),
                    "label": label if label != "" else (prev_meta.get("label") if prev_meta else ""),
                }
            )
            nm["updated_at"] = _now()
            if updated_by:
                nm["updated_by"] = str(updated_by)[:128]
            elif prev_meta.get("updated_by"):
                nm["updated_by"] = str(prev_meta.get("updated_by"))[:128]
            meta_root[key] = nm
            self._save(data)

    def update_meta(
        self,
        key: str,
        *,
        category: str | None = None,
        kind: str | None = None,
        host: str | None = None,
        label: str | None = None,
        updated_by: str = "",
    ) -> bool:
        key = self._validate_key(key)
        if is_reserved_secret_key(key):
            return False
        with _LOCK:
            data = self._load()
            secrets = data.get("secrets") or {}
            if key not in secrets:
                return False
            meta_root = data.setdefault("meta", {})
            prev = meta_root.get(key) if isinstance(meta_root.get(key), dict) else {}
            nm = _norm_meta(prev)
            if category is not None:
                nm["category"] = _norm_meta({"category": category})["category"]
            if kind is not None:
                nm["kind"] = _norm_meta({"kind": kind})["kind"]
            if host is not None:
                nm["host"] = str(host).strip()[:256]
            if label is not None:
                nm["label"] = str(label).strip()[:256]
            nm["updated_at"] = _now()
            if updated_by:
                nm["updated_by"] = str(updated_by)[:128]
            meta_root[key] = nm
            self._save(data)
            return True

    def delete(self, key: str, *, allow_reserved: bool = False) -> bool:
        key = (key or "").strip()
        if is_reserved_secret_key(key) and not allow_reserved:
            return False
        with _LOCK:
            data = self._load()
            secrets = data.setdefault("secrets", {})
            if key not in secrets:
                return False
            del secrets[key]
            meta_root = data.setdefault("meta", {})
            if isinstance(meta_root, dict) and key in meta_root:
                del meta_root[key]
            self._save(data)
            return True

    def public_status(self) -> dict[str, Any]:
        catalog = self.list_catalog(include_reserved=False)
        return {
            "count": len(catalog),
            "keys": [row["key"] for row in catalog],
            "catalog": catalog,
            "categories": [{"id": k, "label": v} for k, v in SECRET_CATEGORIES.items()],
            "kinds": [{"id": k, "label": v} for k, v in SECRET_KINDS.items()],
        }
