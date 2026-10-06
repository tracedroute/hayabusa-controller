"""Image Nest — user-supplied ISO bank on the Hayabusa Controller.

Legal posture: the controller never ships Windows media. Users upload their own
ISO. We process it locally (manifest + optional strip/full bake) and catalog
dated artifacts under CONTROLLER_DATA_DIR/image-nest/.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Callable

_LOCK = threading.RLock()

SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,180}$")
MAX_ISO_BYTES = int(os.environ.get("IMAGE_NEST_MAX_ISO_BYTES") or str(16 * 1024 * 1024 * 1024))
MIN_FREE_AFTER_UPLOAD = int(os.environ.get("IMAGE_NEST_MIN_FREE_BYTES") or str(1024 * 1024 * 1024))
UPLOAD_STREAM_HEADROOM = int(
    os.environ.get("IMAGE_NEST_UPLOAD_HEADROOM_BYTES") or str(256 * 1024 * 1024)
)

# Offline strip targets are defined in profiles/strip-catalog.json (user-editable catalog).
STRIP_CATALOG_FILENAME = "strip-catalog.json"
LINUX_STRIP_CATALOG_FILENAME = "linux-strip-catalog.json"

try:
    from app import image_nest_linux as _linux
except ImportError:  # running as loose module / unit tests
    import image_nest_linux as _linux  # type: ignore



def _now() -> float:
    return time.time()


def _ts_slug() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _iso_utc(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts or _now(), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def detect_os_media(
    *,
    filename: str = "",
    label: str = "",
    wim_info: str = "",
    iso_listing: str = "",
    source_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Classify uploaded media as Windows or Linux for banking / strip."""
    linux = _linux.detect_linux_media(
        filename=filename,
        label=label,
        iso_listing=iso_listing,
        source_meta=source_meta,
    )
    if linux:
        return linux
    win = detect_windows_media(
        filename=filename,
        label=label,
        wim_info=wim_info,
        source_meta=source_meta,
    )
    out = dict(win)
    out["platform"] = "windows"
    out.setdefault("distro", out.get("product") or "windows")
    return out


def detect_windows_media(
    *,
    filename: str = "",
    label: str = "",
    wim_info: str = "",
    source_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Classify uploaded Windows media as client (Win10/11) or server."""
    meta = source_meta if isinstance(source_meta, dict) else {}
    blob = " ".join(
        [
            str(filename or ""),
            str(label or ""),
            str(meta.get("edition") or ""),
            str(meta.get("product") or ""),
            str(meta.get("os_family") or ""),
            str(wim_info or "")[:8000],
        ]
    ).lower()

    server_hints = (
        "windows server",
        "windowsserver",
        "serverstandard",
        "serverdatacenter",
        "serverrdsh",
        "serverazureedition",
        "installation type:      server",
        "installation type: server",
        "ws2019",
        "ws2022",
        "ws2025",
        "server_2019",
        "server_2022",
        "server_2025",
        "server2019",
        "server2022",
        "server2025",
        "_server_",
    )
    client_hints = (
        "windows 11",
        "windows 10",
        "win11",
        "win10",
        "windows11",
        "windows10",
        "edition id:             professional",
        "edition id:             core",
        "edition id:             enterprise",
        "installation type:      client",
    )

    family = str(meta.get("os_family") or "").strip().lower()
    if family in {"server", "winserver", "windows_server"}:
        family = "server"
    elif family in {"client", "win11", "win10", "windows_client"}:
        family = "client"
    elif any(h in blob for h in server_hints):
        family = "server"
    elif any(h in blob for h in client_hints):
        family = "client"
    else:
        family = "client"

    product = "windows-server" if family == "server" else "windows-client"
    if "2025" in blob and family == "server":
        product = "windows-server-2025"
    elif "2022" in blob and family == "server":
        product = "windows-server-2022"
    elif "2019" in blob and family == "server":
        product = "windows-server-2019"
    elif "windows 11" in blob or "win11" in blob:
        product = "windows-11"
    elif "windows 10" in blob or "win10" in blob:
        product = "windows-10"

    slug = "winserver" if family == "server" else ("win10" if "windows 10" in blob or "win10" in blob else "win11")
    return {
        "os_family": family,
        "product": product,
        "name_slug": slug,
        "label": "Windows Server" if family == "server" else "Windows client",
        "platform": "windows",
        "distro": product,
    }


def _windowsapps_package_names(listing: str) -> list[str]:
    """Top-level package folder names under Program Files/WindowsApps."""
    names: list[str] = []
    seen: set[str] = set()
    for raw in (listing or "").splitlines():
        line = raw.strip().replace("\\", "/")
        marker = "/Program Files/WindowsApps/"
        if marker not in line:
            continue
        rest = line.split(marker, 1)[1]
        pkg = rest.split("/", 1)[0].strip()
        if not pkg or pkg in {"Deleted", "Merged"} or pkg in seen:
            continue
        seen.add(pkg)
        names.append(pkg)
    return names


def _appx_family(folder: str) -> str:
    """Publisher.Name from a WindowsApps folder (strip version/arch/publisher id)."""
    name = str(folder or "").strip()
    if not name or name in {"Deleted", "Merged"}:
        return ""
    m = re.match(r"^(.+?)_\d", name)
    return m.group(1) if m else name


def _group_appx_packages(folder_names: list[str]) -> list[dict[str, Any]]:
    """Collapse versioned AppX folders into selectable family rows."""
    groups: dict[str, dict[str, Any]] = {}
    for folder in folder_names:
        fam = _appx_family(folder)
        if not fam:
            continue
        row = groups.get(fam)
        if not row:
            row = {
                "id": fam,
                "name": fam,
                "label": fam,
                "kind": "appx",
                "variants": [],
                "category": "Other",
                "recommended": False,
            }
            groups[fam] = row
        row["variants"].append(folder)
    out = list(groups.values())
    out.sort(key=lambda r: str(r.get("name") or "").lower())
    return out


def _expand_wim_globs(patterns: list[str], listing: str) -> list[str]:
    """Expand catalog globs / package families to concrete WIM paths (wimlib form)."""
    packages = _windowsapps_package_names(listing)
    out: list[str] = []
    seen: set[str] = set()
    for pat in patterns:
        raw = str(pat or "").strip().replace("/", "\\")
        if not raw:
            continue
        # Bare package / family name from inventory UI (no path separators)
        if "\\" not in raw and "/" not in raw.replace("\\", "/"):
            leaf = raw
            for pkg in packages:
                fam = _appx_family(pkg)
                if (
                    pkg.lower() == leaf.lower()
                    or fam.lower() == leaf.lower()
                    or fnmatch.fnmatch(pkg.lower(), leaf.lower())
                    or fnmatch.fnmatch(fam.lower(), leaf.lower())
                ):
                    norm = f"/Program Files/WindowsApps/{pkg}"
                    if norm not in seen:
                        seen.add(norm)
                        out.append(norm)
            continue
        # Exact non-glob path
        if "*" not in raw and "?" not in raw and "[" not in raw:
            norm = raw.replace("\\", "/")
            if not norm.startswith("/"):
                norm = "/" + norm
            if norm not in seen:
                seen.add(norm)
                out.append(norm)
            continue
        # Match package directory names against the glob's last segment
        leaf = raw.replace("\\", "/").rstrip("/").split("/")[-1]
        for pkg in packages:
            fam = _appx_family(pkg)
            if fnmatch.fnmatch(pkg.lower(), leaf.lower()) or fnmatch.fnmatch(
                fam.lower(), leaf.lower()
            ):
                norm = f"/Program Files/WindowsApps/{pkg}"
                if norm not in seen:
                    seen.add(norm)
                    out.append(norm)
    return out


def _fmt_disk_bytes(n: int) -> str:
    n = int(n or 0)
    if n < 0:
        return "0 B"
    if n >= 1024**3:
        return f"{n / 1024**3:.1f} GB"
    if n >= 1024**2:
        return f"{n / 1024**2:.0f} MB"
    if n >= 1024:
        return f"{n / 1024:.0f} KB"
    return f"{n} B"


class ImageNestStore:
    """Filesystem + JSON catalog for Image Nest."""

    def __init__(self, data_dir: Path) -> None:
        self.root = Path(data_dir) / "image-nest"
        self.iso_cache = self.root / "iso-cache"
        self.image_bank = self.root / "image-bank"
        self.manifests = self.root / "manifests"
        self.profiles = self.root / "profiles"
        self.jobs_dir = self.root / "jobs"
        self.playbook_refs_dir = self.root / "playbook-refs"
        self.inventories_dir = self.root / "inventories"
        self.registry_path = self.root / "registry.json"
        self.catalog_path = self.root / "catalog.json"
        for d in (
            self.iso_cache,
            self.image_bank,
            self.manifests,
            self.profiles,
            self.jobs_dir,
            self.playbook_refs_dir,
            self.inventories_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)
        self._ensure_profiles()
        self._ensure_strip_catalog()
        self._ensure_catalog()
        self._ensure_registry()

    def _ensure_catalog(self) -> None:
        if not self.catalog_path.is_file():
            self._save({"version": 1, "isos": {}, "images": {}, "jobs": {}})

    def _ensure_registry(self) -> None:
        if not self.registry_path.is_file():
            self._save_registry(
                {
                    "version": 1,
                    "updated_at_iso": _iso_utc(),
                    "repo_root": str(self.root),
                    "refs": {},
                    "aliases": {},
                }
            )

    def _load_registry(self) -> dict[str, Any]:
        with _LOCK:
            try:
                raw = json.loads(self.registry_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                raw = {"version": 1, "refs": {}, "aliases": {}}
            if not isinstance(raw, dict):
                raw = {"version": 1, "refs": {}, "aliases": {}}
            if not isinstance(raw.get("refs"), dict):
                raw["refs"] = {}
            if not isinstance(raw.get("aliases"), dict):
                raw["aliases"] = {}
            raw["repo_root"] = str(self.root)
            return raw

    def _save_registry(self, state: dict[str, Any]) -> None:
        with _LOCK:
            state["updated_at_iso"] = _iso_utc()
            state["repo_root"] = str(self.root)
            tmp = self.registry_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            tmp.replace(self.registry_path)

    @staticmethod
    def _slug_ref(text: str) -> str:
        slug = re.sub(r"[^a-z0-9]+", "-", str(text or "").lower()).strip("-")
        return slug[:96] or "artifact"

    def list_registry(self) -> dict[str, Any]:
        reg = self._load_registry()
        refs = [deepcopy(v) for v in reg.get("refs", {}).values() if isinstance(v, dict)]
        refs.sort(key=lambda r: float(r.get("created_at") or 0), reverse=True)
        return {
            "ok": True,
            "repo_root": str(self.root),
            "updated_at_iso": reg.get("updated_at_iso"),
            "aliases": deepcopy(reg.get("aliases") or {}),
            "refs": refs,
            "playbook_refs_dir": str(self.playbook_refs_dir),
        }

    def get_registry_ref(self, ref: str) -> dict[str, Any] | None:
        reg = self._load_registry()
        key = str(ref or "").strip()
        if not key:
            return None
        aliases = reg.get("aliases") if isinstance(reg.get("aliases"), dict) else {}
        resolved = str(aliases.get(key) or key)
        row = reg.get("refs", {}).get(resolved)
        return deepcopy(row) if isinstance(row, dict) else None

    # Fields playbooks may request via <<IMAGE_NEST:ref:field>>
    HYDRATION_FIELDS = frozenset(
        {
            "source_image",
            "source_iso",
            "source_wim",
            "source_qcow2",
            "sha256",
            "image_nest_ref",
            "image_nest_id",
            "image_flavor",
            "label",
            "path",
            "playbook_vars_file",
        }
    )

    def resolve_hydration_payload(self, ref: str) -> dict[str, Any] | None:
        """Return playbook-facing payload for a registry ref or alias (for LAN hydrate)."""
        key = str(ref or "").strip()
        if not key:
            return None
        # Prefer the convenience vars JSON (aliases already mirrored here).
        vars_path = self.playbook_refs_dir / f"{key}.vars.json"
        if vars_path.is_file():
            try:
                raw = json.loads(vars_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                raw = None
            if isinstance(raw, dict) and (raw.get("source_image") or raw.get("source_iso") or raw.get("image_nest_ref")):
                out = dict(raw)
                out["playbook_vars_file"] = str(vars_path)
                out["requested_ref"] = key
                return out

        row = self.get_registry_ref(key)
        if not isinstance(row, dict):
            return None
        canonical = str(row.get("ref") or key)
        payload = {
            "image_nest_ref": canonical,
            "requested_ref": key,
            "label": row.get("label"),
            "type": row.get("type"),
            "repo_root": str(self.root),
            "source_iso": row.get("banked_iso_path") or row.get("iso_path") or row.get("path") or "",
            "source_image": row.get("wim_path")
            or row.get("banked_iso_path")
            or row.get("qcow2_path")
            or row.get("path")
            or "",
            "source_wim": row.get("wim_path") or "",
            "source_qcow2": row.get("qcow2_path") or "",
            "image_nest_id": row.get("catalog_id") or "",
            "image_flavor": row.get("flavor") or "",
            "sha256": row.get("sha256") or "",
            "path": row.get("path") or row.get("wim_path") or row.get("iso_path") or "",
            "playbook_vars_file": str(self.playbook_refs_dir / f"{canonical}.vars.json"),
            "created_at_iso": row.get("created_at_iso"),
        }
        return payload

    def resolve_hydration_value(self, ref: str, field: str = "") -> dict[str, Any]:
        """Resolve <<IMAGE_NEST:ref>> / <<IMAGE_NEST:ref:field>> for job hydrate."""
        payload = self.resolve_hydration_payload(ref)
        if not payload:
            return {
                "ok": False,
                "error": f"image nest ref not found: {ref}",
                "code": "missing_image_nest_ref",
                "ref": str(ref or ""),
            }
        field_n = str(field or "source_image").strip().lower()
        if field_n and field_n not in self.HYDRATION_FIELDS:
            return {
                "ok": False,
                "error": f"unknown image nest field: {field_n}",
                "code": "bad_image_nest_field",
                "ref": str(ref or ""),
                "field": field_n,
            }
        value = payload.get(field_n)
        if value is None or value == "":
            # Fallbacks so bare <<IMAGE_NEST:ref>> still works for ISO-only refs.
            if field_n == "source_image":
                value = (
                    payload.get("source_wim")
                    or payload.get("source_qcow2")
                    or payload.get("source_iso")
                    or payload.get("path")
                    or ""
                )
            elif field_n == "path":
                value = payload.get("source_image") or payload.get("source_iso") or ""
        if value is None or value == "":
            return {
                "ok": False,
                "error": f"image nest ref {ref!r} has empty field {field_n!r}",
                "code": "empty_image_nest_field",
                "ref": str(ref or ""),
                "field": field_n,
                "payload": payload,
            }
        return {
            "ok": True,
            "ref": str(payload.get("image_nest_ref") or ref),
            "requested_ref": str(ref or ""),
            "field": field_n,
            "value": str(value),
            "payload": payload,
        }

    def _register_ref(
        self,
        *,
        ref: str,
        row: dict[str, Any],
        aliases: dict[str, str] | None = None,
    ) -> None:
        reg = self._load_registry()
        refs = reg.setdefault("refs", {})
        refs[str(ref)] = row
        if aliases:
            al = reg.setdefault("aliases", {})
            for alias, target in aliases.items():
                al[str(alias)] = str(target)
        self._save_registry(reg)
        self._write_playbook_ref_files(reg)

    def _write_playbook_ref_files(self, reg: dict[str, Any] | None = None) -> None:
        reg = reg or self._load_registry()
        refs = reg.get("refs") if isinstance(reg.get("refs"), dict) else {}
        index = {
            "ok": True,
            "updated_at_iso": reg.get("updated_at_iso"),
            "repo_root": str(self.root),
            "aliases": reg.get("aliases") or {},
            "refs": {
                k: {
                    "type": v.get("type"),
                    "deploy_target": v.get("deploy_target")
                    or ("bare_metal" if v.get("type") == "iso" else "hypervisor"),
                    "label": v.get("label"),
                    "path": v.get("path"),
                    "wim_path": v.get("wim_path"),
                    "qcow2_path": v.get("qcow2_path"),
                    "iso_path": v.get("iso_path"),
                    "flavor": v.get("flavor"),
                    "created_at_iso": v.get("created_at_iso"),
                }
                for k, v in refs.items()
                if isinstance(v, dict)
            },
        }
        (self.playbook_refs_dir / "registry-index.json").write_text(
            json.dumps(index, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        for ref, row in refs.items():
            if not isinstance(row, dict):
                continue
            payload = {
                "image_nest_ref": ref,
                "label": row.get("label"),
                "type": row.get("type"),
                "deploy_target": row.get("deploy_target")
                or ("bare_metal" if row.get("type") == "iso" else "hypervisor"),
                "repo_root": str(self.root),
                # Ansible / ZTP extra-vars (controller-local paths)
                "source_iso": row.get("banked_iso_path") or row.get("iso_path") or row.get("path"),
                "source_image": row.get("wim_path")
                or row.get("banked_iso_path")
                or row.get("qcow2_path")
                or row.get("path"),
                "source_wim": row.get("wim_path") or "",
                "source_qcow2": row.get("qcow2_path") or "",
                # OpenTofu hand-off vars (apply runs on Hayabusa — not on controller)
                "target_vm_name": "",
                "image_nest_id": row.get("catalog_id"),
                "image_flavor": row.get("flavor") or "",
                "sha256": row.get("sha256") or "",
                "created_at_iso": row.get("created_at_iso"),
                "usage": {
                    "ztp_bare_metal": "Mount source_iso for PXE/USB imaging or pass as install media",
                    "hypervisor_vm": "Use source_image (WIM/qcow2) when creating a VM",
                    "ansible_extra_vars": f"@{self.playbook_refs_dir / (ref + '.vars.json')}",
                    "opentofu_tfvars": "Hydrate <<IMAGE_NEST:ref>> on LAN approve; apply on Hayabusa",
                    "hydrate_placeholder": f"<<IMAGE_NEST:{ref}>>",
                },
            }
            out = self.playbook_refs_dir / f"{ref}.vars.json"
            out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        # Convenience aliases for playbooks
        aliases = reg.get("aliases") if isinstance(reg.get("aliases"), dict) else {}
        for alias, target in aliases.items():
            src = self.playbook_refs_dir / f"{target}.vars.json"
            dst = self.playbook_refs_dir / f"{alias}.vars.json"
            if src.is_file():
                try:
                    shutil.copy2(src, dst)
                except OSError:
                    pass

    def _ensure_profiles(self) -> None:
        stripped = self.profiles / "stripped_unattend.xml"
        full = self.profiles / "full_unattend.xml"
        if not stripped.is_file():
            stripped.write_text(
                """<?xml version="1.0" encoding="utf-8"?>
<!-- Image Nest — strip profile (placeholder). Expand with Autounattend / Answer File as needed. -->
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
      publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>*</ComputerName>
    </component>
  </settings>
</unattend>
""",
                encoding="utf-8",
            )
        if not full.is_file():
            full.write_text(
                """<?xml version="1.0" encoding="utf-8"?>
<!-- Image Nest — full deploy profile (placeholder). -->
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
      publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>*</ComputerName>
    </component>
  </settings>
</unattend>
""",
                encoding="utf-8",
            )

    def _strip_catalog_path(self) -> Path:
        return self.profiles / STRIP_CATALOG_FILENAME

    def _default_strip_catalog(self) -> dict[str, Any]:
        return {
            "version": 1,
            "description": (
                "Offline strip targets inside install.wim. Edit this file to add/remove catalog entries."
            ),
            "options": [
                {
                    "id": "xbox-app",
                    "label": "Xbox App",
                    "category": "Xbox",
                    "description": "Main Xbox companion application",
                    "wim_path": r"\Program Files\WindowsApps\Microsoft.XboxApp_*",
                    "default_enabled": True,
                },
                {
                    "id": "teams",
                    "label": "Microsoft Teams",
                    "category": "Productivity",
                    "description": "Teams consumer / chat client",
                    "wim_path": r"\Program Files\WindowsApps\MicrosoftTeams_*",
                    "default_enabled": True,
                },
            ],
        }

    def _ensure_strip_catalog(self) -> None:
        path = self._strip_catalog_path()
        bundled = Path(__file__).resolve().parent / "profiles" / STRIP_CATALOG_FILENAME
        if bundled.is_file():
            should_copy = not path.is_file()
            if path.is_file():
                try:
                    cur = json.loads(path.read_text(encoding="utf-8"))
                    bun = json.loads(bundled.read_text(encoding="utf-8"))
                    should_copy = int(bun.get("version") or 0) > int(cur.get("version") or 0)
                except (OSError, json.JSONDecodeError, TypeError, ValueError):
                    should_copy = True
            if should_copy:
                shutil.copy2(bundled, path)
                return
        if not path.is_file():
            path.write_text(
                json.dumps(self._default_strip_catalog(), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

    def _load_strip_catalog(self) -> dict[str, Any]:
        self._ensure_strip_catalog()
        try:
            raw = json.loads(self._strip_catalog_path().read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = self._default_strip_catalog()
        if not isinstance(raw, dict):
            raw = self._default_strip_catalog()
        options = raw.get("options")
        if not isinstance(options, list):
            options = []
        cleaned: list[dict[str, Any]] = []
        seen: set[str] = set()
        for row in options:
            if not isinstance(row, dict):
                continue
            opt_id = re.sub(r"[^a-z0-9._-]+", "-", str(row.get("id") or "").strip().lower()).strip("-")
            wim_path = str(row.get("wim_path") or "").strip()
            if not opt_id or not wim_path or opt_id in seen:
                continue
            seen.add(opt_id)
            cleaned.append(
                {
                    "id": opt_id,
                    "label": str(row.get("label") or opt_id)[:120],
                    "category": str(row.get("category") or "Other")[:80],
                    "description": str(row.get("description") or "")[:300],
                    "wim_path": wim_path,
                    "default_enabled": bool(row.get("default_enabled", True)),
                    "applies_to": (
                        [str(x).strip().lower() for x in (row.get("applies_to") or []) if str(x).strip()]
                        or ["client", "server"]
                    ),
                }
            )
        presets: list[dict[str, Any]] = []
        for row in raw.get("presets") or []:
            if not isinstance(row, dict):
                continue
            pid = re.sub(r"[^a-z0-9._-]+", "-", str(row.get("id") or "").strip().lower()).strip("-")
            if not pid:
                continue
            presets.append(
                {
                    "id": pid,
                    "label": str(row.get("label") or pid)[:80],
                    "description": str(row.get("description") or "")[:200],
                    "use_defaults": bool(row.get("use_defaults")),
                    "option_ids": [str(x) for x in (row.get("option_ids") or []) if str(x).strip()],
                    "categories": [str(x) for x in (row.get("categories") or []) if str(x).strip()],
                }
            )
        category_order = [str(x) for x in (raw.get("category_order") or []) if str(x).strip()]
        return {
            "version": int(raw.get("version") or 1),
            "description": str(raw.get("description") or ""),
            "catalog_file": str(self._strip_catalog_path()),
            "category_order": category_order,
            "presets": presets,
            "options": cleaned,
        }

    def resolve_strip_preset(self, preset_id: str) -> list[str]:
        catalog = self._load_strip_catalog()
        options = catalog.get("options") or []
        by_id = {str(o["id"]): o for o in options if isinstance(o, dict) and o.get("id")}
        pid = re.sub(r"[^a-z0-9._-]+", "-", str(preset_id or "").strip().lower()).strip("-")
        for preset in catalog.get("presets") or []:
            if not isinstance(preset, dict) or str(preset.get("id")) != pid:
                continue
            if preset.get("use_defaults"):
                return [str(o["id"]) for o in options if o.get("default_enabled")]
            option_ids = list(preset.get("option_ids") or [])
            if option_ids == ["*"]:
                return list(by_id.keys())
            if option_ids:
                return [str(x) for x in option_ids if str(x) in by_id]
            categories = {str(c) for c in (preset.get("categories") or [])}
            if categories:
                return [str(o["id"]) for o in options if str(o.get("category") or "") in categories]
            return []
        return []

    def list_strip_options(self, os_family: str = "") -> dict[str, Any]:
        family = str(os_family or "").strip().lower()
        if family in {"winserver", "windows_server", "server"}:
            family = "server"
        elif family in {"win11", "win10", "windows_client", "client"}:
            family = "client"
        elif family in {"linux", "ubuntu", "debian", "rocky", "rhel", "alma", "centos", "fedora"}:
            return self._list_linux_strip_options(distro=family if family != "linux" else "")
        catalog = self._load_strip_catalog()
        options = list(catalog.get("options") or [])
        if family in {"client", "server"}:
            options = [
                o
                for o in options
                if isinstance(o, dict)
                and (
                    not o.get("applies_to")
                    or family in [str(x).strip().lower() for x in (o.get("applies_to") or [])]
                )
            ]
        presets = list(catalog.get("presets") or [])
        if family in {"client", "server"}:
            filtered: list[dict[str, Any]] = []
            for p in presets:
                if not isinstance(p, dict):
                    continue
                applies = p.get("applies_to")
                if isinstance(applies, list) and applies and family not in [
                    str(x).strip().lower() for x in applies
                ]:
                    continue
                filtered.append(p)
            presets = filtered
        default_ids = [
            str(o["id"]) for o in options if isinstance(o, dict) and o.get("default_enabled")
        ]
        return {
            "ok": True,
            "catalog_file": catalog.get("catalog_file"),
            "description": catalog.get("description"),
            "version": catalog.get("version"),
            "os_family": family or "any",
            "platform": "windows",
            "category_order": catalog.get("category_order") or [],
            "presets": presets,
            "default_option_ids": default_ids,
            "options": options,
        }

    def _linux_strip_catalog_path(self) -> Path:
        return self.profiles / LINUX_STRIP_CATALOG_FILENAME

    def _ensure_linux_strip_catalog(self) -> None:
        path = self._linux_strip_catalog_path()
        bundled = Path(__file__).resolve().parent / "profiles" / LINUX_STRIP_CATALOG_FILENAME
        if bundled.is_file():
            should_copy = not path.is_file()
            if path.is_file():
                try:
                    cur = json.loads(path.read_text(encoding="utf-8"))
                    bun = json.loads(bundled.read_text(encoding="utf-8"))
                    should_copy = int(bun.get("version") or 0) > int(cur.get("version") or 0)
                except (OSError, json.JSONDecodeError, TypeError, ValueError):
                    should_copy = True
            if should_copy:
                shutil.copy2(bundled, path)
                return
        if not path.is_file():
            path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "description": "Linux strip globs",
                        "presets": [],
                        "options": [],
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

    def _load_linux_strip_catalog(self) -> dict[str, Any]:
        self._ensure_linux_strip_catalog()
        try:
            raw = json.loads(self._linux_strip_catalog_path().read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = {"version": 1, "options": [], "presets": []}
        if not isinstance(raw, dict):
            raw = {"version": 1, "options": [], "presets": []}
        options = []
        seen: set[str] = set()
        for row in raw.get("options") or []:
            if not isinstance(row, dict):
                continue
            opt_id = re.sub(r"[^a-z0-9._-]+", "-", str(row.get("id") or "").strip().lower()).strip("-")
            glob_pat = str(row.get("package_glob") or row.get("wim_path") or "").strip()
            if not opt_id or not glob_pat or opt_id in seen:
                continue
            seen.add(opt_id)
            options.append(
                {
                    "id": opt_id,
                    "label": str(row.get("label") or opt_id)[:120],
                    "category": str(row.get("category") or "Other")[:80],
                    "description": str(row.get("description") or "")[:300],
                    "package_glob": glob_pat,
                    "default_enabled": bool(row.get("default_enabled", True)),
                    "applies_to": ["linux"],
                }
            )
        raw["options"] = options
        raw["catalog_file"] = str(self._linux_strip_catalog_path())
        return raw

    def _list_linux_strip_options(self, distro: str = "") -> dict[str, Any]:
        catalog = self._load_linux_strip_catalog()
        options = catalog.get("options") or []
        default_ids = [str(o["id"]) for o in options if o.get("default_enabled")]
        return {
            "ok": True,
            "catalog_file": catalog.get("catalog_file"),
            "description": catalog.get("description"),
            "version": catalog.get("version"),
            "os_family": "linux",
            "platform": "linux",
            "distro": distro or "any",
            "category_order": catalog.get("category_order") or [],
            "presets": catalog.get("presets") or [],
            "default_option_ids": default_ids,
            "options": options,
        }

    def resolve_strip_selection(
        self,
        option_ids: list[str] | None,
        *,
        flavor: str,
        os_family: str = "",
    ) -> dict[str, Any]:
        if str(flavor or "").strip().lower() not in {"strip", "stripped", "strip_and_deploy"}:
            return {
                "ok": True,
                "option_ids": [],
                "paths": [],
                "labels": [],
                "options": [],
                "package_globs": [],
            }
        family = str(os_family or "").strip().lower()
        if family in {"linux", "ubuntu", "debian", "rocky", "rhel", "alma", "centos", "fedora"}:
            catalog = self._load_linux_strip_catalog()
            by_id = {
                str(o["id"]): o
                for o in catalog.get("options") or []
                if isinstance(o, dict) and o.get("id")
            }
            if option_ids is None:
                chosen = [o for o in by_id.values() if o.get("default_enabled")]
            else:
                chosen = []
                for raw_id in option_ids:
                    opt_id = re.sub(r"[^a-z0-9._-]+", "-", str(raw_id or "").strip().lower()).strip("-")
                    if opt_id == "*":
                        chosen = list(by_id.values())
                        break
                    if opt_id in by_id:
                        chosen.append(by_id[opt_id])
            return {
                "ok": True,
                "option_ids": [str(o["id"]) for o in chosen],
                "paths": [],
                "package_globs": [str(o.get("package_glob") or "") for o in chosen if o.get("package_glob")],
                "labels": [str(o.get("label") or o["id"]) for o in chosen],
                "options": chosen,
                "os_family": "linux",
                "platform": "linux",
            }
        if family in {"winserver", "windows_server", "server"}:
            family = "server"
        elif family in {"win11", "win10", "windows_client", "client"}:
            family = "client"
        catalog = self._load_strip_catalog()
        by_id = {
            str(o["id"]): o
            for o in catalog.get("options") or []
            if isinstance(o, dict) and o.get("id")
        }
        if option_ids is None:
            chosen = []
            for o in by_id.values():
                if not o.get("default_enabled"):
                    continue
                applies = o.get("applies_to") or ["client", "server"]
                if family and family not in [str(x).strip().lower() for x in applies]:
                    continue
                chosen.append(o)
        else:
            chosen = []
            for raw_id in option_ids:
                opt_id = re.sub(r"[^a-z0-9._-]+", "-", str(raw_id or "").strip().lower()).strip("-")
                if opt_id in by_id:
                    chosen.append(by_id[opt_id])
        unknown = [
            re.sub(r"[^a-z0-9._-]+", "-", str(raw_id or "").strip().lower()).strip("-")
            for raw_id in (option_ids or [])
            if re.sub(r"[^a-z0-9._-]+", "-", str(raw_id or "").strip().lower()).strip("-") not in by_id
        ]
        if unknown:
            return {
                "ok": False,
                "error": f"unknown strip option id(s): {', '.join(unknown[:8])}",
                "code": "bad_strip_option",
            }
        return {
            "ok": True,
            "option_ids": [str(o["id"]) for o in chosen],
            "paths": [str(o["wim_path"]) for o in chosen],
            "package_globs": [],
            "labels": [str(o.get("label") or o["id"]) for o in chosen],
            "options": chosen,
            "os_family": family or "",
            "platform": "windows",
        }

    def _load(self) -> dict[str, Any]:
        with _LOCK:
            try:
                raw = json.loads(self.catalog_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                raw = {"version": 1, "isos": {}, "images": {}, "jobs": {}}
            if not isinstance(raw, dict):
                raw = {"version": 1, "isos": {}, "images": {}, "jobs": {}}
            for k in ("isos", "images", "jobs"):
                if not isinstance(raw.get(k), dict):
                    raw[k] = {}
            return raw

    def _save(self, state: dict[str, Any]) -> None:
        with _LOCK:
            tmp = self.catalog_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            tmp.replace(self.catalog_path)

    def disk_status(self) -> dict[str, Any]:
        usage = shutil.disk_usage(self.root)
        return {
            "ok": True,
            "total_bytes": int(usage.total),
            "used_bytes": int(usage.used),
            "free_bytes": int(usage.free),
            "max_iso_bytes": MAX_ISO_BYTES,
            "min_free_after_upload_bytes": MIN_FREE_AFTER_UPLOAD,
            "upload_stream_headroom_bytes": UPLOAD_STREAM_HEADROOM,
            "can_accept_upload": usage.free > (MIN_FREE_AFTER_UPLOAD + UPLOAD_STREAM_HEADROOM),
            "tools": self.tool_status(),
        }

    def tool_status(self) -> dict[str, Any]:
        def which(name: str) -> str:
            return shutil.which(name) or ""

        tools = {
            "wimlib_imagex": which("wimlib-imagex"),
            "qemu_img": which("qemu-img"),
            "virt_install": which("virt-install"),
            "seven_z": which("7z") or which("7zz") or which("bsdtar"),
            "mount": which("mount"),
            "unsquashfs": which("unsquashfs"),
            "mksquashfs": which("mksquashfs"),
            "xorriso": which("xorriso"),
            # OpenTofu is intentionally NOT a controller dependency. Hayabusa runs tofu.
            "opentofu": "",
        }
        if tools["wimlib_imagex"] and tools["seven_z"]:
            bake_mode = "offline_wim"
        elif tools["qemu_img"] and tools["virt_install"]:
            bake_mode = "kvm"
        elif tools["qemu_img"]:
            bake_mode = "disk_stub"
        else:
            bake_mode = "catalog_only"
        tools["bake_mode"] = bake_mode
        tools["linux_strip_ready"] = bool(
            tools["seven_z"] and tools["unsquashfs"] and tools["mksquashfs"] and tools["xorriso"]
        )
        tools["rpm"] = which("rpm")
        return tools

    def _iso_listing_paths(self, iso_path: Path) -> list[str]:
        seven = str(self.tool_status().get("seven_z") or "")
        if not seven or not iso_path.is_file():
            return []
        return _linux.iso_listing_paths(iso_path, seven_z=seven)

    def _probe_iso_row(self, row: dict[str, Any]) -> dict[str, Any]:
        """Refine platform/distro from ISO contents (7z listing) and assess capabilities."""
        path = Path(str(row.get("path") or ""))
        tools = self.tool_status()
        free = int(shutil.disk_usage(self.root).free)
        listing = self._iso_listing_paths(path) if path.is_file() else []
        listing_blob = "\n".join(listing[:8000])
        meta = row.get("source_meta") if isinstance(row.get("source_meta"), dict) else {}
        detected = detect_os_media(
            filename=str(row.get("original_filename") or row.get("filename") or ""),
            label=str(row.get("label") or ""),
            iso_listing=listing_blob,
            source_meta=meta,
        )
        reasons: list[str] = []
        low = listing_blob.lower()
        if "sources/install.wim" in low or any(n.lower().endswith("sources/install.wim") for n in listing):
            reasons.append("ISO contains sources/install.wim")
        elif "sources/install.esd" in low:
            reasons.append("ISO contains sources/install.esd")
        if any(
            n.endswith(m)
            for n in listing
            for m in _linux.LINUX_SQUASHFS_MEMBERS
        ):
            reasons.append("ISO contains live rootfs image (squashfs)")
        if any(n.endswith(m) for n in listing for m in _linux.LINUX_MANIFEST_MEMBERS[:3]):
            reasons.append("ISO contains filesystem.manifest")

        platform = str(detected.get("platform") or "windows")
        capabilities: dict[str, Any]
        if platform == "linux":
            inv = _linux.inventory_linux_iso(path, seven_z=str(tools.get("seven_z") or "")) if path.is_file() else {}
            capabilities = _linux.linux_iso_capabilities(inv, tools=tools, free_bytes=free)
        else:
            family = str(detected.get("os_family") or "client")
            has_wim = "sources/install.wim" in low or "sources/install.esd" in low
            blockers: list[str] = []
            if not has_wim:
                blockers.append("no install.wim/esd found in ISO listing")
            if not tools.get("wimlib_imagex"):
                blockers.append("wimlib-imagex missing on controller")
            if not tools.get("seven_z"):
                blockers.append("7z missing on controller")
            if free < 9 * 1024**3:
                blockers.append(f"low disk ({_fmt_disk_bytes(free)} free; need ≥9GB for WIM work)")
            capabilities = {
                "inventory": has_wim and bool(tools.get("wimlib_imagex") and tools.get("seven_z")),
                "strip_supported": has_wim and bool(tools.get("wimlib_imagex")),
                "strip_ready": has_wim
                and bool(tools.get("wimlib_imagex") and tools.get("seven_z") and tools.get("xorriso"))
                and free >= 9 * 1024**3,
                "package_manager": "appx",
                "os_family": family,
                "blockers": blockers,
            }
            if family == "server":
                reasons.append("classified as Windows Server")
            else:
                reasons.append("classified as Windows client")

        return {
            "detected": detected,
            "listing_count": len(listing),
            "detection_reasons": reasons,
            "capabilities": capabilities,
            "listing_sample": listing[:40],
        }

    def _apply_iso_probe(self, iso_id: str, *, warm_inventory: bool = False) -> None:
        state = self._load()
        row = state["isos"].get(iso_id)
        if not isinstance(row, dict):
            return
        path = Path(str(row.get("path") or ""))
        if not path.is_file():
            return
        try:
            probe = self._probe_iso_row(row)
        except Exception as exc:  # noqa: BLE001
            row["probe_error"] = str(exc)[:300]
            state["isos"][iso_id] = row
            self._save(state)
            return
        detected = probe.get("detected") if isinstance(probe.get("detected"), dict) else {}
        row["platform"] = detected.get("platform") or row.get("platform")
        row["os_family"] = detected.get("os_family") or row.get("os_family")
        row["distro"] = detected.get("distro") or row.get("distro")
        row["linux_kind"] = detected.get("linux_kind") or row.get("linux_kind")
        row["name_slug"] = detected.get("name_slug") or row.get("name_slug")
        row["kind"] = "linux_iso" if row.get("platform") == "linux" else "windows_iso"
        row["iso_listing_count"] = probe.get("listing_count")
        row["detection_reasons"] = list(probe.get("detection_reasons") or [])
        row["capabilities"] = probe.get("capabilities") if isinstance(probe.get("capabilities"), dict) else {}
        row.pop("probe_error", None)
        meta = row.get("source_meta") if isinstance(row.get("source_meta"), dict) else {}
        meta = dict(meta)
        meta["platform"] = row.get("platform")
        meta["os_family"] = row.get("os_family")
        meta["distro"] = row.get("distro")
        meta["product"] = detected.get("product")
        row["source_meta"] = meta
        state["isos"][iso_id] = row
        self._save(state)
        if warm_inventory:
            try:
                self.inventory_iso_packages(iso_id, refresh=True)
            except Exception:
                pass

    def list_bank(self) -> list[dict[str, Any]]:
        state = self._load()
        rows = [deepcopy(v) for v in state["images"].values() if isinstance(v, dict)]
        rows.sort(key=lambda r: float(r.get("created_at") or 0), reverse=True)
        return [self._enrich_bank_row(r) for r in rows]

    def _enrich_bank_row(self, row: dict[str, Any]) -> dict[str, Any]:
        out = dict(row)
        target = self._normalize_deploy_target(out.get("deploy_target") or out.get("target") or "")
        if not target:
            # Infer for older bank entries
            if str(out.get("flavor") or "").lower() in {"iso", "bare_metal", "bare-metal"}:
                target = "bare_metal"
            elif out.get("wim_path") or out.get("qcow2_path") or out.get("banked_iso_path") or str(
                out.get("flavor") or ""
            ) in {
                "stripped",
                "full",
            }:
                target = "hypervisor"
            else:
                target = "hypervisor"
        out["deploy_target"] = target
        meta = self._deploy_target_meta(target)
        out["deploy_target_label"] = meta.get("label") or target
        out["export_format"] = meta.get("export_format") or out.get("export_format") or ""
        out["disk_format"] = out.get("disk_format") or meta.get("disk_format") or ""
        family = str(out.get("os_family") or "").strip().lower()
        platform = str(out.get("platform") or "").strip().lower()
        detected: dict[str, Any] = {}
        if family not in {"client", "server", "linux"} or not platform:
            detected = detect_os_media(
                filename=str(out.get("iso_filename") or out.get("name") or ""),
                label=str(out.get("name") or ""),
                source_meta=out.get("source_meta") if isinstance(out.get("source_meta"), dict) else None,
            )
            family = str(detected.get("os_family") or family or "client")
            platform = str(detected.get("platform") or platform or "windows")
            out["os_family"] = family
            out["platform"] = platform
            out["os_product"] = detected.get("product")
            out["distro"] = detected.get("distro") or out.get("distro")
        out["platform"] = platform or ("linux" if family == "linux" else "windows")
        if family == "linux":
            out["os_family_label"] = str(out.get("label") or f"Linux ({out.get('distro') or 'linux'})")
            slug = str(out.get("distro") or out.get("name_slug") or "linux")
        elif family == "server":
            out["os_family_label"] = "Windows Server"
            slug = "winserver"
        else:
            out["os_family_label"] = "Windows client"
            slug = str(out.get("name_slug") or detected.get("name_slug") or "win11")
        flavor = str(out.get("flavor") or "").strip().lower()
        if flavor in {"iso", "bare_metal", "bare-metal"}:
            flavor = "full"
        meta = self._deploy_target_meta(target)
        out["applies_to"] = f"{meta.get('applies')} ({out['os_family_label']})"
        # Artifact type by deploy target + platform.
        if target == "bare_metal":
            out["artifact_type"] = "iso"
            out["artifact_label"] = "Bootable ISO"
            out["hydrate_field"] = "source_iso"
        elif target == "bootable_disk":
            out["artifact_type"] = "qcow2"
            out["artifact_label"] = "Bootable qcow2" if str(out.get("status") or "").startswith("ready") and "stub" not in str(out.get("status") or "") else "qcow2 disk"
            out["hydrate_field"] = "source_image"
        elif target == "hyperv":
            out["artifact_type"] = "vhdx"
            out["artifact_label"] = "Hyper-V VHDX"
            out["hydrate_field"] = "source_image"
        elif target == "vmware":
            out["artifact_type"] = "vmdk"
            out["artifact_label"] = "VMware VMDK"
            out["hydrate_field"] = "source_image"
        elif platform == "linux":
            out["artifact_type"] = "iso"
            out["artifact_label"] = "Bootable ISO"
            out["hydrate_field"] = "source_iso"
        else:
            out["artifact_type"] = "wim"
            out["artifact_label"] = "install.wim"
            out["hydrate_field"] = "source_image"
        # Prefer concrete disk paths when present
        if out.get("vhdx_path"):
            out["artifact_type"] = "vhdx"
            out["artifact_label"] = "Hyper-V VHDX"
            out["hydrate_field"] = "source_image"
        elif out.get("vmdk_path"):
            out["artifact_type"] = "vmdk"
            out["artifact_label"] = "VMware VMDK"
            out["hydrate_field"] = "source_image"
        elif target in {"bootable_disk", "hyperv", "vmware"} and out.get("qcow2_path") and platform == "linux" and out.get("banked_iso_path"):
            out["artifact_type"] = "iso+disk"
            out["artifact_label"] = "ISO + disk stub"
            out["hydrate_field"] = "source_iso"
        ref = str(out.get("registry_ref") or "")
        if not ref:
            if target == "bare_metal":
                ref = (
                    f"latest-{slug}-bare-metal-stripped"
                    if flavor == "stripped"
                    else f"latest-{slug}-bare-metal"
                )
            elif flavor == "stripped":
                ref = f"latest-{slug}-stripped"
            elif flavor == "full":
                ref = f"latest-{slug}-full"
        out["hydrate_placeholder"] = f"<<IMAGE_NEST:{ref}>>" if ref else ""
        return out

    @staticmethod
    def _normalize_deploy_target(raw: str) -> str:
        t = str(raw or "").strip().lower().replace("-", "_").replace(" ", "_")
        if t in {"bare_metal", "baremetal", "ztp", "pxe", "usb", "iso"}:
            return "bare_metal"
        if t in {"bootable_disk", "bootable", "kvm_disk", "qcow2", "qcow2_bootable"}:
            return "bootable_disk"
        if t in {"hyperv", "hyper_v", "vhdx", "vhd"}:
            return "hyperv"
        if t in {"vmware", "vmdk", "esxi"}:
            return "vmware"
        if t in {"hypervisor", "vm", "virt", "kvm", "qemu", "openstack", "proxmox", "wim"}:
            return "hypervisor"
        return ""

    @classmethod
    def _deploy_target_meta(cls, target: str) -> dict[str, str]:
        """Labels / export format for Nest deploy targets (Windows + Linux)."""
        t = cls._normalize_deploy_target(target) or "hypervisor"
        table = {
            "bare_metal": {
                "label": "Bare metal",
                "short": "ISO",
                "export_format": "",
                "disk_format": "",
                "applies": "ZTP / PXE / USB install media",
            },
            "hypervisor": {
                "label": "Hypervisor media",
                "short": "WIM/ISO",
                "export_format": "",
                "disk_format": "qcow2",
                "applies": "OpenTofu / KVM / virt (WIM for Windows, ISO for Linux)",
            },
            "bootable_disk": {
                "label": "Bootable disk",
                "short": "qcow2",
                "export_format": "",
                "disk_format": "qcow2",
                "applies": "Ready guest disk for Proxmox / KVM (Windows via virt-install)",
            },
            "hyperv": {
                "label": "Hyper-V",
                "short": "VHDX",
                "export_format": "vhdx",
                "disk_format": "vhdx",
                "applies": "Hyper-V guest disk (VHDX); Linux banks ISO + empty VHDX stub",
            },
            "vmware": {
                "label": "VMware",
                "short": "VMDK",
                "export_format": "vmdk",
                "disk_format": "vmdk",
                "applies": "VMware guest disk (VMDK); Linux banks ISO + empty VMDK stub",
            },
        }
        return dict(table.get(t) or table["hypervisor"], target=t)

    def _needs_bootable_install(self, target: str) -> bool:
        t = self._normalize_deploy_target(target)
        return t in {"bootable_disk", "hyperv", "vmware"}

    def render_unattend_xml(
        self,
        *,
        hostname: str = "HAYA-NEST",
        username: str = "hayabusa",
        password: str = "Hayabusa!ChangeMe",
        flavor: str = "full",
    ) -> str:
        """Build a minimal Autounattend for virt-install floppy injection."""
        host = re.sub(r"[^A-Za-z0-9-]+", "-", str(hostname or "HAYA-NEST").strip())[:15] or "HAYA-NEST"
        user = re.sub(r"[^A-Za-z0-9._-]+", "", str(username or "hayabusa").strip())[:20] or "hayabusa"
        # Escape XML special chars in password
        pw = (
            str(password or "Hayabusa!ChangeMe")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )
        marker = "stripped" if str(flavor).lower() == "stripped" else "full"
        return f"""<?xml version="1.0" encoding="utf-8"?>
<!-- Hayabusa Image Nest Autounattend ({marker}) — set via Image Nest UI -->
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64"
      publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"
      xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64"
      publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"
      xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <UserData>
        <AcceptEula>true</AcceptEula>
        <FullName>Hayabusa</FullName>
        <Organization>Hayabusa</Organization>
      </UserData>
      <ImageInstall>
        <OSImage>
          <InstallToAvailablePartition>true</InstallToAvailablePartition>
          <WillShowUI>OnError</WillShowUI>
        </OSImage>
      </ImageInstall>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
      publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"
      xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <ComputerName>{host}</ComputerName>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
      publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"
      xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <NetworkLocation>Work</NetworkLocation>
        <ProtectYourPC>3</ProtectYourPC>
        <SkipMachineOOBE>true</SkipMachineOOBE>
        <SkipUserOOBE>true</SkipUserOOBE>
      </OOBE>
      <UserAccounts>
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Name>{user}</Name>
            <Group>Administrators</Group>
            <Password><Value>{pw}</Value><PlainText>true</PlainText></Password>
            <DisplayName>Hayabusa</DisplayName>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
      <AutoLogon>
        <Enabled>true</Enabled>
        <Username>{user}</Username>
        <Password><Value>{pw}</Value><PlainText>true</PlainText></Password>
        <LogonCount>1</LogonCount>
      </AutoLogon>
    </component>
  </settings>
</unattend>
"""

    def write_job_unattend(self, *, job_id: str, flavor: str, unattend: dict[str, Any] | None) -> Path:
        self._ensure_profiles()
        cfg = unattend if isinstance(unattend, dict) else {}
        xml = self.render_unattend_xml(
            hostname=str(cfg.get("hostname") or cfg.get("computer_name") or "HAYA-NEST"),
            username=str(cfg.get("username") or cfg.get("admin_user") or "hayabusa"),
            password=str(cfg.get("password") or cfg.get("admin_password") or "Hayabusa!ChangeMe"),
            flavor=flavor,
        )
        out = self.profiles / f"job-{job_id[:12]}-unattend.xml"
        out.write_text(xml, encoding="utf-8")
        # Keep flavor defaults refreshed for older virt-install path
        dest = self.profiles / ("stripped_unattend.xml" if flavor == "stripped" else "full_unattend.xml")
        dest.write_text(xml, encoding="utf-8")
        return out

    def convert_bank_disk(
        self,
        *,
        image_id: str,
        fmt: str,
        requested_by: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Convert a banked qcow2 (or other qemu disk) to vhdx/vmdk/qcow2."""
        fmt_n = str(fmt or "").strip().lower()
        if fmt_n in {"vhd", "hyperv"}:
            fmt_n = "vhdx"
        if fmt_n in {"esxi", "vmware"}:
            fmt_n = "vmdk"
        if fmt_n not in {"vhdx", "vmdk", "qcow2"}:
            return {"ok": False, "error": "format must be vhdx, vmdk, or qcow2", "code": "bad_format"}
        image = self.get_image(image_id)
        if not image:
            return {"ok": False, "error": "image not found", "code": "not_found"}
        tools = self.tool_status()
        qemu = str(tools.get("qemu_img") or "")
        if not qemu:
            return {"ok": False, "error": "qemu-img missing on controller", "code": "tool_missing"}
        src = Path(str(image.get("qcow2_path") or image.get("disk_path") or ""))
        if not src.is_file():
            # Prefer platform disk if already converted
            for key in ("vhdx_path", "vmdk_path", "banked_iso_path"):
                p = Path(str(image.get(key) or ""))
                if p.is_file() and p.suffix.lower() in {".qcow2", ".vhdx", ".vmdk", ".raw"}:
                    src = p
                    break
        if not src.is_file():
            return {
                "ok": False,
                "error": "No convertible disk on this bank row (need qcow2/vhdx/vmdk)",
                "code": "no_disk",
            }
        stamp = _ts_slug()
        name = f"{image.get('name') or image_id}-{fmt_n}-{stamp}"
        dest = self.image_bank / f"{name}.{fmt_n}"
        proc = subprocess.run(
            [qemu, "convert", "-O", fmt_n, str(src), str(dest)],
            capture_output=True,
            text=True,
            timeout=3600,
        )
        if proc.returncode != 0 or not dest.is_file():
            return {
                "ok": False,
                "error": f"qemu-img convert failed: {(proc.stderr or proc.stdout or '')[:400]}",
                "code": "convert_failed",
            }
        new_id = uuid.uuid4().hex[:12]
        platform = str(image.get("platform") or "windows")
        family = str(image.get("os_family") or "client")
        target = "hyperv" if fmt_n == "vhdx" else ("vmware" if fmt_n == "vmdk" else "bootable_disk")
        row = {
            "id": new_id,
            "name": name,
            "flavor": image.get("flavor") or "full",
            "deploy_target": target,
            "platform": platform,
            "os_family": family,
            "distro": image.get("distro") or "",
            "os_product": image.get("os_product"),
            "status": f"ready_{fmt_n}",
            "created_at": _now(),
            "created_at_iso": _iso_utc(),
            "iso_id": image.get("iso_id"),
            "iso_filename": image.get("iso_filename"),
            "qcow2_path": str(dest) if fmt_n == "qcow2" else str(image.get("qcow2_path") or ""),
            "vhdx_path": str(dest) if fmt_n == "vhdx" else "",
            "vmdk_path": str(dest) if fmt_n == "vmdk" else "",
            "disk_path": str(dest),
            "disk_format": fmt_n,
            "qcow2_bytes": dest.stat().st_size if fmt_n == "qcow2" else int(image.get("qcow2_bytes") or 0),
            "bytes": dest.stat().st_size,
            "parent_image_id": image_id,
            "banked_iso_path": image.get("banked_iso_path") or "",
            "wim_path": image.get("wim_path") or "",
            "requested_by": requested_by if isinstance(requested_by, dict) else {},
            "core_manifest": f"Converted {src.name} → {dest.name} ({fmt_n})",
        }
        state = self._load()
        state["images"][new_id] = row
        self._save(state)
        ref = self._register_image_ref(row)
        row["registry_ref"] = ref
        state = self._load()
        state["images"][new_id] = row
        self._save(state)
        return {"ok": True, "image": self._enrich_bank_row(row), "path": str(dest), "format": fmt_n}

    def publish_bare_metal(
        self,
        *,
        iso_id: str,
        requested_by: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Bank an uploaded ISO for bare-metal / ZTP use (no WIM bake)."""
        iso = self.get_iso(iso_id)
        if not iso:
            return {"ok": False, "error": "ISO not found — upload first", "code": "iso_missing"}
        iso_path = Path(str(iso.get("path") or ""))
        if not iso_path.is_file():
            return {"ok": False, "error": "ISO file missing on disk", "code": "iso_missing"}

        image_id = uuid.uuid4().hex[:12]
        stamp = _ts_slug()
        detected = detect_os_media(
            filename=str(iso.get("original_filename") or iso.get("filename") or ""),
            label=str(iso.get("label") or ""),
            source_meta=iso.get("source_meta") if isinstance(iso.get("source_meta"), dict) else None,
        )
        platform = str(detected.get("platform") or "windows")
        family = str(detected.get("os_family") or "client")
        slug = str(detected.get("name_slug") or ("linux" if platform == "linux" else "win11"))
        image_name = f"{slug}-bare-metal-{stamp}"
        deploy_manifest = f"{image_name}-deployed.txt"
        latest_bm = f"latest-{slug}-bare-metal"
        latest_iso = f"latest-{slug}-iso"
        image_row = {
            "id": image_id,
            "name": image_name,
            "flavor": "iso",
            "deploy_target": "bare_metal",
            "platform": platform,
            "os_family": family,
            "distro": detected.get("distro") or "",
            "os_product": detected.get("product"),
            "status": "ready_iso",
            "created_at": _now(),
            "created_at_iso": _iso_utc(),
            "iso_id": iso_id,
            "iso_filename": iso.get("original_filename") or iso.get("filename"),
            "iso_path": str(iso_path),
            "path": str(iso_path),
            "qcow2_path": "",
            "qcow2_bytes": 0,
            "wim_path": "",
            "wim_bytes": 0,
            "base_manifest": str(iso.get("base_manifest") or ""),
            "deploy_manifest": deploy_manifest,
            "core_manifest": (
                f"Bare-metal {detected.get('label')} install media — use source_iso for ZTP / PXE / USB. "
                f"Hydrate with <<IMAGE_NEST:{latest_bm}>>"
            ),
            "job_id": "",
            "error": "",
            "requested_by": requested_by if isinstance(requested_by, dict) else {},
            "sha256": iso.get("sha256") or "",
            "bytes": iso.get("bytes") or 0,
        }
        # Write a short deploy manifest
        try:
            lines = [
                "=" * 72,
                f"IMAGE PACKAGE MANIFEST: {image_name}",
                "Deploy target: bare_metal",
                f"OS family: {family} ({detected.get('product')})",
                f"Generated: {_iso_utc()}",
                f"Source ISO id: {iso_id}",
                f"ISO path: {iso_path}",
                f"SHA256: {iso.get('sha256') or '(see catalog)'}",
                "=" * 72,
                "",
                "[Applies to]",
                f"- Bare-metal {detected.get('label')} install (ZTP / PXE / USB)",
                "- Not a hypervisor VM disk image",
                "",
                "[Hydration]",
                f"- <<IMAGE_NEST:{latest_bm}>>",
                f"- <<IMAGE_NEST:{latest_iso}>>",
                f"- <<IMAGE_NEST:{latest_bm}:source_iso>>",
            ]
            (self.manifests / deploy_manifest).write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError:
            pass

        state = self._load()
        state["images"][image_id] = image_row
        # Persist family on ISO row for later builds
        iso_row = state["isos"].get(str(iso_id))
        if isinstance(iso_row, dict):
            meta = iso_row.get("source_meta") if isinstance(iso_row.get("source_meta"), dict) else {}
            meta = dict(meta)
            meta["os_family"] = family
            meta["platform"] = platform
            meta["distro"] = detected.get("distro")
            meta["product"] = detected.get("product")
            iso_row["source_meta"] = meta
            iso_row["os_family"] = family
            iso_row["platform"] = platform
            iso_row["distro"] = detected.get("distro")
            state["isos"][str(iso_id)] = iso_row
        self._save(state)

        try:
            if not iso.get("registry_ref"):
                self._register_iso_ref(iso)
            self._register_image_ref(image_row)
        except Exception as exc:  # noqa: BLE001
            image_row["registry_error"] = str(exc)[:300]
            state = self._load()
            state["images"][image_id] = image_row
            self._save(state)

        return {
            "ok": True,
            "image": self._enrich_bank_row(self.get_image(image_id) or image_row),
            "disk": self.disk_status(),
        }

    def _inventory_cache_path(self, iso_id: str) -> Path:
        return self.inventories_dir / f"{str(iso_id or '').strip()}.json"

    def _read_inventory_cache(self, iso_id: str) -> dict[str, Any] | None:
        path = self._inventory_cache_path(iso_id)
        if not path.is_file():
            return None
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return raw if isinstance(raw, dict) else None

    def _write_inventory_cache(self, iso_id: str, payload: dict[str, Any]) -> None:
        path = self._inventory_cache_path(iso_id)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        except OSError:
            pass

    def _annotate_windows_packages(
        self, packages: list[dict[str, Any]], *, os_family: str = "client"
    ) -> list[dict[str, Any]]:
        catalog = self._load_strip_catalog()
        family = str(os_family or "client").strip().lower()
        if family in {"winserver", "windows_server", "server"}:
            family = "server"
        else:
            family = "client"
        rules: list[tuple[str, str, str]] = []
        for opt in catalog.get("options") or []:
            if not isinstance(opt, dict):
                continue
            applies = [str(x).strip().lower() for x in (opt.get("applies_to") or ["client", "server"])]
            if family not in applies:
                continue
            leaf = str(opt.get("wim_path") or "").replace("\\", "/").rstrip("/").split("/")[-1]
            if not leaf:
                continue
            rules.append(
                (
                    leaf.lower(),
                    str(opt.get("category") or "Recommended"),
                    str(opt.get("label") or opt.get("id") or leaf),
                )
            )
        out: list[dict[str, Any]] = []
        for pkg in packages:
            row = dict(pkg)
            name = str(row.get("name") or row.get("id") or "")
            variants = [str(v) for v in (row.get("variants") or [])]
            matched_cat = ""
            matched_label = ""
            for leaf, cat, label in rules:
                hay = [name.lower()] + [v.lower() for v in variants]
                if any(fnmatch.fnmatch(h, leaf) or fnmatch.fnmatch(_appx_family(h).lower(), leaf) for h in hay):
                    matched_cat = cat
                    matched_label = label
                    break
            if matched_cat:
                row["recommended"] = True
                row["category"] = matched_cat
                row["catalog_label"] = matched_label
            else:
                row.setdefault("recommended", False)
                row.setdefault("category", "Other")
            out.append(row)
        # Recommended first, then alpha within category
        out.sort(
            key=lambda r: (
                0 if r.get("recommended") else 1,
                str(r.get("category") or "").lower(),
                str(r.get("name") or "").lower(),
            )
        )
        return out

    def _annotate_linux_packages(self, packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        catalog = self._load_linux_strip_catalog()
        rules: list[tuple[str, str, str]] = []
        for opt in catalog.get("options") or []:
            if not isinstance(opt, dict):
                continue
            glob = str(opt.get("package_glob") or "").strip()
            if not glob:
                continue
            rules.append(
                (
                    glob.lower(),
                    str(opt.get("category") or "Recommended"),
                    str(opt.get("label") or opt.get("id") or glob),
                )
            )
        out: list[dict[str, Any]] = []
        for pkg in packages:
            row = dict(pkg)
            name = str(row.get("name") or "")
            row["id"] = name
            row["label"] = name
            row["kind"] = "linux"
            matched_cat = ""
            matched_label = ""
            for glob, cat, label in rules:
                if name.lower() == glob or fnmatch.fnmatch(name.lower(), glob):
                    matched_cat = cat
                    matched_label = label
                    break
            if matched_cat:
                row["recommended"] = True
                row["category"] = matched_cat
                row["catalog_label"] = matched_label
            else:
                row["recommended"] = False
                row.setdefault("category", "Other")
            out.append(row)
        out.sort(
            key=lambda r: (
                0 if r.get("recommended") else 1,
                str(r.get("category") or "").lower(),
                str(r.get("name") or "").lower(),
            )
        )
        return out

    def _windows_folder_names_from_wim(
        self, wim_path: Path, *, wim_index: int = 0, os_family: str = ""
    ) -> tuple[list[str], int, str]:
        tools = self.tool_status()
        wim_bin = tools.get("wimlib_imagex") or ""
        if not wim_bin or not wim_path.is_file():
            return [], 0, "wimlib/WIM missing"
        info = subprocess.run(
            [wim_bin, "info", str(wim_path)],
            capture_output=True,
            text=True,
            timeout=180,
        )
        info_text = info.stdout or ""
        idx = int(wim_index or 0) or self._pick_wim_index(info_text, os_family=os_family)
        listing = subprocess.run(
            [wim_bin, "dir", str(wim_path), str(idx), "--path=/Program Files/WindowsApps"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if listing.returncode != 0:
            return [], idx, (listing.stderr or listing.stdout or "wim dir failed")[:300]
        return _windowsapps_package_names(listing.stdout or ""), idx, ""

    def _banked_wim_for_iso(self, iso_id: str) -> tuple[Path | None, list[str]]:
        """Find a banked WIM for this ISO and any previously removed AppX folder names."""
        state = self._load()
        removed: list[str] = []
        best: Path | None = None
        best_mtime = 0.0
        for row in state.get("images", {}).values():
            if not isinstance(row, dict):
                continue
            if str(row.get("iso_id") or "") != str(iso_id):
                continue
            for rem in row.get("strip_removed_paths") or []:
                name = Path(str(rem)).name
                if name and name not in removed:
                    removed.append(name)
            wim = Path(str(row.get("wim_path") or ""))
            if wim.is_file() and wim.stat().st_size > 500_000_000:
                mtime = wim.stat().st_mtime
                if mtime >= best_mtime:
                    best = wim
                    best_mtime = mtime
        return best, removed

    def inventory_iso_packages(
        self, iso_id: str, *, refresh: bool = False, wim_index: int = 0
    ) -> dict[str, Any]:
        """List every detected package on an uploaded ISO (Windows AppX + Linux pkgs)."""
        iso = self.get_iso(iso_id)
        if not iso:
            return {"ok": False, "error": "ISO not found", "code": "iso_missing"}
        path = Path(str(iso.get("path") or ""))
        if not path.is_file():
            return {"ok": False, "error": "ISO file missing", "code": "iso_missing"}
        detected = detect_os_media(
            filename=str(iso.get("original_filename") or iso.get("filename") or ""),
            label=str(iso.get("label") or ""),
            source_meta=iso.get("source_meta") if isinstance(iso.get("source_meta"), dict) else None,
        )
        platform = str(iso.get("platform") or detected.get("platform") or "windows")
        family = str(iso.get("os_family") or detected.get("os_family") or "client")
        if platform == "linux":
            family = "linux"

        if not refresh:
            cached = self._read_inventory_cache(iso_id)
            if cached and cached.get("ok") and cached.get("packages") is not None:
                cached = dict(cached)
                cached["cached"] = True
                return cached

        tools = self.tool_status()
        notes: list[str] = []

        if platform == "linux":
            inv = _linux.inventory_linux_iso(path, seven_z=str(tools.get("seven_z") or ""))
            notes.extend(list(inv.get("notes") or []))
            packages = self._annotate_linux_packages(list(inv.get("packages") or []))
            cap = iso.get("capabilities") if isinstance(iso.get("capabilities"), dict) else {}
            if not cap or refresh:
                cap = _linux.linux_iso_capabilities(
                    inv, tools=tools, free_bytes=int(shutil.disk_usage(self.root).free)
                )
            payload = {
                "ok": bool(inv.get("ok")),
                "platform": "linux",
                "os_family": "linux",
                "distro": detected.get("distro") or iso.get("distro") or "",
                "packages": packages,
                "package_names": [str(p.get("name") or "") for p in packages],
                "recommended_ids": [str(p.get("id") or p.get("name") or "") for p in packages if p.get("recommended")],
                "squashfs_member": inv.get("squashfs_member") or "",
                "package_manager": inv.get("package_manager") or "",
                "capabilities": cap,
                "detection_reasons": list(iso.get("detection_reasons") or []),
                "notes": notes,
                "error": inv.get("error") or "",
                "linux_strip_ready": bool(tools.get("linux_strip_ready")),
                "cached": False,
                "source": "iso",
            }
            if payload["ok"]:
                self._write_inventory_cache(iso_id, payload)
            return payload

        # Windows — prefer extract/cache WIM, else reconstruct from banked WIM + prior removes
        folder_names: list[str] = []
        source = ""
        idx_used = 0
        err = ""

        cached_wim = self.jobs_dir / f"wim-extract-{iso_id}" / "install.wim"
        if cached_wim.is_file() and cached_wim.stat().st_size > 500_000_000:
            folder_names, idx_used, err = self._windows_folder_names_from_wim(
                cached_wim, wim_index=wim_index, os_family=family
            )
            if folder_names:
                source = "cached_wim"
                notes.append(f"inventory from cached install.wim @ index {idx_used}")

        if not folder_names:
            # Temporary extract into jobs dir (needs free disk); keep WIM for later strip
            work = self.jobs_dir / f"wim-extract-{iso_id}"
            free = shutil.disk_usage(self.root).free
            if free >= 9 * 1024**3 or (work / "install.wim").is_file():
                wim_src, member = self._extract_install_wim(iso_path=path, work=work, iso_id=iso_id)
                if wim_src and wim_src.is_file():
                    # Keep WIM in the extract cache for subsequent strip builds.
                    keep = work / "install.wim"
                    if wim_src.resolve() != keep.resolve():
                        try:
                            if keep.exists():
                                keep.unlink()
                            shutil.move(str(wim_src), str(keep))
                            wim_src = keep
                        except OSError:
                            pass
                    folder_names, idx_used, err = self._windows_folder_names_from_wim(
                        wim_src, wim_index=wim_index, os_family=family
                    )
                    if folder_names:
                        source = "extracted_wim"
                        notes.append(f"inventory from extracted {member} @ index {idx_used}")
                elif member:
                    notes.append(str(member))
            else:
                notes.append(
                    f"skip WIM extract for inventory — only {_fmt_disk_bytes(free)} free (need ≥9 GB)"
                )

        if not folder_names:
            banked, removed_folders = self._banked_wim_for_iso(iso_id)
            if banked:
                folder_names, idx_used, err = self._windows_folder_names_from_wim(
                    banked, wim_index=wim_index, os_family=family
                )
                # Reconstruct packages removed by a prior strip of the same ISO
                for name in removed_folders:
                    if name not in folder_names:
                        folder_names.append(name)
                if folder_names:
                    source = "banked_wim_reconstructed" if removed_folders else "banked_wim"
                    notes.append(
                        f"inventory from banked {banked.name} @ index {idx_used}"
                        + (f" (+{len(removed_folders)} previously removed)" if removed_folders else "")
                    )

        if not folder_names:
            return {
                "ok": False,
                "platform": "windows",
                "os_family": family,
                "packages": [],
                "package_names": [],
                "recommended_ids": [],
                "notes": notes,
                "error": err
                or "Could not inventory WindowsApps — free ≥9 GB to extract install.wim, or bank a WIM first",
                "code": "inventory_unavailable",
                "cached": False,
            }

        packages = self._annotate_windows_packages(
            _group_appx_packages(folder_names), os_family=family
        )
        cap = iso.get("capabilities") if isinstance(iso.get("capabilities"), dict) else {}
        if not cap:
            cap = self._probe_iso_row(iso).get("capabilities") if isinstance(iso, dict) else {}
            if not isinstance(cap, dict):
                cap = {}
        payload = {
            "ok": True,
            "platform": "windows",
            "os_family": family,
            "distro": detected.get("distro") or detected.get("product") or "",
            "packages": packages,
            "package_names": [str(p.get("name") or "") for p in packages],
            "recommended_ids": [
                str(p.get("id") or p.get("name") or "") for p in packages if p.get("recommended")
            ],
            "wim_index": idx_used,
            "variant_count": len(folder_names),
            "capabilities": cap,
            "detection_reasons": list(iso.get("detection_reasons") or []),
            "notes": notes,
            "error": "",
            "cached": False,
            "source": source,
        }
        self._write_inventory_cache(iso_id, payload)
        return payload

    def list_isos(self) -> list[dict[str, Any]]:
        state = self._load()
        rows = [deepcopy(v) for v in state["isos"].values() if isinstance(v, dict)]
        rows.sort(key=lambda r: float(r.get("created_at") or 0), reverse=True)
        return rows

    def list_jobs(self, *, limit: int = 40) -> list[dict[str, Any]]:
        state = self._load()
        rows = [deepcopy(v) for v in state["jobs"].values() if isinstance(v, dict)]
        rows.sort(key=lambda r: float(r.get("created_at") or 0), reverse=True)
        return rows[: max(1, min(limit, 100))]

    def get_image(self, image_id: str) -> dict[str, Any] | None:
        state = self._load()
        row = state["images"].get(str(image_id or "").strip())
        return deepcopy(row) if isinstance(row, dict) else None

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        state = self._load()
        row = state["jobs"].get(str(job_id or "").strip())
        return deepcopy(row) if isinstance(row, dict) else None

    def get_iso(self, iso_id: str) -> dict[str, Any] | None:
        state = self._load()
        row = state["isos"].get(str(iso_id or "").strip())
        return deepcopy(row) if isinstance(row, dict) else None

    def read_manifest(self, rel_name: str) -> dict[str, Any]:
        name = Path(str(rel_name or "")).name
        if not SAFE_NAME_RE.match(name) or not name.endswith(".txt"):
            return {"ok": False, "error": "invalid manifest name", "code": "bad_name"}
        path = self.manifests / name
        if not path.is_file():
            return {"ok": False, "error": "manifest not found", "code": "not_found"}
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return {"ok": False, "error": str(exc)[:300], "code": "io"}
        return {"ok": True, "name": name, "content": text[:500000], "bytes": path.stat().st_size}

    def _finish_iso_upload(self, iso_id: str) -> None:
        """Background: base manifest + playbook registry (can take minutes and extra disk)."""
        state = self._load()
        row = state["isos"].get(iso_id)
        if not isinstance(row, dict):
            return
        dest = Path(str(row.get("path") or ""))
        if not dest.is_file():
            return
        label = str(row.get("filename") or row.get("label") or iso_id)
        try:
            self._apply_iso_probe(iso_id, warm_inventory=True)
            state = self._load()
            row = state["isos"].get(iso_id) or row
            base_manifest = self._write_base_iso_manifest(iso_id=iso_id, iso_path=dest, label=label)
            row["base_manifest"] = base_manifest
            row.pop("base_manifest_error", None)
            state = self._load()
            state["isos"][iso_id] = row
            self._save(state)
        except Exception as exc:  # noqa: BLE001
            row["base_manifest_error"] = str(exc)[:300]
            state = self._load()
            state["isos"][iso_id] = row
            self._save(state)
        try:
            self._register_iso_ref(row)
            row.pop("registry_error", None)
        except Exception as exc:  # noqa: BLE001
            row["registry_error"] = str(exc)[:300]
            state = self._load()
            state["isos"][iso_id] = row
            self._save(state)

    def reconcile_iso_cache(self) -> dict[str, Any]:
        """Register ISO files on disk that are missing from the catalog (e.g. interrupted uploads)."""
        state = self._load()
        known_paths = {
            str(Path(str(row.get("path") or "")).resolve())
            for row in state.get("isos", {}).values()
            if isinstance(row, dict) and row.get("path")
        }
        adopted: list[str] = []
        for path in sorted(self.iso_cache.glob("*-*.iso")):
            if not path.is_file():
                continue
            resolved = str(path.resolve())
            if resolved in known_paths:
                continue
            stem = path.name
            iso_id = stem.split("-", 1)[0]
            if not re.fullmatch(r"[0-9a-f]{16}", iso_id):
                continue
            if time.time() - path.stat().st_mtime < 90:
                continue
            size = path.stat().st_size
            if size < 1024 * 1024:
                continue
            h = hashlib.sha256()
            with open(path, "rb") as handle:
                while True:
                    chunk = handle.read(8 * 1024 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)
            safe = stem[len(iso_id) + 1 :] if stem.startswith(iso_id + "-") else path.name
            row = {
                "id": iso_id,
                "filename": safe,
                "original_filename": safe,
                "path": str(path),
                "bytes": size,
                "sha256": h.hexdigest(),
                "created_at": path.stat().st_mtime,
                "created_at_iso": _iso_utc(path.stat().st_mtime),
                "uploaded_by": {},
                "kind": "windows_iso",
                "label": safe,
                "source_meta": {"reconciled": True},
            }
            state["isos"][iso_id] = row
            known_paths.add(resolved)
            adopted.append(iso_id)
        if adopted:
            self._save(state)
            for iso_id in adopted:
                threading.Thread(
                    target=self._finish_iso_upload,
                    args=(iso_id,),
                    daemon=True,
                    name=f"image-nest-finish-{iso_id[:8]}",
                ).start()
        return {"ok": True, "adopted": adopted, "count": len(adopted)}

    def save_upload(
        self,
        *,
        filename: str,
        stream: BinaryIO,
        uploaded_by: dict[str, Any] | None = None,
        progress_cb: Callable[[int], None] | None = None,
        label: str = "",
        source_meta: dict[str, Any] | None = None,
        expected_bytes: int | None = None,
    ) -> dict[str, Any]:
        disk = self.disk_status()
        free_now = int(disk.get("free_bytes") or 0)
        expected = int(expected_bytes or 0)
        if expected > 0 and free_now < expected + MIN_FREE_AFTER_UPLOAD:
            need = expected + MIN_FREE_AFTER_UPLOAD
            return {
                "ok": False,
                "error": (
                    f"Need ~{_fmt_disk_bytes(need)} for this upload "
                    f"({_fmt_disk_bytes(expected)} ISO + {_fmt_disk_bytes(MIN_FREE_AFTER_UPLOAD)} reserve); "
                    f"controller has {_fmt_disk_bytes(free_now)} free"
                ),
                "code": "disk_full",
                "disk": disk,
                "need_bytes": need,
                "have_bytes": free_now,
            }
        if not disk.get("can_accept_upload"):
            return {
                "ok": False,
                "error": (
                    f"Controller disk is low "
                    f"(need >{_fmt_disk_bytes(MIN_FREE_AFTER_UPLOAD + UPLOAD_STREAM_HEADROOM)} free to start; "
                    f"have {_fmt_disk_bytes(free_now)})"
                ),
                "code": "disk_full",
                "disk": disk,
            }

        raw_name = Path(str(filename or "upload.iso")).name
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", raw_name).strip("._")[:160] or "upload.iso"
        if not safe.lower().endswith(".iso"):
            safe = safe + ".iso"

        iso_id = uuid.uuid4().hex[:16]
        dest = self.iso_cache / f"{iso_id}-{safe}"
        h = hashlib.sha256()
        total = 0
        try:
            with open(dest, "wb") as out:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_ISO_BYTES:
                        out.close()
                        dest.unlink(missing_ok=True)
                        return {
                            "ok": False,
                            "error": f"ISO exceeds max size ({MAX_ISO_BYTES} bytes)",
                            "code": "too_large",
                        }
                    free = shutil.disk_usage(self.root).free
                    if free < len(chunk) + UPLOAD_STREAM_HEADROOM:
                        out.close()
                        dest.unlink(missing_ok=True)
                        return {
                            "ok": False,
                            "error": (
                                "Upload stopped — controller ran out of scratch space while writing "
                                f"(have {_fmt_disk_bytes(free)} free, need {_fmt_disk_bytes(len(chunk) + UPLOAD_STREAM_HEADROOM)})"
                            ),
                            "code": "disk_full",
                            "disk": self.disk_status(),
                        }
                    h.update(chunk)
                    out.write(chunk)
                    if progress_cb:
                        progress_cb(total)
        except OSError as exc:
            dest.unlink(missing_ok=True)
            return {"ok": False, "error": str(exc)[:300], "code": "io"}

        if total < 64 * 1024:
            dest.unlink(missing_ok=True)
            return {"ok": False, "error": "file too small to be an OS ISO", "code": "too_small"}

        detected = detect_os_media(
            filename=raw_name,
            label=str(label or safe),
            source_meta=source_meta if isinstance(source_meta, dict) else None,
        )
        meta = source_meta if isinstance(source_meta, dict) else {}
        meta = dict(meta)
        meta["os_family"] = detected.get("os_family")
        meta["platform"] = detected.get("platform")
        meta["distro"] = detected.get("distro")
        meta["product"] = detected.get("product")

        row = {
            "id": iso_id,
            "filename": safe,
            "original_filename": raw_name[:180],
            "path": str(dest),
            "bytes": total,
            "sha256": h.hexdigest(),
            "created_at": _now(),
            "created_at_iso": _iso_utc(),
            "uploaded_by": uploaded_by if isinstance(uploaded_by, dict) else {},
            "kind": "linux_iso" if detected.get("platform") == "linux" else "windows_iso",
            "label": str(label or safe)[:180],
            "source_meta": meta,
            "os_family": detected.get("os_family"),
            "platform": detected.get("platform"),
            "distro": detected.get("distro"),
            "name_slug": detected.get("name_slug"),
            "detection_reasons": ["filename/metadata heuristic (refined after 7z listing)"],
        }
        state = self._load()
        state["isos"][iso_id] = row
        self._save(state)

        # Quick 7z listing probe (fast, no extract) before background manifest/inventory.
        try:
            self._apply_iso_probe(iso_id, warm_inventory=False)
        except Exception:
            pass

        threading.Thread(
            target=self._finish_iso_upload,
            args=(iso_id,),
            daemon=True,
            name=f"image-nest-finish-{iso_id[:8]}",
        ).start()

        return {
            "ok": True,
            "iso": row,
            "disk": self.disk_status(),
            "manifest_pending": True,
        }

    def ingest_path(
        self,
        *,
        path: Path,
        filename: str = "",
        label: str = "",
        source_meta: dict[str, Any] | None = None,
        uploaded_by: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        src = Path(path)
        if not src.is_file():
            return {"ok": False, "error": "source file not found", "code": "not_found"}
        name = str(filename or src.name or "upload.iso")
        with open(src, "rb") as handle:
            return self.save_upload(
                filename=name,
                stream=handle,
                uploaded_by=uploaded_by,
                label=label,
                source_meta=source_meta,
            )

    def start_build(
        self,
        *,
        iso_id: str,
        flavor: str,
        requested_by: dict[str, Any] | None = None,
        wim_index: int = 0,
        disk_gb: int = 60,
        strip_option_ids: list[str] | None = None,
        strip_packages: list[str] | None = None,
        deploy_target: str = "hypervisor",
        unattend: dict[str, Any] | None = None,
        run_async: bool = True,
    ) -> dict[str, Any]:
        flavor_n = str(flavor or "").strip().lower()
        if flavor_n in {"strip", "stripped", "strip_and_deploy"}:
            flavor_n = "stripped"
        elif flavor_n in {"full", "deploy_full"}:
            flavor_n = "full"
        elif flavor_n in {"iso", "bare_metal", "bare-metal"}:
            flavor_n = "full"
        else:
            return {"ok": False, "error": "flavor must be stripped or full", "code": "bad_flavor"}

        target = self._normalize_deploy_target(deploy_target) or "hypervisor"
        target_meta = self._deploy_target_meta(target)
        export_format = str(target_meta.get("export_format") or "")

        iso = self.get_iso(iso_id)
        if not iso:
            return {"ok": False, "error": "ISO not found — upload first", "code": "iso_missing"}
        iso_path = Path(str(iso.get("path") or ""))
        if not iso_path.is_file():
            return {"ok": False, "error": "ISO file missing on disk", "code": "iso_missing"}

        detected = detect_os_media(
            filename=str(iso.get("original_filename") or iso.get("filename") or ""),
            label=str(iso.get("label") or ""),
            source_meta=iso.get("source_meta") if isinstance(iso.get("source_meta"), dict) else None,
        )
        platform = str(iso.get("platform") or detected.get("platform") or "windows")
        family = str(iso.get("os_family") or detected.get("os_family") or "client")
        if platform == "linux":
            family = "linux"
            slug = str(detected.get("name_slug") or iso.get("distro") or "linux")
        else:
            slug = "winserver" if family == "server" else str(detected.get("name_slug") or "win11")

        tools = self.tool_status()
        if target in {"bootable_disk", "hyperv", "vmware"}:
            if not tools.get("qemu_img"):
                return {
                    "ok": False,
                    "error": "qemu-img required for bootable / Hyper-V / VMware disk targets",
                    "code": "tool_missing",
                    "tools": tools,
                }
            # Windows ready disks need virt-install on this appliance.
            if platform != "linux" and not tools.get("virt_install"):
                return {
                    "ok": False,
                    "error": (
                        "virt-install required to bake a bootable Windows disk on this controller. "
                        "Use Hypervisor (WIM) or Bare metal (ISO), or install qemu-kvm/virtinst."
                    ),
                    "code": "tool_missing",
                    "tools": tools,
                }

        concrete_pkgs: list[str] | None = None
        if strip_packages is not None:
            concrete_pkgs = []
            seen_pkg: set[str] = set()
            for raw in strip_packages:
                name = str(raw or "").strip()
                if not name or name in seen_pkg:
                    continue
                seen_pkg.add(name)
                concrete_pkgs.append(name)

        if concrete_pkgs is not None and flavor_n == "stripped":
            if platform == "linux":
                strip_sel = {
                    "ok": True,
                    "option_ids": [],
                    "paths": [],
                    "package_globs": list(concrete_pkgs),
                    "labels": list(concrete_pkgs),
                    "options": [],
                    "os_family": "linux",
                    "platform": "linux",
                    "strip_packages": list(concrete_pkgs),
                }
            else:
                # Paths are family/folder names; expanded against live WIM listing at bake time.
                strip_sel = {
                    "ok": True,
                    "option_ids": [],
                    "paths": list(concrete_pkgs),
                    "package_globs": [],
                    "labels": list(concrete_pkgs),
                    "options": [],
                    "os_family": family,
                    "platform": "windows",
                    "strip_packages": list(concrete_pkgs),
                }
        else:
            strip_sel = self.resolve_strip_selection(
                strip_option_ids, flavor=flavor_n, os_family=family
            )
        if not strip_sel.get("ok"):
            return {
                "ok": False,
                "error": str(strip_sel.get("error") or "invalid strip options"),
                "code": str(strip_sel.get("code") or "bad_strip_option"),
            }

        job_id = uuid.uuid4().hex
        image_id = uuid.uuid4().hex[:12]
        stamp = _ts_slug()
        if target == "bare_metal":
            image_name = f"{slug}-bare-metal-{flavor_n}-{stamp}"
            qcow_path = Path("")
            disk_path = Path("")
        elif target == "bootable_disk":
            image_name = f"{slug}-bootable-{flavor_n}-{stamp}"
            qcow_path = self.image_bank / f"{image_name}.qcow2"
            disk_path = qcow_path
        elif target == "hyperv":
            image_name = f"{slug}-hyperv-{flavor_n}-{stamp}"
            qcow_path = self.image_bank / f"{image_name}.qcow2"
            disk_path = self.image_bank / f"{image_name}.vhdx"
        elif target == "vmware":
            image_name = f"{slug}-vmware-{flavor_n}-{stamp}"
            qcow_path = self.image_bank / f"{image_name}.qcow2"
            disk_path = self.image_bank / f"{image_name}.vmdk"
        else:
            image_name = f"{slug}-{flavor_n}-{stamp}"
            qcow_path = self.image_bank / f"{image_name}.qcow2"
            disk_path = qcow_path
        base_manifest = str(iso.get("base_manifest") or "")
        deploy_manifest = f"{image_name}-deployed.txt"
        label = detected.get("label") or slug
        catalog_file = (
            str(self._linux_strip_catalog_path())
            if platform == "linux"
            else str(self._strip_catalog_path())
        )
        if target == "bare_metal":
            core = (
                f"Bare-metal {'Linux' if platform == 'linux' else 'Windows'} install ISO ({label})"
                + (" — stripped" if flavor_n == "stripped" else "")
                + " — ZTP/PXE/USB"
            )
        elif target == "bootable_disk":
            core = (
                f"Bootable guest disk qcow2 ({label}) for Proxmox/KVM"
                + (" — Windows virt-install + Autounattend" if platform != "linux" else " — Linux ISO + disk stub (or virt-install when available)")
            )
        elif target == "hyperv":
            core = f"Hyper-V VHDX ({label})" + (
                " — Windows bootable convert" if platform != "linux" else " — Linux ISO + empty VHDX stub"
            )
        elif target == "vmware":
            core = f"VMware VMDK ({label})" + (
                " — Windows bootable convert" if platform != "linux" else " — Linux ISO + empty VMDK stub"
            )
        elif platform == "linux":
            core = (
                f"Hypervisor Linux ISO ({label}) for OpenTofu / virt"
                + (" — stripped" if flavor_n == "stripped" else "")
            )
        else:
            core = (
                f"Hypervisor Windows WIM ({label}) for OpenTofu / virt"
                + (" — stripped" if flavor_n == "stripped" else "")
            )

        unattend_cfg = unattend if isinstance(unattend, dict) else {}
        image_row = {
            "id": image_id,
            "name": image_name,
            "flavor": flavor_n,
            "deploy_target": target,
            "export_format": export_format,
            "disk_format": str(target_meta.get("disk_format") or ""),
            "platform": platform,
            "os_family": family,
            "distro": detected.get("distro") or iso.get("distro") or "",
            "os_product": detected.get("product"),
            "status": "queued",
            "created_at": _now(),
            "created_at_iso": _iso_utc(),
            "iso_id": iso_id,
            "iso_filename": iso.get("original_filename") or iso.get("filename"),
            "qcow2_path": str(qcow_path) if qcow_path else "",
            "disk_path": str(disk_path) if disk_path else "",
            "vhdx_path": str(disk_path) if target == "hyperv" else "",
            "vmdk_path": str(disk_path) if target == "vmware" else "",
            "qcow2_bytes": 0,
            "base_manifest": base_manifest,
            "deploy_manifest": deploy_manifest,
            "core_manifest": core,
            "job_id": job_id,
            "error": "",
            "requested_by": requested_by if isinstance(requested_by, dict) else {},
            "wim_index": int(wim_index or 0),
            "disk_gb": max(20, min(int(disk_gb or 60), 200)) if target != "bare_metal" else 0,
            "strip_option_ids": list(strip_sel.get("option_ids") or []),
            "strip_packages": list(strip_sel.get("strip_packages") or concrete_pkgs or []),
            "strip_labels": list(strip_sel.get("labels") or []),
            "strip_package_globs": list(strip_sel.get("package_globs") or []),
            "strip_paths": list(strip_sel.get("paths") or []),
            "strip_catalog_file": catalog_file,
            "unattend": {
                "hostname": str(unattend_cfg.get("hostname") or unattend_cfg.get("computer_name") or "HAYA-NEST"),
                "username": str(unattend_cfg.get("username") or unattend_cfg.get("admin_user") or "hayabusa"),
                # password kept for job only; omit from registry exports
                "password": str(unattend_cfg.get("password") or unattend_cfg.get("admin_password") or "Hayabusa!ChangeMe"),
            },
        }
        job_row = {
            "id": job_id,
            "image_id": image_id,
            "flavor": flavor_n,
            "deploy_target": target,
            "export_format": export_format,
            "status": "queued",
            "created_at": _now(),
            "updated_at": _now(),
            "log": [],
            "error": "",
            "strip_option_ids": list(strip_sel.get("option_ids") or []),
            "strip_packages": list(image_row.get("strip_packages") or []),
        }
        state = self._load()
        state["images"][image_id] = image_row
        state["jobs"][job_id] = job_row
        self._save(state)

        if run_async:
            threading.Thread(
                target=self._run_build_job,
                args=(job_id,),
                daemon=True,
                name=f"image-nest-{job_id[:8]}",
            ).start()
        return {"ok": True, "job": job_row, "image": self._enrich_bank_row(image_row), "job_id": job_id}

    def delete_image(self, image_id: str) -> dict[str, Any]:
        state = self._load()
        row = state["images"].pop(str(image_id or "").strip(), None)
        if not isinstance(row, dict):
            return {"ok": False, "error": "not found", "code": "not_found"}
        for key in ("qcow2_path", "wim_path", "banked_iso_path"):
            p = Path(str(row.get(key) or ""))
            if p.is_file() and str(self.image_bank) in str(p.resolve()):
                try:
                    p.unlink()
                except OSError:
                    pass
        for mkey in ("base_manifest", "deploy_manifest"):
            name = Path(str(row.get(mkey) or "")).name
            if name and SAFE_NAME_RE.match(name):
                mp = self.manifests / name
                if mp.is_file():
                    try:
                        mp.unlink()
                    except OSError:
                        pass
        self._save(state)
        return {"ok": True, "deleted": image_id}

    def _register_iso_ref(self, iso_row: dict[str, Any]) -> str:
        meta = iso_row.get("source_meta") if isinstance(iso_row.get("source_meta"), dict) else {}
        detected = detect_os_media(
            filename=str(iso_row.get("original_filename") or iso_row.get("filename") or ""),
            label=str(iso_row.get("label") or ""),
            source_meta=meta,
        )
        family = str(iso_row.get("os_family") or detected.get("os_family") or "client")
        platform = str(iso_row.get("platform") or detected.get("platform") or "windows")
        if platform == "linux":
            family = "linux"
            slug = str(detected.get("name_slug") or "linux")
        else:
            slug = str(iso_row.get("name_slug") or detected.get("name_slug") or "")
            if not slug:
                slug = "winserver" if family == "server" else "win11"
        lang = str(meta.get("language") or "en-us").lower()
        arch = str(meta.get("arch") or "x64").lower()
        edition = str(meta.get("edition") or detected.get("product") or f"{slug}-multi").lower()
        stamp = datetime.fromtimestamp(float(iso_row.get("created_at") or _now()), tz=timezone.utc).strftime(
            "%Y%m%d"
        )
        ref = self._slug_ref(f"{slug}-iso-{lang}-{arch}-{edition}-{stamp}")
        label = str(iso_row.get("label") or iso_row.get("filename") or ref)
        row = {
            "ref": ref,
            "type": "iso",
            "deploy_target": "bare_metal",
            "platform": platform,
            "os_family": family,
            "distro": detected.get("distro") or "",
            "os_product": detected.get("product"),
            "catalog_id": iso_row.get("id"),
            "label": label,
            "path": iso_row.get("path"),
            "iso_path": iso_row.get("path"),
            "sha256": iso_row.get("sha256"),
            "bytes": iso_row.get("bytes"),
            "created_at": iso_row.get("created_at"),
            "created_at_iso": iso_row.get("created_at_iso"),
            "source_meta": {
                **meta,
                "os_family": family,
                "platform": platform,
                "distro": detected.get("distro"),
                "product": detected.get("product"),
            },
            "playbook_vars_file": str(self.playbook_refs_dir / f"{ref}.vars.json"),
        }
        aliases = {
            f"latest-{slug}-iso": ref,
            f"latest-{slug}-bare-metal": ref,
            f"latest-{slug}-iso-{lang}-{arch}": ref,
        }
        if platform == "linux":
            aliases.update(
                {
                    "latest-linux-iso": ref,
                    "latest-linux-bare-metal": ref,
                }
            )
        else:
            aliases.update(
                {
                    "latest-windows-iso": ref,
                    "latest-windows-bare-metal": ref,
                }
            )
            if family == "client":
                aliases.update(
                    {
                        "latest-win11-iso": ref,
                        "latest-win11-bare-metal": ref,
                        f"latest-win11-iso-{lang}-{arch}": ref,
                    }
                )
        self._register_ref(ref=ref, row=row, aliases=aliases)
        state = self._load()
        iso = state["isos"].get(str(iso_row.get("id") or ""))
        if isinstance(iso, dict):
            iso["registry_ref"] = ref
            iso["os_family"] = family
            iso["platform"] = platform
            state["isos"][str(iso_row.get("id"))] = iso
            self._save(state)
        return ref

    def _register_image_ref(self, image_row: dict[str, Any]) -> str:
        flavor = str(image_row.get("flavor") or "full")
        target = self._normalize_deploy_target(image_row.get("deploy_target") or "") or (
            "bare_metal" if flavor in {"iso", "bare_metal"} else "hypervisor"
        )
        family = str(image_row.get("os_family") or "").strip().lower()
        platform = str(image_row.get("platform") or "").strip().lower()
        if family not in {"client", "server", "linux"} or not platform:
            detected = detect_os_media(
                filename=str(image_row.get("iso_filename") or image_row.get("name") or ""),
                label=str(image_row.get("name") or ""),
            )
            family = str(detected.get("os_family") or family or "client")
            platform = str(detected.get("platform") or platform or "windows")
        if platform == "linux" or family == "linux":
            platform = "linux"
            family = "linux"
            slug = str(image_row.get("distro") or "linux")
        else:
            slug = str(image_row.get("name_slug") or "")
            if not slug:
                detected_slug = detect_os_media(
                    filename=str(image_row.get("iso_filename") or image_row.get("name") or ""),
                    label=str(image_row.get("name") or ""),
                ).get("name_slug")
                slug = str(detected_slug or ("winserver" if family == "server" else "win11"))
        stamp = datetime.fromtimestamp(float(image_row.get("created_at") or _now()), tz=timezone.utc).strftime(
            "%Y%m%d-%H%M%S"
        )
        if target == "bare_metal":
            ref = self._slug_ref(f"{slug}-bare-metal-{stamp}")
        else:
            ref = self._slug_ref(f"{slug}-{flavor}-{stamp}")
        label = str(image_row.get("name") or ref)
        row = {
            "ref": ref,
            "type": "iso" if target == "bare_metal" or platform == "linux" else "bank_image",
            "deploy_target": target,
            "platform": platform,
            "os_family": family,
            "distro": image_row.get("distro") or "",
            "os_product": image_row.get("os_product") or "",
            "catalog_id": image_row.get("id"),
            "label": label,
            "flavor": flavor,
            "path": image_row.get("vhdx_path")
            or image_row.get("vmdk_path")
            or image_row.get("disk_path")
            or image_row.get("banked_iso_path")
            or image_row.get("wim_path")
            or image_row.get("qcow2_path")
            or image_row.get("iso_path")
            or image_row.get("path")
            or "",
            "iso_path": image_row.get("banked_iso_path")
            or image_row.get("iso_path")
            or "",
            "wim_path": image_row.get("wim_path") or "",
            "qcow2_path": image_row.get("qcow2_path") or "",
            "vhdx_path": image_row.get("vhdx_path") or "",
            "vmdk_path": image_row.get("vmdk_path") or "",
            "disk_path": image_row.get("disk_path") or "",
            "disk_format": image_row.get("disk_format") or "",
            "banked_iso_path": image_row.get("banked_iso_path") or "",
            "status": image_row.get("status"),
            "sha256": image_row.get("sha256") or "",
            "bytes": image_row.get("wim_bytes")
            or image_row.get("qcow2_bytes")
            or image_row.get("bytes")
            or 0,
            "created_at": image_row.get("created_at"),
            "created_at_iso": image_row.get("created_at_iso"),
            "iso_id": image_row.get("iso_id"),
            "deploy_manifest": image_row.get("deploy_manifest"),
            "playbook_vars_file": str(self.playbook_refs_dir / f"{ref}.vars.json"),
        }
        iso = self.get_iso(str(image_row.get("iso_id") or ""))
        if isinstance(iso, dict):
            row["iso_path"] = row["iso_path"] or iso.get("path")
            row["iso_registry_ref"] = iso.get("registry_ref")
            if target == "bare_metal" and not row.get("path"):
                row["path"] = iso.get("path")
        if target == "bare_metal":
            bm_tail = f"bare-metal-{flavor}" if flavor in {"stripped", "full"} else "bare-metal"
            aliases: dict[str, str] = {f"latest-{slug}-{bm_tail}": ref}
        elif target == "bootable_disk":
            aliases = {
                f"latest-{slug}-bootable": ref,
                f"latest-{slug}-hypervisor-bootable": ref,
                f"latest-{slug}-qcow2": ref,
            }
        elif target == "hyperv":
            aliases = {
                f"latest-{slug}-hyperv": ref,
                f"latest-{slug}-vhdx": ref,
            }
        elif target == "vmware":
            aliases = {
                f"latest-{slug}-vmware": ref,
                f"latest-{slug}-vmdk": ref,
            }
        else:
            aliases = {f"latest-{slug}-{flavor}": ref}
        if platform == "linux":
            linux_tail = (
                f"bare-metal-{flavor}"
                if target == "bare_metal" and flavor in {"stripped", "full"}
                else (f"bare-metal" if target == "bare_metal" else flavor)
            )
            aliases.update(
                {
                    f"latest-{slug}-{linux_tail}": ref,
                    f"latest-linux-{linux_tail}": ref,
                    "latest-linux-iso" if target == "bare_metal" else f"latest-linux-{flavor}": ref,
                }
            )
            if target == "bare_metal":
                aliases.update({"latest-linux-bare-metal": ref, "latest-linux-iso": ref})
                if flavor == "stripped":
                    aliases.update(
                        {
                            "latest-linux-bare-metal-stripped": ref,
                            f"latest-{slug}-bare-metal-stripped": ref,
                        }
                    )
            elif target == "bootable_disk":
                aliases.update(
                    {
                        "latest-linux-bootable": ref,
                        "latest-linux-qcow2": ref,
                        f"latest-{slug}-bootable": ref,
                    }
                )
            elif target == "hyperv":
                aliases.update(
                    {
                        "latest-linux-hyperv": ref,
                        "latest-linux-vhdx": ref,
                        f"latest-{slug}-hyperv": ref,
                    }
                )
            elif target == "vmware":
                aliases.update(
                    {
                        "latest-linux-vmware": ref,
                        "latest-linux-vmdk": ref,
                        f"latest-{slug}-vmware": ref,
                    }
                )
            else:
                aliases.update(
                    {
                        f"latest-linux-{flavor}": ref,
                        f"latest-linux-hypervisor-{flavor}": ref,
                        "latest-linux-hypervisor": ref,
                    }
                )
        elif target == "bare_metal":
            aliases.update(
                {
                    f"latest-{slug}-bare-metal": ref,
                    f"latest-{slug}-iso": ref,
                    "latest-windows-bare-metal": ref,
                    "latest-windows-iso": ref,
                }
            )
            if flavor == "stripped":
                aliases.update(
                    {
                        f"latest-{slug}-bare-metal-stripped": ref,
                        "latest-windows-bare-metal-stripped": ref,
                    }
                )
            if family == "client":
                aliases.update({"latest-win11-bare-metal": ref, "latest-win11-iso": ref})
                if flavor == "stripped":
                    aliases["latest-win11-bare-metal-stripped"] = ref
                if slug == "win10":
                    aliases.update(
                        {
                            "latest-win10-bare-metal": ref,
                            "latest-win10-iso": ref,
                            "latest-windows-10-bare-metal": ref,
                        }
                    )
                    if flavor == "stripped":
                        aliases["latest-win10-bare-metal-stripped"] = ref
        else:
            aliases.update(
                {
                    f"latest-{slug}-{flavor}": ref,
                    f"latest-{slug}-hypervisor-{flavor}": ref,
                    f"latest-{slug}-hypervisor": ref,
                    f"latest-windows-{flavor}": ref,
                    "latest-windows-hypervisor": ref,
                }
            )
            if family == "client":
                if target == "bootable_disk":
                    aliases.update(
                        {
                            "latest-win11-bootable": ref,
                            "latest-win11-hypervisor-bootable": ref,
                            "latest-win11-qcow2": ref,
                        }
                    )
                elif target == "hyperv":
                    aliases.update({"latest-win11-hyperv": ref, "latest-win11-vhdx": ref})
                elif target == "vmware":
                    aliases.update({"latest-win11-vmware": ref, "latest-win11-vmdk": ref})
                else:
                    aliases.update(
                        {
                            f"latest-win11-{flavor}": ref,
                            f"latest-win11-hypervisor-{flavor}": ref,
                            "latest-win11-hypervisor": ref,
                        }
                    )
                if slug == "win10":
                    aliases.update(
                        {
                            f"latest-win10-{flavor}": ref,
                            f"latest-win10-hypervisor-{flavor}": ref,
                            "latest-win10-hypervisor": ref,
                            "latest-windows-10-stripped": ref if flavor == "stripped" else "",
                        }
                    )
                    aliases = {k: v for k, v in aliases.items() if k and v}
                if flavor == "full":
                    aliases["latest-win11-vm-image"] = ref
                    if slug == "win10":
                        aliases["latest-win10-vm-image"] = ref
                if flavor == "stripped":
                    aliases["latest-win11-hypervisor-stripped"] = ref
            if family == "server":
                if flavor == "full":
                    aliases["latest-winserver-vm-image"] = ref
                if flavor == "stripped":
                    aliases["latest-winserver-hypervisor-stripped"] = ref
        self._register_ref(ref=ref, row=row, aliases=aliases)
        state = self._load()
        img = state["images"].get(str(image_row.get("id") or ""))
        if isinstance(img, dict):
            img["registry_ref"] = ref
            img["deploy_target"] = target
            img["os_family"] = family
            img["platform"] = platform
            state["images"][str(image_row.get("id"))] = img
            self._save(state)
        return ref

    def write_tofu_handoff(self, *, image_id: str, target_vm_name: str) -> dict[str, Any]:
        """Write a tfvars snippet for Hayabusa — never installs or runs OpenTofu here."""
        image = self.get_image(image_id)
        if not image:
            return {"ok": False, "error": "image not found", "code": "not_found"}
        qcow = Path(str(image.get("qcow2_path") or ""))
        wim = Path(str(image.get("wim_path") or ""))
        source = qcow if qcow.is_file() else wim
        vm = re.sub(r"[^A-Za-z0-9._-]+", "-", str(target_vm_name or "").strip())[:64]
        if not vm:
            return {"ok": False, "error": "target_vm_name required", "code": "bad_name"}
        out_dir = self.root / "tofu-handoff"
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / f"{vm}.auto.tfvars"
        body = (
            f'# Generated by Image Nest on {_iso_utc()}\n'
            f'# User-supplied ISO processed locally — not distributed by Hayabusa.\n'
            f'# Controller does NOT run OpenTofu. Sync this file to Hayabusa and apply there.\n'
            f'target_vm_name = "{vm}"\n'
            f'source_image   = "{source}"\n'
            f'image_nest_id  = "{image.get("id")}"\n'
            f'image_flavor   = "{image.get("flavor")}"\n'
            f'image_status   = "{image.get("status")}"\n'
        )
        out.write_text(body, encoding="utf-8")
        return {
            "ok": True,
            "path": str(out),
            "content": body,
            "hint": (
                "Hand-off only — this controller does not install or run OpenTofu. "
                "Sync the snippet to Hayabusa Craft and apply from there."
            ),
        }

    # --- internal helpers -------------------------------------------------

    def _append_job_log(self, job_id: str, line: str) -> None:
        state = self._load()
        job = state["jobs"].get(job_id)
        if not isinstance(job, dict):
            return
        logs = job.get("log") if isinstance(job.get("log"), list) else []
        logs.append(f"{_iso_utc()}  {line}")
        job["log"] = logs[-200:]
        job["updated_at"] = _now()
        state["jobs"][job_id] = job
        self._save(state)

    def _update_job(self, job_id: str, **fields: Any) -> None:
        state = self._load()
        job = state["jobs"].get(job_id)
        if not isinstance(job, dict):
            return
        job.update(fields)
        job["updated_at"] = _now()
        state["jobs"][job_id] = job
        image_id = str(job.get("image_id") or "")
        img = state["images"].get(image_id)
        if isinstance(img, dict):
            if "status" in fields:
                job_status = str(fields.get("status") or "")
                # Do not overwrite ready_wim_* / ready_iso with generic job "completed".
                if job_status != "completed":
                    img["status"] = job_status
            if fields.get("error"):
                img["error"] = str(fields["error"])[:400]
            state["images"][image_id] = img
        self._save(state)

    def _write_base_iso_manifest(self, *, iso_id: str, iso_path: Path, label: str) -> str:
        tools = self.tool_status()
        out_name = f"base-iso-{iso_id}-{_ts_slug()}.txt"
        out_path = self.manifests / out_name
        lines = [
            "=" * 72,
            f"IMAGE PACKAGE MANIFEST (BASE ISO): {label}",
            f"Generated: {_iso_utc()}",
            f"ISO path: {iso_path}",
            f"SHA256: (see catalog)",
            "=" * 72,
            "",
        ]
        wim = tools.get("wimlib_imagex") or ""
        if wim:
            # Prefer listing WIM indexes without requiring a privileged loop mount.
            # Users can mount later for deeper DISM-style package dumps.
            probe = subprocess.run(
                [wim, "info", str(iso_path)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            # wimlib cannot read ISO directly usually — try extract install.wim via 7z
            if probe.returncode != 0:
                lines.append("[wimlib] direct info on ISO failed (expected); trying archive extract…")
                lines.append((probe.stderr or probe.stdout or "")[:2000])
            else:
                lines.append(probe.stdout or "")
        seven = tools.get("seven_z") or ""
        if seven:
            cmd = [seven, "l", str(iso_path)] if Path(seven).name.startswith("7") else [seven, "-tf", str(iso_path)]
            listing = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            lines.append("")
            lines.append("[Archive listing — sources / install media layout]")
            lines.append((listing.stdout or listing.stderr or "")[:120000])
        else:
            lines.append("")
            lines.append(
                "[Tooling] Install wimlib-imagex and/or 7z on this controller for richer ISO package manifests."
            )
            lines.append(f"ISO size bytes: {iso_path.stat().st_size}")

        # Attempt: extract install.wim info if 7z can pull sources/install.wim to temp
        if seven and wim:
            tmp = self.jobs_dir / f"wim-extract-{iso_id}"
            tmp.mkdir(parents=True, exist_ok=True)
            try:
                # 7z extract specific member if present
                for member in ("sources/install.wim", "sources/install.esd"):
                    ex = subprocess.run(
                        [seven, "e", "-y", f"-o{tmp}", str(iso_path), member],
                        capture_output=True,
                        text=True,
                        timeout=600,
                    )
                    candidate = tmp / Path(member).name
                    if candidate.is_file():
                        info = subprocess.run(
                            [wim, "info", str(candidate)],
                            capture_output=True,
                            text=True,
                            timeout=180,
                        )
                        lines.append("")
                        lines.append(f"[wimlib-imagex info — {member}]")
                        lines.append(info.stdout or info.stderr or "")
                        # Prefer highest index (often Pro); fall back to 1.
                        idx = self._pick_wim_index(info.stdout or "")
                        listing = subprocess.run(
                            [wim, "dir", str(candidate), str(idx), "--path=\\Program Files\\WindowsApps"],
                            capture_output=True,
                            text=True,
                            timeout=300,
                        )
                        lines.append("")
                        lines.append(f"[Built-In Applications Metadata — WindowsApps @ index {idx}]")
                        apps = listing.stdout or listing.stderr or ""
                        lines.append(apps[:80000] if apps else "(no WindowsApps listing)")
                        try:
                            folders = _windowsapps_package_names(apps)
                            pkgs = self._annotate_windows_packages(
                                _group_appx_packages(folders),
                                os_family=str(
                                    detect_windows_media(
                                        filename=iso_path.name, wim_info=info.stdout or ""
                                    ).get("os_family")
                                    or "client"
                                ),
                            )
                            self._write_inventory_cache(
                                iso_id,
                                {
                                    "ok": True,
                                    "platform": "windows",
                                    "os_family": detect_windows_media(
                                        filename=iso_path.name, wim_info=info.stdout or ""
                                    ).get("os_family")
                                    or "client",
                                    "packages": pkgs,
                                    "package_names": [str(p.get("name") or "") for p in pkgs],
                                    "recommended_ids": [
                                        str(p.get("id") or "") for p in pkgs if p.get("recommended")
                                    ],
                                    "wim_index": idx,
                                    "variant_count": len(folders),
                                    "notes": ["captured during base ISO manifest"],
                                    "error": "",
                                    "cached": False,
                                    "source": "base_manifest",
                                },
                            )
                        except Exception as exc:  # noqa: BLE001
                            lines.append(f"[inventory cache skipped] {exc}")
                        break
                    lines.append(f"[extract] {member}: {(ex.stderr or ex.stdout or '')[:400]}")
            finally:
                shutil.rmtree(tmp, ignore_errors=True)

        out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return out_name

    def _pick_wim_index(self, info_text: str, os_family: str = "") -> int:
        """Prefer Pro (client) or Server Standard/Datacenter Desktop Experience (server)."""
        family = str(os_family or "").strip().lower()
        blocks: list[dict[str, Any]] = []
        cur: dict[str, Any] | None = None
        for line in (info_text or "").splitlines():
            m = re.search(r"^Index:\s*(\d+)\s*$", line.strip(), re.I)
            if m:
                cur = {"index": int(m.group(1)), "text": ""}
                blocks.append(cur)
                continue
            if cur is not None:
                cur["text"] += line.lower() + "\n"
        if not blocks:
            return 1

        def score(block: dict[str, Any]) -> tuple[int, int]:
            text = str(block.get("text") or "")
            idx = int(block.get("index") or 0)
            s = 0
            if family == "server":
                if "serverstandard" in text or "standard" in text:
                    s += 50
                if "serverdatacenter" in text or "datacenter" in text:
                    s += 45
                if "desktop experience" in text or "serverwithgui" in text:
                    s += 20
                if "server core" in text or "core" == text.strip():
                    s -= 5
                if " evaluation" in text:
                    s -= 10
            else:
                # Client: prefer Pro, avoid N/Single Language when possible
                if re.search(r"name:\s*windows\s*1[01]\s+pro\s*$", text, re.M):
                    s += 80
                elif re.search(r"\bpro\b", text) or "professional" in text:
                    s += 50
                if "workstations" in text:
                    s += 5
                if "enterprise" in text:
                    s += 35
                if "education" in text:
                    s += 20
                if re.search(r"\bhome\b", text):
                    s += 10
                if (
                    re.search(r"\bn\b", text)
                    or " home n" in text
                    or " pro n" in text
                    or "workstations n" in text
                ):
                    s -= 40
                if "single language" in text:
                    s -= 30
            return (s, -idx)

        best = max(blocks, key=score)
        return int(best.get("index") or 1)

    def _extract_install_wim(self, *, iso_path: Path, work: Path, iso_id: str = "") -> tuple[Path | None, str]:
        work.mkdir(parents=True, exist_ok=True)
        dest = work / "install.wim"
        if iso_id:
            cached = self.jobs_dir / f"wim-extract-{iso_id}" / "install.wim"
            if cached.is_file() and cached.stat().st_size > 500_000_000:
                # Move (do not hardlink/copy): strip mutates the WIM and we need free space.
                try:
                    if dest.exists():
                        dest.unlink()
                    shutil.move(str(cached), str(dest))
                    return dest, "sources/install.wim (cached-move)"
                except OSError as exc:
                    return None, f"failed to reclaim cached WIM: {exc}"
        seven = (self.tool_status().get("seven_z") or "")
        if not seven:
            return None, "7z missing"
        free = shutil.disk_usage(self.root).free
        # install.wim is typically ~5–8GiB; require headroom before extract.
        if free < 9 * 1024**3:
            return None, (
                f"insufficient free disk for WIM extract "
                f"({_fmt_disk_bytes(free)} free; need ≥9 GB)"
            )
        for member in ("sources/install.wim", "sources/install.esd"):
            subprocess.run(
                [seven, "e", "-y", f"-o{work}", str(iso_path), member],
                capture_output=True,
                text=True,
                timeout=900,
            )
            cand = work / Path(member).name
            if cand.is_file():
                if cand.resolve() != dest.resolve():
                    if dest.exists():
                        dest.unlink()
                    cand.rename(dest)
                return dest, member
        return None, "install.wim/esd not found in ISO"

    def _iso_wim_member(self, iso_path: Path) -> str:
        """Return sources/install.wim or sources/install.esd path inside the ISO."""
        seven = (self.tool_status().get("seven_z") or "")
        if not seven:
            return "sources/install.wim"
        listing = subprocess.run(
            [seven, "l", "-ba", str(iso_path)],
            capture_output=True,
            text=True,
            timeout=180,
        )
        for line in (listing.stdout or "").splitlines():
            name = line.split()[-1].replace("\\", "/").lower() if line.split() else ""
            if name.endswith("sources/install.wim"):
                return "sources/install.wim"
            if name.endswith("sources/install.esd"):
                return "sources/install.esd"
        return "sources/install.wim"

    def _iso_volume_id(self, source_iso: Path, *, xorriso: str) -> str:
        proc = subprocess.run(
            [xorriso, "-indev", str(source_iso), "-pvd_info"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        for line in (proc.stdout or "").splitlines():
            m = re.search(r"Volume id\s*:\s*'([^']*)'", line, re.I)
            if m:
                return m.group(1).strip() or "IMAGE_NEST_WIN"
        return "IMAGE_NEST_WIN"

    def _rebuild_windows_iso_from_tree(
        self, tree: Path, out_iso: Path, *, volume_id: str = "IMAGE_NEST_WIN"
    ) -> dict[str, Any]:
        """Rebuild a Windows install ISO from an extracted tree (UEFI + BIOS boot)."""
        xorriso = shutil.which("xorriso")
        if not xorriso:
            return {"ok": False, "error": "xorriso missing"}
        if out_iso.exists():
            out_iso.unlink()
        etfs = tree / "boot" / "etfsboot.com"
        efisys_np = tree / "efi" / "microsoft" / "boot" / "efisys_noprompt.bin"
        efisys = tree / "efi" / "microsoft" / "boot" / "efisys.bin"
        efi_member = ""
        if efisys_np.is_file():
            efi_member = "efi/microsoft/boot/efisys_noprompt.bin"
        elif efisys.is_file():
            efi_member = "efi/microsoft/boot/efisys.bin"
        cmd = [
            xorriso,
            "-as",
            "mkisofs",
            "-iso-level",
            "3",
            "-joliet",
            "-joliet-long",
            "-D",
            "-N",
            "-V",
            str(volume_id or "IMAGE_NEST_WIN")[:32],
            "-o",
            str(out_iso),
        ]
        if etfs.is_file():
            cmd += [
                "-b",
                "boot/etfsboot.com",
                "-no-emul-boot",
                "-boot-load-seg",
                "0x07C0",
                "-boot-load-size",
                "8",
            ]
        if efi_member:
            cmd += [
                "-eltorito-alt-boot",
                "-eltorito-boot",
                efi_member,
                "-no-emul-boot",
                "-efi-boot",
                efi_member,
            ]
        cmd.append(str(tree))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        if proc.returncode != 0 or not out_iso.is_file():
            return {
                "ok": False,
                "error": f"xorriso mkisofs failed: {(proc.stderr or proc.stdout or '')[:500]}",
            }
        return {"ok": True, "path": str(out_iso), "bytes": out_iso.stat().st_size, "method": "tree_rebuild"}

    def _repack_windows_iso(
        self,
        *,
        source_iso: Path,
        install_wim: Path,
        out_iso: Path,
        work: Path,
    ) -> dict[str, Any]:
        """Replace install.wim inside a Windows ISO; replay first, tree rebuild fallback."""
        xorriso = shutil.which("xorriso")
        seven = shutil.which("7z") or shutil.which("7zz") or ""
        if not xorriso:
            return {"ok": False, "error": "xorriso missing — install xorriso on controller"}
        if not source_iso.is_file() or not install_wim.is_file():
            return {"ok": False, "error": "source ISO or install.wim missing"}
        work.mkdir(parents=True, exist_ok=True)
        if out_iso.exists():
            out_iso.unlink()
        wim_member = self._iso_wim_member(source_iso)
        iso_rr_path = f"/{wim_member}"
        cmd = [
            xorriso,
            "-abort_on",
            "FATAL",
            "-indev",
            str(source_iso),
            "-outdev",
            str(out_iso),
            "-boot_image",
            "any",
            "replay",
            "-overwrite",
            "on",
            "-map",
            str(install_wim),
            iso_rr_path,
            "-commit",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        if proc.returncode == 0 and out_iso.is_file():
            return {
                "ok": True,
                "path": str(out_iso),
                "bytes": out_iso.stat().st_size,
                "wim_member": wim_member,
                "method": "xorriso_replay",
            }

        replay_err = (proc.stderr or proc.stdout or "xorriso replay failed")[:400]
        if not seven:
            return {"ok": False, "error": f"xorriso repack failed: {replay_err}"}

        tree = work / "iso-tree"
        if tree.exists():
            shutil.rmtree(tree, ignore_errors=True)
        tree.mkdir(parents=True, exist_ok=True)
        ex = subprocess.run(
            [seven, "x", "-y", f"-o{tree}", str(source_iso)],
            capture_output=True,
            text=True,
            timeout=3600,
        )
        if ex.returncode != 0:
            return {
                "ok": False,
                "error": f"xorriso repack failed: {replay_err}; 7z extract failed: {(ex.stderr or ex.stdout or '')[:200]}",
            }
        vol_id = self._iso_volume_id(source_iso, xorriso=xorriso)
        # Reclaim ISO cache space before mkisofs — upload remains registered; user can re-upload if needed.
        try:
            if str(source_iso.resolve()).startswith(str(self.iso_cache.resolve())):
                source_iso.unlink()
        except OSError:
            pass
        dest_wim = tree / Path(wim_member)
        dest_wim.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(install_wim), str(dest_wim))
        rebuilt = self._rebuild_windows_iso_from_tree(tree, out_iso, volume_id=vol_id)
        if not rebuilt.get("ok"):
            return {
                "ok": False,
                "error": f"xorriso repack failed: {replay_err}; tree rebuild: {rebuilt.get('error')}",
            }
        rebuilt["wim_member"] = wim_member
        return rebuilt

    def _bank_iso_copy(self, *, iso_path: Path, image_name: str) -> dict[str, Any]:
        """Copy uploaded ISO into image-bank for bare-metal / full banking."""
        banked = self.image_bank / f"{image_name}.iso"
        if banked.exists():
            banked.unlink()
        shutil.copy2(iso_path, banked)
        return {
            "ok": True,
            "banked_iso_path": str(banked),
            "iso_path": str(banked),
            "path": str(banked),
            "bytes": banked.stat().st_size,
        }

    def _wim_apply_deletes(
        self,
        *,
        wim_bin: str,
        wim_path: Path,
        image_index: int,
        paths: list[str],
        work: Path,
    ) -> dict[str, Any]:
        """Apply recursive deletes via wimlib command-file on stdin (not --command=@file)."""
        removed: list[str] = []
        errors: list[str] = []
        if not paths:
            return {"ok": True, "removed": [], "errors": []}

        def _run_cmdfile(cmd_lines: list[str]) -> subprocess.CompletedProcess[str]:
            cmd_file = work / f"strip-{uuid.uuid4().hex[:8]}.cmd"
            # wimlib accepts both quote styles; paths use forward slashes.
            body = "\n".join(cmd_lines) + "\n"
            cmd_file.write_text(body, encoding="utf-8")
            with cmd_file.open("r", encoding="utf-8") as stdin_fh:
                return subprocess.run(
                    [wim_bin, "update", str(wim_path), str(image_index)],
                    stdin=stdin_fh,
                    capture_output=True,
                    text=True,
                    timeout=900,
                )

        batch_lines = [f'delete --force --recursive "{p}"' for p in paths]
        upd = _run_cmdfile(batch_lines)
        if upd.returncode == 0:
            return {"ok": True, "removed": list(paths), "errors": [], "detail": (upd.stdout or "")[:400]}

        errors.append(f"batch failed: {(upd.stderr or upd.stdout or '')[:400]}")
        for path in paths:
            one = _run_cmdfile([f'delete --force --recursive "{path}"'])
            if one.returncode == 0:
                removed.append(path)
            else:
                errors.append(f"{path}: {(one.stderr or one.stdout or '')[:160]}")
        return {
            "ok": len(removed) == len(paths),
            "removed": removed,
            "errors": errors,
        }

    def _offline_windows_bare_metal_iso(
        self,
        *,
        job_id: str,
        iso_path: Path,
        flavor: str,
        wim_index: int,
        image_name: str,
        strip_paths: list[str] | None = None,
        strip_labels: list[str] | None = None,
        iso_id: str = "",
        os_family: str = "",
    ) -> dict[str, Any]:
        """Strip install.wim inside an extracted ISO tree and rebuild a bootable ISO (disk-efficient)."""
        tools = self.tool_status()
        wim_bin = tools.get("wimlib_imagex") or ""
        seven = tools.get("seven_z") or ""
        xorriso = tools.get("xorriso") or ""
        if not (wim_bin and seven and xorriso):
            return {"ok": False, "error": "bare-metal ISO requires wimlib-imagex, 7z, and xorriso"}

        work = self.jobs_dir / f"bake-{job_id[:10]}"
        if work.exists():
            shutil.rmtree(work, ignore_errors=True)
        work.mkdir(parents=True, exist_ok=True)
        tree = work / "iso-tree"
        notes: list[str] = []
        iso_size = int(iso_path.stat().st_size) if iso_path.is_file() else 0
        free = int(shutil.disk_usage(self.root).free)
        if free < iso_size * 2 + 512 * 1024**2:
            return {
                "ok": False,
                "error": (
                    f"insufficient disk for bare-metal ISO rebuild "
                    f"({_fmt_disk_bytes(free)} free; need ~{_fmt_disk_bytes(iso_size * 2)})"
                ),
            }

        self._append_job_log(job_id, "Extracting ISO tree for bare-metal rebuild")
        ex = subprocess.run(
            [seven, "x", "-y", f"-o{tree}", str(iso_path)],
            capture_output=True,
            text=True,
            timeout=3600,
        )
        if ex.returncode != 0:
            return {
                "ok": False,
                "error": f"ISO tree extract failed: {(ex.stderr or ex.stdout or '')[:300]}",
                "notes": notes,
            }
        notes.append("extracted ISO tree via 7z")

        vol_id = self._iso_volume_id(iso_path, xorriso=xorriso)
        wim_member = self._iso_wim_member(iso_path)
        try:
            if str(iso_path.resolve()).startswith(str(self.iso_cache.resolve())):
                iso_path.unlink()
                notes.append("reclaimed ISO cache space before mkisofs")
        except OSError:
            pass

        wim_src = tree / Path(wim_member)
        if not wim_src.is_file():
            return {"ok": False, "error": f"{wim_member} missing in extracted tree", "notes": notes}

        info = subprocess.run(
            [wim_bin, "info", str(wim_src)],
            capture_output=True,
            text=True,
            timeout=180,
        )
        info_text = info.stdout or ""
        detected = detect_os_media(
            filename=image_name,
            wim_info=info_text,
            source_meta={"os_family": os_family} if os_family else None,
        )
        family = str(detected.get("os_family") or os_family or "client")
        idx = int(wim_index or 0) or self._pick_wim_index(info_text, os_family=family)
        notes.append(f"selected_wim_index={idx}")

        before = subprocess.run(
            [wim_bin, "dir", str(wim_src), str(idx), "--path=/Program Files/WindowsApps"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        before_apps = before.stdout or ""
        before_pkgs = _windowsapps_package_names(before_apps)

        removed: list[str] = []
        expanded: list[str] = []
        strip_mode = "none"
        if flavor == "stripped":
            targets = list(strip_paths or [])
            self._append_job_log(
                job_id,
                f"Offline strip on WIM index {idx} ({len(targets)} catalog target(s), family={family})",
            )
            if not targets:
                strip_mode = "noop_empty_selection"
            else:
                expanded = _expand_wim_globs(targets, before_apps)
                if not expanded:
                    strip_mode = "noop_no_match"
                else:
                    strip_mode = "delete"
                    self._append_job_log(
                        job_id,
                        f"Applying {len(expanded)} concrete AppX delete(s) via wimlib stdin cmdfile",
                    )
                    result = self._wim_apply_deletes(
                        wim_bin=wim_bin,
                        wim_path=wim_src,
                        image_index=idx,
                        paths=expanded,
                        work=work,
                    )
                    removed = list(result.get("removed") or [])
                    if len(removed) < len(expanded):
                        return {
                            "ok": False,
                            "error": (
                                f"strip incomplete: deleted {len(removed)}/{len(expanded)} "
                                "matched AppX paths — refusing to bank a false stripped image"
                            ),
                            "notes": notes,
                            "removed": removed,
                            "os_family": family,
                            "wim_index": idx,
                        }

        after = subprocess.run(
            [wim_bin, "dir", str(wim_src), str(idx), "--path=/Program Files/WindowsApps"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        after_apps = after.stdout or ""
        after_pkgs = _windowsapps_package_names(after_apps)

        banked_iso = self.image_bank / f"{image_name}.iso"
        self._append_job_log(job_id, f"Rebuilding bootable ISO → {banked_iso.name}")
        rebuilt = self._rebuild_windows_iso_from_tree(tree, banked_iso, volume_id=vol_id)
        shutil.rmtree(work, ignore_errors=True)
        if not rebuilt.get("ok"):
            return {
                "ok": False,
                "error": str(rebuilt.get("error") or "ISO rebuild failed"),
                "notes": notes,
                "os_family": family,
                "wim_index": idx,
            }
        notes.append(f"banked ISO → {banked_iso.name} ({banked_iso.stat().st_size} bytes)")
        return {
            "ok": True,
            "banked_iso_path": str(banked_iso),
            "iso_path": str(banked_iso),
            "path": str(banked_iso),
            "wim_path": "",
            "wim_index": idx,
            "removed": removed,
            "expanded": expanded,
            "strip_mode": strip_mode,
            "os_family": family,
            "product": detected.get("product"),
            "before_packages": before_pkgs,
            "after_packages": after_pkgs,
            "before_apps": before_apps[:60000],
            "after_apps": after_apps[:60000],
            "notes": notes,
        }

    def _offline_wim_process(
        self,
        *,
        job_id: str,
        iso_path: Path,
        flavor: str,
        wim_index: int,
        image_name: str,
        strip_paths: list[str] | None = None,
        strip_labels: list[str] | None = None,
        iso_id: str = "",
        os_family: str = "",
        output_format: str = "wim",
    ) -> dict[str, Any]:
        """Extract WIM, optional strip deletes, bank WIM or repack bootable ISO."""
        tools = self.tool_status()
        wim_bin = tools.get("wimlib_imagex") or ""
        seven = tools.get("seven_z") or ""
        if not (wim_bin and seven):
            return {"ok": False, "error": "offline_wim requires wimlib-imagex and 7z"}

        if str(output_format or "wim").strip().lower() == "iso":
            return self._offline_windows_bare_metal_iso(
                job_id=job_id,
                iso_path=iso_path,
                flavor=flavor,
                wim_index=wim_index,
                image_name=image_name,
                strip_paths=strip_paths,
                strip_labels=strip_labels,
                iso_id=iso_id,
                os_family=os_family,
            )

        work = self.jobs_dir / f"bake-{job_id[:10]}"
        if work.exists():
            shutil.rmtree(work, ignore_errors=True)
        work.mkdir(parents=True, exist_ok=True)
        notes: list[str] = []
        banked: Path | None = None
        try:
            self._append_job_log(job_id, "Extracting install.wim/esd from ISO (offline)")
            wim_src, member = self._extract_install_wim(iso_path=iso_path, work=work, iso_id=iso_id)
            if not wim_src:
                return {"ok": False, "error": member, "notes": notes}
            notes.append(f"extracted {member}")

            info = subprocess.run(
                [wim_bin, "info", str(wim_src)],
                capture_output=True,
                text=True,
                timeout=180,
            )
            info_text = info.stdout or ""
            notes.append(info_text[:4000])
            detected = detect_os_media(
                filename=iso_path.name,
                wim_info=info_text,
                source_meta={"os_family": os_family} if os_family else None,
            )
            family = str(detected.get("os_family") or os_family or "client")
            notes.append(f"os_family={family} product={detected.get('product')}")
            idx = int(wim_index or 0) or self._pick_wim_index(info_text, os_family=family)
            notes.append(f"selected_wim_index={idx}")

            before = subprocess.run(
                [wim_bin, "dir", str(wim_src), str(idx), "--path=/Program Files/WindowsApps"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            before_apps = before.stdout or ""
            before_pkgs = _windowsapps_package_names(before_apps)
            notes.append(f"[before] WindowsApps packages={len(before_pkgs)} lines≈{before_apps.count(chr(10))}")

            removed: list[str] = []
            expanded: list[str] = []
            strip_mode = "none"
            if flavor == "stripped":
                targets = list(strip_paths or [])
                labels = list(strip_labels or [])
                self._append_job_log(
                    job_id,
                    f"Offline strip on WIM index {idx} ({len(targets)} catalog target(s), family={family})",
                )
                if not targets:
                    strip_mode = "noop_empty_selection"
                    notes.append("strip: no targets selected — banking WIM without AppX deletes")
                else:
                    expanded = _expand_wim_globs(targets, before_apps)
                    notes.append(
                        f"strip glob expand: catalog={len(targets)} matched_paths={len(expanded)}"
                    )
                    if not expanded:
                        strip_mode = "noop_no_match"
                        notes.append(
                            "strip: no matching AppX folders in this image "
                            "(common on Server Core / minimal editions) — banking unchanged WIM"
                        )
                    else:
                        strip_mode = "delete"
                        self._append_job_log(
                            job_id,
                            f"Applying {len(expanded)} concrete AppX delete(s) via wimlib stdin cmdfile",
                        )
                        result = self._wim_apply_deletes(
                            wim_bin=wim_bin,
                            wim_path=wim_src,
                            image_index=idx,
                            paths=expanded,
                            work=work,
                        )
                        removed = list(result.get("removed") or [])
                        for err in (result.get("errors") or [])[:20]:
                            notes.append(f"strip error: {err}")
                        for path in removed:
                            notes.append(f"removed: {path}")
                        for label in labels:
                            notes.append(f"selection: {label}")
                        notes.append(
                            f"strip removed_attempted={len(expanded)} removed_ok={len(removed)}"
                        )
                        if len(removed) < len(expanded):
                            return {
                                "ok": False,
                                "error": (
                                    f"strip incomplete: deleted {len(removed)}/{len(expanded)} "
                                    "matched AppX paths — refusing to bank a false stripped image"
                                ),
                                "notes": notes,
                                "before_apps": before_apps[:60000],
                                "after_apps": "",
                                "removed": removed,
                                "expanded": expanded,
                                "os_family": family,
                                "wim_index": idx,
                            }
            else:
                notes.append("full flavor — no offline AppX deletes")

            after = subprocess.run(
                [wim_bin, "dir", str(wim_src), str(idx), "--path=/Program Files/WindowsApps"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            after_apps = after.stdout or ""
            after_pkgs = _windowsapps_package_names(after_apps)
            notes.append(f"[after] WindowsApps packages={len(after_pkgs)}")

            # Verify deleted package roots are gone
            still_present = []
            removed_names = {Path(p).name.lower() for p in removed}
            after_names = {n.lower() for n in after_pkgs}
            for name in removed_names:
                if name in after_names:
                    still_present.append(name)
            if still_present:
                return {
                    "ok": False,
                    "error": (
                        "strip verification failed — packages still present after delete: "
                        + ", ".join(still_present[:8])
                    ),
                    "notes": notes,
                    "before_apps": before_apps[:60000],
                    "after_apps": after_apps[:60000],
                    "removed": removed,
                    "os_family": family,
                    "wim_index": idx,
                }
            if flavor == "stripped" and strip_mode == "delete":
                notes.append(
                    f"strip verified: removed {len(removed)} path(s); "
                    f"packages {len(before_pkgs)} → {len(after_pkgs)}"
                )

            out_fmt = str(output_format or "wim").strip().lower()
            if out_fmt == "iso":
                banked_iso = self.image_bank / f"{image_name}.iso"
                self._append_job_log(job_id, f"Repacking bootable ISO → {banked_iso.name}")
                repack = self._repack_windows_iso(
                    source_iso=iso_path,
                    install_wim=wim_src,
                    out_iso=banked_iso,
                    work=work / "repack",
                )
                if not repack.get("ok"):
                    return {
                        "ok": False,
                        "error": str(repack.get("error") or "ISO repack failed"),
                        "notes": notes,
                        "before_apps": before_apps[:60000],
                        "after_apps": after_apps[:60000],
                        "removed": removed,
                        "os_family": family,
                        "wim_index": idx,
                    }
                notes.append(
                    f"banked ISO → {banked_iso.name} ({banked_iso.stat().st_size} bytes) "
                    f"member={repack.get('wim_member')}"
                )
                return {
                    "ok": True,
                    "banked_iso_path": str(banked_iso),
                    "iso_path": str(banked_iso),
                    "path": str(banked_iso),
                    "wim_path": "",
                    "wim_index": idx,
                    "removed": removed,
                    "expanded": expanded,
                    "strip_mode": strip_mode,
                    "os_family": family,
                    "product": detected.get("product"),
                    "before_packages": before_pkgs,
                    "after_packages": after_pkgs,
                    "before_apps": before_apps[:60000],
                    "after_apps": after_apps[:60000],
                    "notes": notes,
                }

            banked = self.image_bank / f"{image_name}.wim"
            if banked.exists():
                banked.unlink()
            # Move (not copy) to avoid needing a second ~7GB free.
            shutil.move(str(wim_src), str(banked))
            notes.append(f"banked WIM → {banked.name} ({banked.stat().st_size} bytes)")

            return {
                "ok": True,
                "wim_path": str(banked),
                "wim_index": idx,
                "removed": removed,
                "expanded": expanded,
                "strip_mode": strip_mode,
                "os_family": family,
                "product": detected.get("product"),
                "before_packages": before_pkgs,
                "after_packages": after_pkgs,
                "before_apps": before_apps[:60000],
                "after_apps": after_apps[:60000],
                "notes": notes,
            }
        finally:
            # If banking moved the WIM out, work may only have cmd leftovers.
            if work.exists():
                shutil.rmtree(work, ignore_errors=True)

    def _write_deploy_manifest(self, *, image: dict[str, Any], flavor: str, extras: list[str]) -> str:
        name = str(image.get("deploy_manifest") or f"{image.get('name')}-deployed.txt")
        path = self.manifests / Path(name).name
        lines = [
            "=" * 72,
            f"IMAGE PACKAGE MANIFEST: {image.get('name')}",
            f"Flavor: {flavor}",
            f"Generated: {_iso_utc()}",
            f"Source ISO id: {image.get('iso_id')}",
            "=" * 72,
            "",
            "[Controller processing intent]",
        ]
        if flavor == "stripped":
            lines += [
                "- Strip profile selected (telemetry / bloatware reduction intent)",
                "- VirtIO storage drivers planned for injection when KVM bake runs",
                "- Autounattend profile: profiles/stripped_unattend.xml",
                "- Strip catalog: profiles/strip-catalog.json",
            ]
            strip_labels = image.get("strip_labels") if isinstance(image.get("strip_labels"), list) else []
            strip_ids = image.get("strip_option_ids") if isinstance(image.get("strip_option_ids"), list) else []
            if strip_labels:
                lines.append("")
                lines.append("[Strip selections applied]")
                for label in strip_labels:
                    lines.append(f"  - {label}")
            elif strip_ids:
                lines.append("")
                lines.append("[Strip option ids applied]")
                for opt_id in strip_ids:
                    lines.append(f"  - {opt_id}")
            else:
                lines.append("")
                lines.append("[Strip selections applied]")
                lines.append("  - (none — WIM banked without AppX deletes)")
        else:
            lines += [
                "- Full deploy profile selected",
                "- Standard Windows UI retained",
                "- Optional tooling profile (VSCode/Git/Chrome/Python) planned for later bake stages",
                "- Autounattend profile: profiles/full_unattend.xml",
            ]
        lines.append("")
        lines.append("[Build log excerpts]")
        lines.extend(extras[:80])
        lines.append("")
        lines.append("[Hypervisor Storage Drivers Status]")
        lines.append("Driver Name      : viostor.inf (VirtIO Block Driver)")
        lines.append(
            "Status           : "
            + (
                "Injected by Controller Loop"
                if image.get("status") == "ready"
                else "Pending / Missing from Base Media (to be injected by Controller Loop)"
            )
        )
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return Path(name).name

    def _run_build_job(self, job_id: str) -> None:
        job = self.get_job(job_id)
        if not job:
            return
        if str(job.get("status") or "") not in {"queued"}:
            return
        image_id = str(job.get("image_id") or "")
        image = self.get_image(image_id)
        if not image:
            self._update_job(job_id, status="failed", error="image row missing")
            return

        self._update_job(job_id, status="running")
        self._append_job_log(job_id, f"Build started flavor={image.get('flavor')}")
        extras: list[str] = []
        tools = self.tool_status()
        flavor = str(image.get("flavor") or "full")
        deploy_target = self._normalize_deploy_target(image.get("deploy_target") or "") or "hypervisor"
        extras.append(f"deploy_target={deploy_target}")
        iso = self.get_iso(str(image.get("iso_id") or ""))
        iso_path = Path(str((iso or {}).get("path") or ""))
        qcow = Path(str(image.get("qcow2_path") or ""))
        disk_gb = int(image.get("disk_gb") or 60)

        try:
            # Base manifest is generated after upload (background). Do not re-extract install.wim
            # here — that duplicates work and can fill the disk before the actual bake runs.
            base_name = str(image.get("base_manifest") or "")
            iso_base = str((iso or {}).get("base_manifest") or "")
            if iso_base and (not base_name or not (self.manifests / Path(base_name).name).is_file()):
                base_name = iso_base
                state = self._load()
                img = state["images"].get(image_id)
                if isinstance(img, dict):
                    img["base_manifest"] = base_name
                    state["images"][image_id] = img
                    self._save(state)
                extras.append(f"reused ISO base manifest {base_name}")

            qemu = tools.get("qemu_img") or ""
            virt = tools.get("virt_install") or ""
            bake_mode = str(tools.get("bake_mode") or "catalog_only")
            unattend_cfg = image.get("unattend") if isinstance(image.get("unattend"), dict) else {}
            profile = self.write_job_unattend(
                job_id=job_id, flavor=flavor, unattend=unattend_cfg
            )
            wim_path = ""
            export_format = str(
                image.get("export_format")
                or self._deploy_target_meta(deploy_target).get("export_format")
                or ""
            )
            wants_bootable = deploy_target in {"bootable_disk", "hyperv", "vmware"}
            extras.append(f"bake_mode={bake_mode}")
            extras.append(
                "OpenTofu is not installed or executed on this controller; "
                "Hayabusa Craft applies hand-off tfvars."
            )

            # Primary path: Linux squashfs strip / bank, or Windows offline WIM.
            platform = str(image.get("platform") or (iso or {}).get("platform") or "")
            if not platform:
                platform = str(
                    detect_os_media(
                        filename=str(image.get("iso_filename") or ""),
                        label=str(image.get("name") or ""),
                    ).get("platform")
                    or "windows"
                )
            banked_iso_path = ""
            wim_output = "iso" if deploy_target == "bare_metal" else "wim"
            if platform == "linux" and iso_path.is_file():
                family = "linux"
                concrete = (
                    image.get("strip_packages")
                    if isinstance(image.get("strip_packages"), list)
                    else None
                )
                if concrete is not None:
                    globs = [str(x) for x in concrete if str(x).strip()]
                    strip_labels = list(image.get("strip_labels") or globs)
                else:
                    strip_sel = self.resolve_strip_selection(
                        image.get("strip_option_ids")
                        if isinstance(image.get("strip_option_ids"), list)
                        else None,
                        flavor=flavor,
                        os_family="linux",
                    )
                    globs = list(
                        image.get("strip_package_globs")
                        or strip_sel.get("package_globs")
                        or []
                    )
                    strip_labels = list(image.get("strip_labels") or strip_sel.get("labels") or [])
                work = self.jobs_dir / f"bake-linux-{job_id[:10]}"
                seven = tools.get("seven_z") or ""
                self._append_job_log(job_id, f"Linux offline process flavor={flavor}")
                offline = _linux.offline_linux_process(
                    iso_path=iso_path,
                    work=work,
                    image_bank=self.image_bank,
                    image_name=str(image.get("name") or image_id),
                    flavor=flavor,
                    package_globs=globs,
                    strip_labels=strip_labels,
                    seven_z=seven,
                    log_cb=lambda m: self._append_job_log(job_id, m),
                )
                extras.extend(list(offline.get("notes") or [])[:60])
                if offline.get("before_packages"):
                    extras.append(
                        "[before packages] " + ", ".join(list(offline.get("before_packages") or [])[:40])
                    )
                if offline.get("after_packages"):
                    extras.append(
                        "[after packages] " + ", ".join(list(offline.get("after_packages") or [])[:40])
                    )
                if not offline.get("ok"):
                    raise RuntimeError(str(offline.get("error") or "linux offline process failed"))
                banked_iso_path = str(offline.get("banked_iso_path") or "")
                state = self._load()
                img = state["images"].get(image_id)
                if isinstance(img, dict):
                    img["platform"] = "linux"
                    img["os_family"] = "linux"
                    img["strip_mode"] = offline.get("strip_mode") or ""
                    img["strip_removed_paths"] = list(offline.get("removed") or [])
                    img["strip_removed_count"] = len(offline.get("removed") or [])
                    img["strip_verified"] = True
                    img["before_package_count"] = len(offline.get("before_packages") or [])
                    img["after_package_count"] = len(offline.get("after_packages") or [])
                    if banked_iso_path:
                        img["banked_iso_path"] = banked_iso_path
                        img["iso_path"] = banked_iso_path
                        img["path"] = banked_iso_path
                        bp = Path(banked_iso_path)
                        if bp.is_file():
                            img["bytes"] = bp.stat().st_size
                    state["images"][image_id] = img
                    self._save(state)
                    image = img
                status = "ready_iso_stripped" if flavor == "stripped" else "ready_iso_full"
            elif (
                deploy_target == "bare_metal"
                and platform == "windows"
                and flavor == "full"
                and iso_path.is_file()
            ):
                self._append_job_log(job_id, "Bare-metal full — banking bootable ISO copy")
                copied = self._bank_iso_copy(iso_path=iso_path, image_name=str(image.get("name") or image_id))
                if not copied.get("ok"):
                    raise RuntimeError(str(copied.get("error") or "ISO copy failed"))
                banked_iso_path = str(copied.get("banked_iso_path") or "")
                extras.append(f"banked ISO copy → {Path(banked_iso_path).name}")
                state = self._load()
                img = state["images"].get(image_id)
                if isinstance(img, dict):
                    img["platform"] = "windows"
                    img["strip_mode"] = "full_copy"
                    if banked_iso_path:
                        img["banked_iso_path"] = banked_iso_path
                        img["iso_path"] = banked_iso_path
                        img["path"] = banked_iso_path
                        bp = Path(banked_iso_path)
                        if bp.is_file():
                            img["bytes"] = bp.stat().st_size
                    state["images"][image_id] = img
                    self._save(state)
                    image = img
                status = "ready_iso"
            elif bake_mode == "offline_wim" and iso_path.is_file():
                family = str(image.get("os_family") or "")
                concrete = (
                    image.get("strip_packages")
                    if isinstance(image.get("strip_packages"), list)
                    else None
                )
                if concrete is not None:
                    strip_paths = [str(x) for x in concrete if str(x).strip()]
                    strip_labels = list(image.get("strip_labels") or strip_paths)
                else:
                    strip_sel = self.resolve_strip_selection(
                        image.get("strip_option_ids")
                        if isinstance(image.get("strip_option_ids"), list)
                        else None,
                        flavor=flavor,
                        os_family=family,
                    )
                    strip_paths = list(
                        image.get("strip_paths") or strip_sel.get("paths") or []
                    )
                    strip_labels = list(image.get("strip_labels") or strip_sel.get("labels") or [])
                offline = self._offline_wim_process(
                    job_id=job_id,
                    iso_path=iso_path,
                    flavor=flavor,
                    wim_index=int(image.get("wim_index") or 0),
                    image_name=str(image.get("name") or image_id),
                    strip_paths=strip_paths,
                    strip_labels=strip_labels,
                    iso_id=str(image.get("iso_id") or ""),
                    os_family=family,
                    output_format=wim_output,
                )
                extras.extend(list(offline.get("notes") or [])[:60])
                if offline.get("before_packages"):
                    extras.append(
                        "[before packages] " + ", ".join(list(offline.get("before_packages") or [])[:40])
                    )
                if offline.get("after_packages"):
                    extras.append(
                        "[after packages] " + ", ".join(list(offline.get("after_packages") or [])[:40])
                    )
                if offline.get("before_apps"):
                    extras.append("[before WindowsApps excerpt]")
                    extras.extend(str(offline.get("before_apps") or "").splitlines()[:20])
                if offline.get("after_apps"):
                    extras.append("[after WindowsApps excerpt]")
                    extras.extend(str(offline.get("after_apps") or "").splitlines()[:20])
                if not offline.get("ok"):
                    raise RuntimeError(str(offline.get("error") or "offline WIM process failed"))
                wim_path = str(offline.get("wim_path") or "")
                banked_iso_path = str(offline.get("banked_iso_path") or banked_iso_path)
                # Persist verification onto image row mid-job
                state = self._load()
                img = state["images"].get(image_id)
                if isinstance(img, dict):
                    img["os_family"] = offline.get("os_family") or img.get("os_family") or family
                    img["os_product"] = offline.get("product") or img.get("os_product")
                    img["wim_index"] = offline.get("wim_index") or img.get("wim_index")
                    img["strip_mode"] = offline.get("strip_mode") or ""
                    img["strip_removed_paths"] = list(offline.get("removed") or [])
                    img["strip_removed_count"] = len(offline.get("removed") or [])
                    img["strip_verified"] = bool(
                        flavor != "stripped"
                        or offline.get("strip_mode") in {"noop_empty_selection", "noop_no_match", "delete", "none"}
                    )
                    if flavor == "stripped" and offline.get("strip_mode") == "delete":
                        img["strip_verified"] = True
                    img["before_package_count"] = len(offline.get("before_packages") or [])
                    img["after_package_count"] = len(offline.get("after_packages") or [])
                    if banked_iso_path:
                        img["banked_iso_path"] = banked_iso_path
                        img["iso_path"] = banked_iso_path
                        img["path"] = banked_iso_path
                        bp = Path(banked_iso_path)
                        if bp.is_file():
                            img["bytes"] = bp.stat().st_size
                    if wim_path:
                        img["wim_path"] = wim_path
                        wp = Path(wim_path)
                        if wp.is_file():
                            img["wim_bytes"] = wp.stat().st_size
                    state["images"][image_id] = img
                    self._save(state)
                    image = img
                if deploy_target == "bare_metal":
                    status = "ready_iso_stripped" if flavor == "stripped" else "ready_iso"
                else:
                    status = "ready_wim_stripped" if flavor == "stripped" else "ready_wim"
            else:
                status = "cataloged"

            if deploy_target != "bare_metal" and qemu:
                self._append_job_log(job_id, f"Creating qcow2 disk {qcow.name} ({disk_gb}G)")
                proc = subprocess.run(
                    [qemu, "create", "-f", "qcow2", str(qcow), f"{disk_gb}G"],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                extras.append((proc.stdout or proc.stderr or "")[:500])
                if proc.returncode != 0:
                    raise RuntimeError(f"qemu-img failed: {(proc.stderr or proc.stdout or '')[:300]}")
                # Linux Hyper-V / VMware: also create native empty disk stubs next to the ISO.
                if platform == "linux" and export_format in {"vhdx", "vmdk"}:
                    disk_out = Path(str(image.get("disk_path") or ""))
                    if not disk_out.name:
                        disk_out = self.image_bank / f"{image.get('name') or image_id}.{export_format}"
                    self._append_job_log(
                        job_id, f"Creating empty {export_format} stub {disk_out.name} ({disk_gb}G)"
                    )
                    proc2 = subprocess.run(
                        [qemu, "create", "-f", export_format, str(disk_out), f"{disk_gb}G"],
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    extras.append((proc2.stdout or proc2.stderr or "")[:500])
                    if proc2.returncode != 0:
                        raise RuntimeError(
                            f"qemu-img {export_format} create failed: "
                            f"{(proc2.stderr or proc2.stdout or '')[:300]}"
                        )
                    state = self._load()
                    img = state["images"].get(image_id)
                    if isinstance(img, dict):
                        img["disk_path"] = str(disk_out)
                        if export_format == "vhdx":
                            img["vhdx_path"] = str(disk_out)
                        if export_format == "vmdk":
                            img["vmdk_path"] = str(disk_out)
                        state["images"][image_id] = img
                        self._save(state)
                        image = img
                    status = (
                        ("ready_iso_stripped" if flavor == "stripped" else "ready_iso")
                        + f"+{export_format}_stub"
                    )
                elif status.startswith("ready_wim"):
                    status = status + "+disk_stub"
                elif status.startswith("ready_iso"):
                    status = status + "+disk_stub"
                elif status == "cataloged":
                    status = "ready_disk_stub"
            else:
                if deploy_target == "bare_metal":
                    self._append_job_log(job_id, "Bare-metal target — skipping disk stub")
                    extras.append("bare_metal: no disk stub")
                else:
                    self._append_job_log(job_id, "qemu-img not installed — skipping disk stub")
                    extras.append("qemu-img missing; skipped disk create")

            # Windows bootable / Hyper-V / VMware: virt-install into qcow2 (requires KVM).
            # Linux: skip unattended virt-install (no kickstart/autoinstall yet); ISO + stub is the artifact.
            run_virt = (
                wants_bootable
                and platform != "linux"
                and bool(qemu)
                and bool(virt)
                and iso_path.is_file()
                and qcow.is_file()
            )
            # Legacy optional path: hypervisor target may still try virt-install when tools exist.
            if (
                not run_virt
                and deploy_target == "hypervisor"
                and platform != "linux"
                and qemu
                and virt
                and iso_path.is_file()
                and qcow.is_file()
            ):
                run_virt = True
            if wants_bootable and platform != "linux" and not run_virt:
                raise RuntimeError(
                    "Bootable Windows disk requires qemu-img + virt-install on the controller"
                )
            if run_virt:
                name = f"image-factory-{image_id}"
                self._append_job_log(job_id, f"Starting virt-install {name} (unattend={profile.name})")
                cmd = [
                    virt,
                    "--name",
                    name,
                    "--memory",
                    "4096",
                    "--vcpus",
                    "2",
                    "--disk",
                    f"path={qcow},bus=virtio,format=qcow2",
                    "--cdrom",
                    str(iso_path),
                    "--disk",
                    f"path={profile},device=floppy",
                    "--boot",
                    "uefi",
                    "--graphics",
                    "none",
                    "--noautoconsole",
                    "--wait",
                    "-1",
                ]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=6 * 3600)
                extras.append((proc.stdout or "")[-2000:])
                extras.append((proc.stderr or "")[-2000:])
                subprocess.run(["virsh", "destroy", name], capture_output=True, timeout=30)
                subprocess.run(["virsh", "undefine", name, "--nvram"], capture_output=True, timeout=30)
                if proc.returncode != 0:
                    raise RuntimeError(f"virt-install failed rc={proc.returncode}")
                status = "ready"
                # Convert bootable qcow2 → VHDX/VMDK when requested.
                if export_format in {"vhdx", "vmdk"} and qcow.is_file():
                    disk_out = Path(str(image.get("disk_path") or ""))
                    if not disk_out.name:
                        disk_out = self.image_bank / f"{image.get('name') or image_id}.{export_format}"
                    self._append_job_log(job_id, f"Converting qcow2 → {export_format} ({disk_out.name})")
                    proc_c = subprocess.run(
                        [qemu, "convert", "-O", export_format, str(qcow), str(disk_out)],
                        capture_output=True,
                        text=True,
                        timeout=3600,
                    )
                    extras.append((proc_c.stdout or proc_c.stderr or "")[:500])
                    if proc_c.returncode != 0 or not disk_out.is_file():
                        raise RuntimeError(
                            f"qemu-img convert to {export_format} failed: "
                            f"{(proc_c.stderr or proc_c.stdout or '')[:300]}"
                        )
                    state = self._load()
                    img = state["images"].get(image_id)
                    if isinstance(img, dict):
                        img["disk_path"] = str(disk_out)
                        img["disk_format"] = export_format
                        if export_format == "vhdx":
                            img["vhdx_path"] = str(disk_out)
                        if export_format == "vmdk":
                            img["vmdk_path"] = str(disk_out)
                        img["bytes"] = disk_out.stat().st_size
                        state["images"][image_id] = img
                        self._save(state)
                        image = img
                    status = f"ready_{export_format}"

            if status == "cataloged":
                extras.append(
                    "Manifest-only catalog entry. Install wimtools + p7zip-full (offline WIM) "
                    "or qemu-utils for richer bake outputs."
                )

            deploy_name = self._write_deploy_manifest(image=image, flavor=flavor, extras=extras)
            state = self._load()
            img = state["images"].get(image_id)
            if isinstance(img, dict):
                img["status"] = status
                img["deploy_manifest"] = deploy_name
                img["error"] = ""
                img["bake_mode"] = bake_mode
                if wim_path:
                    img["wim_path"] = wim_path
                    wp = Path(wim_path)
                    if wp.is_file():
                        img["wim_bytes"] = wp.stat().st_size
                banked_iso = str(image.get("banked_iso_path") or banked_iso_path or "")
                if banked_iso:
                    img["banked_iso_path"] = banked_iso
                    img["iso_path"] = banked_iso
                    img["path"] = banked_iso
                    bp = Path(banked_iso)
                    if bp.is_file():
                        img["bytes"] = bp.stat().st_size
                if qcow.is_file():
                    img["qcow2_bytes"] = qcow.stat().st_size
                img["core_manifest"] = (
                    "No Telemetry intent · offline bloatware strip · VirtIO planned · tofu via Hayabusa"
                    if flavor == "stripped"
                    else "Standard UI · offline WIM banked · VirtIO planned · tofu via Hayabusa"
                )
                state["images"][image_id] = img
                self._save(state)
                try:
                    self._register_image_ref(img)
                except Exception as exc:  # noqa: BLE001
                    self._append_job_log(job_id, f"registry warn: {exc}")
            self._update_job(job_id, status="completed" if status != "failed" else "failed")
            self._append_job_log(job_id, f"Finished status={status}")
        except Exception as exc:  # noqa: BLE001
            self._append_job_log(job_id, f"ERROR: {exc}")
            try:
                self._write_deploy_manifest(image=image, flavor=flavor, extras=extras + [str(exc)])
            except Exception:
                pass
            self._update_job(job_id, status="failed", error=str(exc)[:400])
