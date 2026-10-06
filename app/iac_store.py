"""Ansible and OpenTofu configuration file storage."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .config import Settings

ALLOWED_ROOTS = ("ansible", "opentofu")
MAX_FILE_BYTES = 2 * 1024 * 1024


class IacStore:
    def __init__(self, settings: Settings) -> None:
        self.roots = {
            "ansible": settings.ansible_dir,
            "opentofu": settings.opentofu_dir,
        }
        for root in self.roots.values():
            root.mkdir(parents=True, exist_ok=True)
            readme = root / "README.md"
            if not readme.is_file():
                label = "Ansible" if root == settings.ansible_dir else "OpenTofu"
                readme.write_text(
                    f"# {label} configurations\n\n"
                    "Files stored on this Hayabusa Controller are local to the appliance.\n"
                    "Sync or apply them through the controller after you are authenticated "
                    "and connected to your Hayabusa VPN mesh.\n",
                    encoding="utf-8",
                )

    def _resolve(self, kind: str, rel: str) -> Path:
        if kind not in self.roots:
            raise ValueError("kind must be ansible or opentofu")
        rel = (rel or "").replace("\\", "/").lstrip("/")
        if not rel or ".." in rel.split("/"):
            raise ValueError("invalid path")
        root = self.roots[kind].resolve()
        path = (root / rel).resolve()
        if root != path and root not in path.parents:
            raise ValueError("path escapes store")
        return path

    def list_tree(self, kind: str) -> list[dict[str, Any]]:
        root = self.roots[kind].resolve()
        out: list[dict[str, Any]] = []
        if not root.is_dir():
            return out
        for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
            for name in sorted(filenames):
                p = Path(dirpath) / name
                try:
                    if p.is_symlink() and not p.exists():
                        continue
                    st = p.stat()
                except OSError:
                    continue
                rel = str(p.relative_to(root)).replace("\\", "/")
                out.append({"path": rel, "size": st.st_size})
        return out

    def read_text(self, kind: str, rel: str) -> str:
        path = self._resolve(kind, rel)
        if not path.is_file():
            raise FileNotFoundError(rel)
        data = path.read_bytes()
        if len(data) > MAX_FILE_BYTES:
            raise ValueError("file too large")
        return data.decode("utf-8")

    def write_text(self, kind: str, rel: str, content: str) -> dict[str, Any]:
        path = self._resolve(kind, rel)
        raw = (content or "").encode("utf-8")
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError("file too large")
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(raw)
        os.chmod(tmp, 0o600)
        tmp.replace(path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return {"path": rel, "size": len(raw)}

    def delete(self, kind: str, rel: str) -> bool:
        path = self._resolve(kind, rel)
        if not path.is_file():
            return False
        path.unlink()
        return True

    def status(self) -> dict[str, Any]:
        return {
            "ansible": {"files": len(self.list_tree("ansible")), "root": str(self.roots["ansible"])},
            "opentofu": {"files": len(self.list_tree("opentofu")), "root": str(self.roots["opentofu"])},
        }
