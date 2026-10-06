"""Hayabusa-compatible /api/devops-iac workspace (exact tree layout)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 2 * 1024 * 1024

# Top-level names that belong only under Ansible/ in the Hayabusa master tree.
# If they appear at workspace root (legacy flatten), remove after sync.
_LEGACY_TOP_LEVEL_ANSIBLE_CHILDREN = frozenset(
    {
        "ansible",  # lowercase stub from older controller IacStore
        "bare-metal-ztp",
        "IoT Devices",
        "openPLC",
        "residential-routers-and-switches",
        "residential-routers-and-switches-apis",
        "SCADA & PLC",
        "ztp",
    }
)


class DevopsIacWorkspace:
    def __init__(self, root: Path, defaults: Path | None = None) -> None:
        self.root = root
        self.defaults = defaults
        self.root.mkdir(parents=True, exist_ok=True)

    def seed_from_defaults(self, force: bool = False) -> int:
        """
        Sync workspace to Hayabusa devops_iac_defaults layout.

        Hayabusa is master: Ansible/, OpenTofu/, and README.txt are updated from
        packaged defaults. User-created top-level projects (e.g. my-tofu-project)
        are left alone. Misplaced legacy top-level clones of Ansible children are
        pruned when the same name exists under Ansible/.
        """
        if not self.defaults or not self.defaults.is_dir():
            return 0
        marker = self.root / ".hayabusa_defaults_seeded"
        # Restore missing packaged files only. Never delete or overwrite user work.
        self._sync_master_defaults(delete=False, ignore_existing=True)
        self._prune_legacy_top_level()
        marker.write_text(f"seeded={int(time.time())}\n", encoding="utf-8")
        return 1

    def _rsync_tree(self, src: Path, dst: Path, *, delete: bool = False, ignore_existing: bool = False) -> None:
        dst.mkdir(parents=True, exist_ok=True)
        if shutil.which("rsync"):
            cmd = ["rsync", "-a"]
            if ignore_existing:
                cmd.append("--ignore-existing")
            if delete:
                cmd.append("--delete")
            cmd.extend([f"{src}/", f"{dst}/"])
            subprocess.run(
                cmd,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return
        if delete and dst.exists():
            for child in list(dst.iterdir()):
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink(missing_ok=True)
        for item in src.iterdir():
            target = dst / item.name
            if item.is_dir():
                shutil.copytree(item, target, dirs_exist_ok=True)
            elif ignore_existing and target.exists():
                continue
            else:
                shutil.copy2(item, target)

    def _sync_master_defaults(self, *, delete: bool = False, ignore_existing: bool = False) -> None:
        assert self.defaults is not None
        for name in ("Ansible", "OpenTofu"):
            src = self.defaults / name
            if src.is_dir():
                self._rsync_tree(src, self.root / name, delete=delete, ignore_existing=ignore_existing)
        readme = self.defaults / "README.txt"
        if readme.is_file() and not (self.root / "README.txt").exists():
            shutil.copy2(readme, self.root / "README.txt")

    def _prune_legacy_top_level(self) -> None:
        """Remove workspace-root dirs that duplicate Hayabusa's Ansible/ children."""
        ansible = self.root / "Ansible"
        if not ansible.is_dir():
            return
        for name in _LEGACY_TOP_LEVEL_ANSIBLE_CHILDREN:
            top = self.root / name
            if not top.exists() or top.is_symlink():
                # Drop broken/legacy symlink or empty clash; skip unknown symlinks carefully
                if top.is_symlink():
                    try:
                        top.unlink()
                    except OSError:
                        pass
                continue
            # Only prune when Ansible already has this child (master layout present)
            if name == "ansible":
                # Always remove lowercase stub once Ansible/ exists
                if top.is_dir():
                    shutil.rmtree(top, ignore_errors=True)
                elif top.is_file():
                    top.unlink(missing_ok=True)
                continue
            if (ansible / name).exists() and top.is_dir():
                shutil.rmtree(top, ignore_errors=True)

    def _norm(self, rel: str) -> str:
        rel = (rel or "").replace("\\", "/").strip().lstrip("/")
        if rel in {".", "./"}:
            rel = ""
        parts = [p for p in rel.split("/") if p and p != "."]
        if any(p == ".." for p in parts):
            raise ValueError("invalid path")
        return "/".join(parts)

    def _abs(self, rel: str) -> Path:
        safe = self._norm(rel)
        root = self.root.resolve()
        path = (root / safe).resolve() if safe else root
        if root != path and root not in path.parents:
            raise ValueError("path escapes workspace")
        return path

    def is_packaged_default(self, rel: str) -> bool:
        """True if this relative path exists in the packaged default tree."""
        try:
            safe = self._norm(rel)
        except ValueError:
            return True
        if not safe or safe in {"Ansible", "OpenTofu", "README.txt", "README.md"}:
            return True
        if not self.defaults or not self.defaults.is_dir():
            return False
        try:
            src = (self.defaults / safe).resolve()
            root = self.defaults.resolve()
        except OSError:
            return True
        if src != root and root not in src.parents:
            return True
        return src.exists() or src.is_symlink()

    def refuse_default_mutation(self, rel: str, *, action: str = "delete") -> dict[str, Any] | None:
        try:
            safe = self._norm(rel)
        except ValueError as exc:
            return {"ok": False, "error": str(exc), "code": "invalid_path"}
        if self.is_packaged_default(safe):
            return {
                "ok": False,
                "error": f"cannot {action} packaged default playbook: {safe or '(workspace root)'}",
                "code": "protected_default",
                "path": safe,
            }
        try:
            path = self._abs(safe)
        except ValueError as exc:
            return {"ok": False, "error": str(exc), "code": "invalid_path"}
        if not path.is_dir():
            return None
        root = self.root.resolve()
        for dirpath, dirnames, filenames in os.walk(path):
            for name in list(dirnames) + list(filenames):
                child = Path(dirpath) / name
                try:
                    rel_child = str(child.resolve().relative_to(root)).replace("\\", "/")
                except ValueError:
                    continue
                if self.is_packaged_default(rel_child):
                    return {
                        "ok": False,
                        "error": (
                            f"cannot {action} folder {safe}: it contains packaged default "
                            f"playbooks (e.g. {rel_child})"
                        ),
                        "code": "protected_default",
                        "path": safe,
                    }
        return None

    def whoami(self, username: str = "controller") -> dict[str, Any]:
        self.seed_from_defaults()
        bm = (self.root / "Ansible" / "bare-metal-ztp").is_dir() or (
            self.root / "bare-metal-ztp"
        ).is_dir()
        return {
            "ok": True,
            "user_key": username,
            "workspace": str(self.root),
            "bare_metal_ztp_dir": bm,
            "context": "user",
            "org_id": None,
            "can_read": True,
            "can_write": True,
            "can_enqueue": False,
            "can_approve": False,
            "global_read_only": False,
            "tofu_project": "OpenTofu",
            "organizations": [],
            "opentofu_state_sync_interval_sec": 0,
        }

    def ls(self, rel: str = "") -> dict[str, Any]:
        self.seed_from_defaults()
        try:
            ab = self._abs(rel)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        if not ab.is_dir():
            return {"ok": False, "error": "Not a directory"}
        entries = []
        for name in sorted(os.listdir(ab)):
            p = ab / name
            try:
                st = p.stat()
                typ = "dir" if p.is_dir() else "file"
                entries.append(
                    {
                        "name": name,
                        "type": typ,
                        "size": 0 if typ == "dir" else int(st.st_size),
                        "mtime": int(st.st_mtime),
                        "safe": True,
                    }
                )
            except OSError:
                entries.append({"name": name, "type": "unknown", "size": 0, "mtime": None, "safe": False})
        return {
            "ok": True,
            "path": self._norm(rel),
            "context": "user",
            "org_id": None,
            "can_write": True,
            "entries": entries,
        }

    def read_file(self, rel: str) -> dict[str, Any]:
        try:
            path = self._abs(rel)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        if not path.is_file():
            return {"ok": False, "error": "not found"}
        data = path.read_bytes()
        if len(data) > MAX_FILE_BYTES:
            return {"ok": False, "error": "file too large"}
        try:
            content = data.decode("utf-8")
        except UnicodeDecodeError:
            return {"ok": False, "error": "binary file"}
        return {"ok": True, "path": self._norm(rel), "content": content}

    def write_file(self, rel: str, content: str) -> dict[str, Any]:
        try:
            path = self._abs(rel)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        raw = (content or "").encode("utf-8")
        if len(raw) > MAX_FILE_BYTES:
            return {"ok": False, "error": "file too large"}
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(raw)
        os.chmod(tmp, 0o600)
        tmp.replace(path)
        return {"ok": True, "path": self._norm(rel), "size": len(raw)}

    def import_sync(self, files: list[dict[str, str]], *, owner_id: str = "") -> dict[str, Any]:
        """Apply Hayabusa-pushed Ansible/OpenTofu files into this controller workspace."""
        self.seed_from_defaults()
        written = 0
        bytes_n = 0
        owner = (owner_id or "admin").strip() or "admin"
        for item in files[:250]:
            if not isinstance(item, dict):
                continue
            rel = self._norm(str(item.get("path") or ""))
            content = item.get("content")
            if not rel or not isinstance(content, str):
                continue
            low = rel.lower()
            if not low.startswith(("ansible/", "opentofu/")):
                continue
            out = self.write_file(rel, content)
            if not out.get("ok"):
                continue
            written += 1
            bytes_n += int(out.get("size") or 0)
        self._prune_legacy_top_level()
        return {
            "ok": True,
            "written": written,
            "bytes": bytes_n,
            "count": written,
            "owner_id": owner,
            "hayabusa_saw_secret_values": False,
        }

    def mkdir(self, rel: str) -> dict[str, Any]:
        try:
            path = self._abs(rel)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        path.mkdir(parents=True, exist_ok=True)
        return {"ok": True, "path": self._norm(rel)}

    def mv(self, src: str, dst: str) -> dict[str, Any]:
        blocked = self.refuse_default_mutation(src, action="rename")
        if blocked:
            return blocked
        try:
            a = self._abs(src)
            b = self._abs(dst)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        if not a.exists():
            return {"ok": False, "error": "source missing"}
        if b.exists():
            return {"ok": False, "error": "target already exists"}
        b.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(a), str(b))
        return {"ok": True, "from": self._norm(src), "to": self._norm(dst)}

    def rm(self, rel: str) -> dict[str, Any]:
        blocked = self.refuse_default_mutation(rel, action="delete")
        if blocked:
            return blocked
        try:
            path = self._abs(rel)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        if not path.exists():
            return {"ok": False, "error": "not found"}
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        return {"ok": True, "path": self._norm(rel)}

    def opentofu_state_summary(self) -> dict[str, Any]:
        cand, rel = self._find_tfstate()
        if not cand or not cand.is_file():
            return {
                "ok": True,
                "found": False,
                "message": "No terraform.tfstate found under OpenTofu",
                "workspace": str(self.root),
            }
        try:
            blob = json.loads(cand.read_text(encoding="utf-8", errors="replace"))
            n = len(blob.get("resources") or []) if isinstance(blob, dict) else 0
        except Exception:  # noqa: BLE001
            n = 0
        return {
            "ok": True,
            "found": True,
            "path": rel,
            "resources": n,
            "size": cand.stat().st_size,
            "workspace": str(self.root),
        }

    def _find_tfstate(self) -> tuple[Path | None, str | None]:
        base = self.root / "OpenTofu"
        direct = base / "terraform.tfstate"
        if direct.is_file():
            return direct, "OpenTofu/terraform.tfstate"
        if not base.is_dir():
            return None, None
        for dirpath, _, names in os.walk(base):
            if "terraform.tfstate" in names:
                cand = Path(dirpath) / "terraform.tfstate"
                try:
                    rel = str(cand.relative_to(self.root)).replace("\\", "/")
                except ValueError:
                    rel = "OpenTofu/terraform.tfstate"
                return cand, rel
        return None, None

    @staticmethod
    def _valid_ipv4(s: object) -> bool:
        if not isinstance(s, str):
            return False
        parts = s.strip().split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def _ip_from_attrs(self, attrs: dict[str, Any]) -> str | None:
        for k in (
            "private_ip",
            "public_ip",
            "access_ip_v4",
            "ipv4_address",
            "default_ip_address",
            "ip_address",
            "ipv4_addresses",
            "ip_addresses",
            "guest_ip_addresses",
        ):
            v = attrs.get(k)
            if isinstance(v, str) and self._valid_ipv4(v):
                return v.strip()
            if isinstance(v, list):
                for it in v:
                    if isinstance(it, str) and self._valid_ipv4(it):
                        return it.strip()
        for nk in ("network_interface", "network_interfaces", "network", "networks"):
            block = attrs.get(nk)
            items = block if isinstance(block, list) else ([block] if isinstance(block, dict) else [])
            for elem in items:
                if not isinstance(elem, dict):
                    continue
                for k in ("ip_address", "ipv4_address", "ipv4_addresses", "address"):
                    v = elem.get(k)
                    if isinstance(v, str) and self._valid_ipv4(v):
                        return v.strip()
                    if isinstance(v, list) and v and isinstance(v[0], str) and self._valid_ipv4(v[0]):
                        return str(v[0]).strip()
        return None

    def _hosts_from_tfstate(self, blob: dict[str, Any], *, max_rows: int = 500) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        resources = blob.get("resources")
        if not isinstance(resources, list):
            return out
        for res in resources:
            if not isinstance(res, dict) or res.get("mode") == "data":
                continue
            typ = str(res.get("type") or "")
            name = str(res.get("name") or "")
            module = str(res.get("module") or "")
            tl = typ.lower()
            instances = res.get("instances")
            if not isinstance(instances, list):
                continue
            for inst in instances:
                if len(out) >= max_rows:
                    return out
                if not isinstance(inst, dict):
                    continue
                attrs = inst.get("attributes")
                if not isinstance(attrs, dict):
                    continue
                ip_val = self._ip_from_attrs(attrs)
                show = bool(ip_val)
                if not show:
                    for hint in (
                        "instance",
                        "virtual_machine",
                        "proxmox_virtual_environment_vm",
                        "proxmox_vm",
                        "qemu",
                        "droplet",
                        "server",
                        "lxc_container",
                        "proxmox_virtual_environment_container",
                    ):
                        if hint in tl:
                            show = True
                            break
                if not show and (tl.endswith("_vm") or tl.endswith("_lxc") or tl.endswith("_container")):
                    show = True
                if not show:
                    continue
                disp = ""
                for k in ("name", "hostname", "computer_name"):
                    v = attrs.get(k)
                    if isinstance(v, str) and v.strip():
                        disp = v.strip()[:200]
                        break
                disp = disp or name
                idx = inst.get("index_key")
                if module:
                    addr = f"{module}.{typ}.{name}" if idx is None else f"{module}.{typ}.{name}[{idx}]"
                else:
                    addr = f"{typ}.{name}" if idx is None else f"{typ}.{name}[{idx}]"
                vmid = attrs.get("vm_id")
                if vmid is None and isinstance(attrs.get("id"), (int, str)) and str(attrs.get("id")).isdigit():
                    vmid = int(attrs["id"])
                elif isinstance(vmid, str) and vmid.isdigit():
                    vmid = int(vmid)
                row: dict[str, Any] = {
                    "ip": ip_val,
                    "name": disp or addr,
                    "source": "opentofu",
                    "tofu_address": addr,
                    "tofu_type": typ,
                    "vmid": vmid if isinstance(vmid, int) else None,
                }
                if "started" in attrs:
                    row["started"] = bool(attrs.get("started"))
                out.append(row)
        return out

    def _hosts_from_ansible(self, *, max_rows: int = 500) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        ansible = self.root / "Ansible"
        if not ansible.is_dir():
            return out
        skip_bits = (".example.", ".sample.", "example.yml", "example.yaml")
        for dirpath, dirnames, filenames in os.walk(ansible):
            dirnames[:] = [d for d in dirnames if d not in {".git", "__pycache__"}]
            for fn in filenames:
                low = fn.lower()
                if any(bit in low for bit in skip_bits):
                    continue
                if not (
                    low.endswith((".yml", ".yaml", ".ini", ".json"))
                    or low in {"hosts", "inventory"}
                    or "inventory" in low
                    or low.startswith("hosts")
                ):
                    continue
                path = Path(dirpath) / fn
                try:
                    if path.stat().st_size > 2_000_000:
                        continue
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                # JSON inventory with hostvars
                if low.endswith(".json") or text.lstrip().startswith("{"):
                    try:
                        blob = json.loads(text)
                    except Exception:  # noqa: BLE001
                        blob = None
                    if isinstance(blob, dict):
                        meta = blob.get("_meta") if isinstance(blob.get("_meta"), dict) else {}
                        hostvars = meta.get("hostvars") if isinstance(meta.get("hostvars"), dict) else {}
                        for hk, hv in hostvars.items():
                            if len(out) >= max_rows:
                                return out
                            if not isinstance(hv, dict):
                                continue
                            ip = str(hv.get("ansible_host") or "").strip()
                            if not self._valid_ipv4(ip):
                                continue
                            nm = hv.get("peregrine_tofu_display_name") or hk
                            out.append(
                                {
                                    "ip": ip,
                                    "name": str(nm).strip() or ip,
                                    "source": "ansible",
                                    "tofu_address": hv.get("peregrine_tofu_address"),
                                }
                            )
                        continue
                # INI-style [group] + bare IPs / host ansible_host=IP
                for line in text.splitlines():
                    if len(out) >= max_rows:
                        return out
                    s = line.strip()
                    if not s or s.startswith("#") or s.startswith(";") or s.startswith("["):
                        continue
                    # host ansible_host=1.2.3.4
                    if "ansible_host=" in s:
                        left = s.split(None, 1)[0]
                        for tok in s.split():
                            if tok.startswith("ansible_host="):
                                ip = tok.split("=", 1)[1].strip()
                                if self._valid_ipv4(ip):
                                    out.append({"ip": ip, "name": left or ip, "source": "ansible"})
                                break
                        continue
                    first = s.split()[0]
                    if self._valid_ipv4(first):
                        out.append({"ip": first, "name": first, "source": "ansible"})
        return out

    def inventory_summary(self, *, max_hosts: int = 500) -> dict[str, Any]:
        """Compact OpenTofu + Ansible inventory for Hayabusa map merge (no secret values)."""
        self.seed_from_defaults()
        hosts: list[dict[str, Any]] = []
        state_path = None
        state_mtime = None
        cand, rel = self._find_tfstate()
        if cand and cand.is_file():
            state_path = rel
            try:
                state_mtime = int(cand.stat().st_mtime)
                blob = json.loads(cand.read_text(encoding="utf-8", errors="replace"))
                if isinstance(blob, dict):
                    hosts.extend(self._hosts_from_tfstate(blob, max_rows=max_hosts))
            except Exception:  # noqa: BLE001
                pass
        if len(hosts) < max_hosts:
            hosts.extend(self._hosts_from_ansible(max_rows=max_hosts - len(hosts)))
        # Dedup by IP or tofu address / name
        seen: set[str] = set()
        uniq: list[dict[str, Any]] = []
        for h in hosts:
            ip = str(h.get("ip") or "").strip()
            key = ip or str(h.get("tofu_address") or h.get("name") or "").strip()
            if not key or key in seen:
                continue
            seen.add(key)
            uniq.append(h)
        return {
            "ok": True,
            "workspace": str(self.root),
            "generated_at": int(time.time()),
            "state_path": state_path,
            "state_mtime": state_mtime,
            "hosts": uniq[:max_hosts],
            "count": len(uniq[:max_hosts]),
        }
