"""Linux ISO support for Image Nest — inventory + offline squashfs strip.

Supports Debian/Ubuntu-style live ISOs (casper/live filesystem.squashfs) and
RPM media that ship a package pool. Bare-metal banking reuses the uploaded ISO;
hypervisor strip produces a banked ISO with selected packages removed from the
live rootfs when squashfs tools are available.
"""

from __future__ import annotations

import fnmatch
import re
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any

LINUX_DISTRO_HINTS: dict[str, tuple[str, ...]] = {
    "ubuntu": ("ubuntu", "ubuntu-"),
    "debian": ("debian", "debian-"),
    "rocky": ("rocky", "rocky-linux", "rockylinux"),
    "alma": ("almalinux", "alma-linux", "alma_linux"),
    "rhel": ("rhel", "red-hat", "redhat", "red_hat"),
    "centos": ("centos", "centos-stream"),
    "fedora": ("fedora",),
    "opensuse": ("opensuse", "openSUSE", "leap", "tumbleweed"),
    "arch": ("archlinux", "arch-linux"),
    "oracle": ("oraclelinux", "oracle-linux"),
}

LINUX_BLOB_HINTS = (
    "ubuntu",
    "debian",
    "rocky",
    "alma",
    "centos",
    "fedora",
    "rhel",
    "red hat",
    "redhat",
    "opensuse",
    "suse",
    "archlinux",
    "oracle linux",
    "linux",
    ".disk/info",
    "casper/",
    "live/",
    "isolinux",
)


def detect_linux_media(
    *,
    filename: str = "",
    label: str = "",
    iso_listing: str = "",
    source_meta: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Return Linux classification or None if media does not look like Linux."""
    meta = source_meta if isinstance(source_meta, dict) else {}
    forced = str(meta.get("platform") or meta.get("os_platform") or "").strip().lower()
    blob = " ".join(
        [
            str(filename or ""),
            str(label or ""),
            str(meta.get("edition") or ""),
            str(meta.get("product") or ""),
            str(meta.get("distro") or ""),
            str(meta.get("os_family") or ""),
            str(iso_listing or "")[:12000],
        ]
    ).lower()

    if forced in {"windows", "win"}:
        return None
    if forced in {"linux"} or str(meta.get("os_family") or "").lower() == "linux":
        pass
    else:
        # Prefer explicit Windows markers over generic "server"
        win_markers = ("windows 11", "windows 10", "win11_", "win10_", "windows_server", "install.wim")
        if any(m in blob for m in win_markers):
            return None
        if not any(h in blob for h in LINUX_BLOB_HINTS):
            return None
        # Avoid classifying plain "server" Windows as Linux
        if "windows" in blob and "linux" not in blob and not any(
            d in blob for d in ("ubuntu", "debian", "rocky", "alma", "centos", "fedora", "rhel", "suse", "arch")
        ):
            return None

    distro = str(meta.get("distro") or "").strip().lower()
    if not distro:
        for name, hints in LINUX_DISTRO_HINTS.items():
            if any(h.lower() in blob for h in hints):
                distro = name
                break
    if not distro:
        distro = "linux"

    family_kind = "server"
    if any(x in blob for x in ("desktop", "live-server" , "workstation", "gnome", "kde")):
        # live-server is still server; desktop/workstation → client-like
        if "desktop" in blob or "workstation" in blob or "gnome" in blob or "kde" in blob:
            if "live-server" not in blob and "server" not in Path(str(filename or "")).name.lower():
                family_kind = "desktop"
    if "live-server" in blob or re.search(r"(^|[-_])server([-_]|$)", Path(str(filename or "")).name.lower()):
        family_kind = "server"

    slug = distro if distro != "linux" else "linux"
    return {
        "platform": "linux",
        "os_family": "linux",
        "distro": distro,
        "linux_kind": family_kind,
        "product": f"{distro}-{family_kind}",
        "name_slug": slug,
        "label": f"Linux ({distro})",
        "pkg_format": "rpm" if distro in {"rocky", "alma", "rhel", "centos", "fedora", "oracle"} else "deb",
    }


def parse_filesystem_manifest(text: str) -> list[dict[str, str]]:
    """Parse casper/live filesystem.manifest lines (`name\\tversion` or `name version`)."""
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "\t" in line:
            name, ver = line.split("\t", 1)
        else:
            parts = line.split()
            if not parts:
                continue
            name, ver = parts[0], (parts[1] if len(parts) > 1 else "")
        name = name.strip()
        if not name or name in seen:
            continue
        seen.add(name)
        out.append({"name": name, "version": ver.strip(), "source": "filesystem.manifest"})
    return out


def parse_rpm_pool_names(listing_lines: list[str]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in listing_lines:
        line = raw.strip().replace("\\", "/")
        if not line.lower().endswith(".rpm"):
            continue
        base = Path(line).name
        # name-ver-rel.arch.rpm → package name is tricky; take NVRA best-effort
        m = re.match(r"^(.+)-([^-]+)-([^-]+)\.[^.]+\.rpm$", base, re.I)
        name = m.group(1) if m else base[:-4]
        if name in seen:
            continue
        seen.add(name)
        out.append({"name": name, "version": "", "source": "rpm-pool", "filename": base})
    return out


LINUX_SQUASHFS_MEMBERS: tuple[str, ...] = (
    "casper/filesystem.squashfs",
    "live/filesystem.squashfs",
    "install/filesystem.squashfs",
    "LiveOS/squashfs.img",
    "live/squashfs.img",
    "images/install.img",
)

LINUX_MANIFEST_MEMBERS: tuple[str, ...] = (
    "casper/filesystem.manifest",
    "live/filesystem.manifest",
    "install/filesystem.manifest",
    "repodata/repomd.xml",
)


def iso_listing_paths(iso_path: Path, *, seven_z: str) -> list[str]:
    """Return normalized member paths inside an ISO (7z listing, no full extract)."""
    iso_path = Path(iso_path)
    if not seven_z or not iso_path.is_file():
        return []
    listing = run_cmd([seven_z, "l", "-ba", str(iso_path)], timeout=300)
    out: list[str] = []
    for line in (listing.stdout or "").splitlines():
        parts = line.split()
        if not parts:
            continue
        out.append(parts[-1].replace("\\", "/"))
    return out


def find_iso_member(names: list[str], candidates: tuple[str, ...]) -> str:
    for cand in candidates:
        for n in names:
            if n.rstrip("/").endswith(cand) or n.endswith(cand):
                return cand
    return ""


def detect_root_pkg_format(root: Path) -> str:
    if (root / "var/lib/dpkg/status").is_file():
        return "deb"
    if (root / "var/lib/rpm").is_dir() and (
        (root / "var/lib/rpm/Packages").is_file() or (root / "var/lib/rpm/rpmdb.sqlite").is_file()
    ):
        return "rpm"
    if (root / "etc/debian_version").is_file():
        return "deb"
    if (root / "etc/redhat-release").is_file() or (root / "etc/fedora-release").is_file():
        return "rpm"
    return "unknown"


def parse_dpkg_status_packages(text: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for st in re.split(r"\n\n+", text or ""):
        m = re.search(r"^Package:\s*(\S+)", st, re.M)
        if not m:
            continue
        name = m.group(1).strip()
        if not name or name in seen:
            continue
        seen.add(name)
        ver_m = re.search(r"^Version:\s*(\S+)", st, re.M)
        out.append(
            {
                "name": name,
                "version": ver_m.group(1) if ver_m else "",
                "source": "dpkg-status",
            }
        )
    return out


def inventory_from_squashfs_probe(
    *,
    iso_path: Path,
    squash_member: str,
    seven_z: str,
    work: Path,
) -> tuple[list[dict[str, str]], list[str]]:
    """Extract squashfs head and inventory packages via dpkg status or rpm -qa."""
    notes: list[str] = []
    work.mkdir(parents=True, exist_ok=True)
    squash_local = work / Path(squash_member).name
    if squash_local.exists():
        squash_local.unlink()
    ex = run_cmd([seven_z, "e", "-y", f"-o{work}", str(iso_path), squash_member], timeout=600)
    if ex.returncode != 0 or not squash_local.is_file():
        notes.append(f"squash extract failed for {squash_member}")
        return [], notes

    probe_root = work / "squash-probe-root"
    if probe_root.exists():
        shutil.rmtree(probe_root, ignore_errors=True)
    probe_root.mkdir(parents=True, exist_ok=True)

    for extract_path in ("var/lib/dpkg/status", "var/lib/rpm/Packages", "var/lib/rpm/rpmdb.sqlite"):
        run_cmd(
            ["unsquashfs", "-f", "-d", str(probe_root), "-e", extract_path, str(squash_local)],
            timeout=600,
        )

    packages: list[dict[str, str]] = []
    status_path = probe_root / "var/lib/dpkg/status"
    if status_path.is_file():
        packages = parse_dpkg_status_packages(status_path.read_text(encoding="utf-8", errors="replace"))
        notes.append(f"inventory from squashfs dpkg status ({len(packages)} pkgs)")
        return packages, notes

    rpm_bin = shutil.which("rpm")
    rpm_db = probe_root / "var/lib/rpm"
    if rpm_bin and rpm_db.is_dir():
        proc = run_cmd(
            [rpm_bin, "--dbpath", str(rpm_db), "-qa", "--qf", "%{NAME}\t%{VERSION}\n"],
            timeout=300,
        )
        if proc.returncode == 0 and (proc.stdout or "").strip():
            seen: set[str] = set()
            for line in (proc.stdout or "").splitlines():
                parts = line.split("\t", 1)
                name = parts[0].strip()
                if not name or name in seen:
                    continue
                seen.add(name)
                packages.append(
                    {
                        "name": name,
                        "version": parts[1].strip() if len(parts) > 1 else "",
                        "source": "rpm-qa",
                    }
                )
            notes.append(f"inventory from squashfs rpm -qa ({len(packages)} pkgs)")
            return packages, notes

    notes.append("squashfs present but could not read dpkg/rpm package DB")
    return [], notes


def linux_iso_capabilities(
    inv: dict[str, Any],
    *,
    tools: dict[str, Any],
    free_bytes: int,
) -> dict[str, Any]:
    """Assess what Image Nest can do with this Linux ISO."""
    squash = str(inv.get("squashfs_member") or "")
    pkg_fmt = str(inv.get("package_manager") or "unknown")
    pkg_count = len(inv.get("packages") or [])
    tools_ok = bool(tools.get("linux_strip_ready"))
    blockers: list[str] = []
    if not squash:
        blockers.append("no live rootfs image (filesystem.squashfs / LiveOS/squashfs.img)")
    if pkg_fmt == "unknown" and pkg_count == 0:
        blockers.append("no package inventory found on ISO")
    elif pkg_fmt == "rpm" and not shutil.which("rpm"):
        blockers.append("rpm CLI missing on controller (needed for RPM live rootfs strip)")
    if not tools_ok:
        blockers.append("need unsquashfs, mksquashfs, xorriso, and 7z on controller")
    if free_bytes < 2 * 1024**3:
        blockers.append(f"low disk ({free_bytes} bytes free; need ≥2GB for squashfs strip)")
    strip_supported = bool(squash and pkg_count > 0 and pkg_fmt in {"deb", "rpm"})
    if strip_supported and pkg_fmt == "rpm" and not shutil.which("rpm"):
        strip_supported = False
    strip_ready = strip_supported and tools_ok and free_bytes >= 2 * 1024**3
    return {
        "inventory": pkg_count > 0,
        "strip_supported": strip_supported,
        "strip_ready": strip_ready,
        "package_manager": pkg_fmt,
        "squashfs_member": squash,
        "blockers": blockers,
    }


def repack_iso_replace_member(
    *,
    source_iso: Path,
    iso_member: str,
    local_file: Path,
    out_iso: Path,
) -> dict[str, Any]:
    """Replace one file inside an ISO while preserving boot (xorriso replay)."""
    xorriso = shutil.which("xorriso")
    if not xorriso:
        return {"ok": False, "error": "xorriso missing"}
    if not source_iso.is_file() or not local_file.is_file():
        return {"ok": False, "error": "source ISO or replacement file missing"}
    if out_iso.exists():
        out_iso.unlink()
    iso_rr = "/" + str(iso_member).lstrip("/")
    proc = run_cmd(
        [
            xorriso,
            "-indev",
            str(source_iso),
            "-outdev",
            str(out_iso),
            "-boot_image",
            "any",
            "replay",
            "-map",
            str(local_file),
            iso_rr,
            "-commit",
        ],
        timeout=3600,
    )
    if proc.returncode != 0 or not out_iso.is_file():
        return {
            "ok": False,
            "error": f"xorriso ISO repack failed: {(proc.stderr or proc.stdout or '')[:500]}",
        }
    return {"ok": True, "path": str(out_iso), "bytes": out_iso.stat().st_size, "member": iso_member}


def parse_deb_pool_names(listing_lines: list[str]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in listing_lines:
        line = raw.strip().replace("\\", "/")
        if not line.lower().endswith(".deb"):
            continue
        base = Path(line).name
        # pkg_ver_arch.deb
        name = base.split("_", 1)[0]
        if not name or name in seen:
            continue
        seen.add(name)
        out.append({"name": name, "version": "", "source": "deb-pool", "filename": base})
    return out


def match_linux_strip_targets(
    inventory: list[dict[str, str]],
    patterns: list[str],
) -> list[str]:
    """Return concrete package names present in inventory that match any pattern/glob."""
    names = [str(p.get("name") or "") for p in inventory if p.get("name")]
    chosen: list[str] = []
    seen: set[str] = set()
    for pat in patterns:
        raw = str(pat or "").strip()
        if not raw:
            continue
        for name in names:
            if name in seen:
                continue
            if raw == name or fnmatch.fnmatch(name.lower(), raw.lower()):
                seen.add(name)
                chosen.append(name)
    return chosen


def run_cmd(cmd: list[str], *, timeout: int = 600, cwd: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)


def rebuild_iso_from_tree(tree: Path, out_iso: Path) -> dict[str, Any]:
    """Rebuild an ISO from an extracted tree using xorriso (Rock Ridge + Joliet)."""
    xorriso = shutil.which("xorriso")
    if not xorriso:
        return {"ok": False, "error": "xorriso missing — install xorriso on controller"}
    if out_iso.exists():
        out_iso.unlink()
    # Prefer preserving bootability when isolinux/grub trees exist; fall back to data ISO.
    cmd = [
        xorriso,
        "-as",
        "mkisofs",
        "-R",
        "-J",
        "-V",
        "IMAGE_NEST_LINUX",
        "-o",
        str(out_iso),
    ]
    # El Torito when classic isolinux is present
    isolinux = tree / "isolinux" / "isolinux.bin"
    if isolinux.is_file():
        cmd += [
            "-b",
            "isolinux/isolinux.bin",
            "-c",
            "isolinux/boot.cat",
            "-no-emul-boot",
            "-boot-load-size",
            "4",
            "-boot-info-table",
        ]
    cmd.append(str(tree))
    proc = run_cmd(cmd, timeout=900)
    if proc.returncode != 0 or not out_iso.is_file():
        return {
            "ok": False,
            "error": f"xorriso failed: {(proc.stderr or proc.stdout or '')[:400]}",
        }
    return {"ok": True, "path": str(out_iso), "bytes": out_iso.stat().st_size}


def inventory_linux_iso(iso_path: Path, *, seven_z: str) -> dict[str, Any]:
    """Discover packages present on a Linux ISO via 7z (no full extract)."""
    iso_path = Path(iso_path)
    if not seven_z or not iso_path.is_file():
        return {"ok": False, "error": "7z/ISO missing", "packages": []}
    names_only = iso_listing_paths(iso_path, seven_z=seven_z)

    packages: list[dict[str, str]] = []
    notes: list[str] = []
    package_manager = "unknown"

    # Prefer filesystem.manifest when present (Ubuntu/Debian live)
    manifest_member = find_iso_member(names_only, LINUX_MANIFEST_MEMBERS[:3])
    if manifest_member:
        ex = run_cmd(
            [seven_z, "e", "-y", f"-o/tmp", str(iso_path), manifest_member],
            timeout=180,
        )
        cand = Path("/tmp") / Path(manifest_member).name
        if not cand.is_file():
            cand = Path("/tmp") / manifest_member
        if cand.is_file():
            text = cand.read_text(encoding="utf-8", errors="replace")
            packages = parse_filesystem_manifest(text)
            package_manager = "deb"
            notes.append(f"inventory from {manifest_member} ({len(packages)} pkgs)")
            try:
                cand.unlink()
            except OSError:
                pass

    squash = find_iso_member(names_only, LINUX_SQUASHFS_MEMBERS)

    # filesystem.manifest is fast but sometimes trimmed; prefer squashfs dpkg/rpm when it
    # inventories substantially more packages (common on custom/minimal live ISOs).
    manifest_count = len(packages)
    if squash and (not packages or manifest_count < 50):
        probe_work = Path("/tmp") / f"image-nest-inv-{uuid.uuid4().hex[:8]}"
        try:
            sq_pkgs, sq_notes = inventory_from_squashfs_probe(
                iso_path=iso_path,
                squash_member=squash,
                seven_z=seven_z,
                work=probe_work,
            )
            notes.extend(sq_notes)
            if sq_pkgs and len(sq_pkgs) > manifest_count:
                packages = sq_pkgs
                package_manager = "deb" if sq_pkgs[0].get("source") == "dpkg-status" else "rpm"
            elif sq_pkgs and not packages:
                packages = sq_pkgs
                package_manager = "deb" if sq_pkgs[0].get("source") == "dpkg-status" else "rpm"
        finally:
            shutil.rmtree(probe_work, ignore_errors=True)

    if not packages:
        deb = parse_deb_pool_names(names_only)
        rpm = parse_rpm_pool_names(names_only)
        if deb:
            packages = deb
            package_manager = "deb"
            notes.append(f"inventory from deb pool ({len(packages)} pkgs)")
        elif rpm:
            packages = rpm
            package_manager = "rpm"
            notes.append(f"inventory from rpm pool ({len(packages)} pkgs)")
        else:
            notes.append("no package inventory found on ISO")

    if package_manager == "unknown" and packages:
        src = str(packages[0].get("source") or "")
        if "rpm" in src:
            package_manager = "rpm"
        elif src in {"filesystem.manifest", "deb-pool", "dpkg-status"}:
            package_manager = "deb"

    return {
        "ok": True,
        "packages": packages,
        "package_names": [p["name"] for p in packages],
        "squashfs_member": squash,
        "package_manager": package_manager,
        "notes": notes,
        "listing_sample": names_only[:80],
        "iso_members": len(names_only),
    }


def _purge_dpkg_packages(root: Path, packages: list[str]) -> dict[str, Any]:
    """Remove package files using dpkg info lists when present; update status."""
    removed: list[str] = []
    skipped: list[str] = []
    info_dir = root / "var" / "lib" / "dpkg" / "info"
    status_path = root / "var" / "lib" / "dpkg" / "status"
    for pkg in packages:
        list_file = info_dir / f"{pkg}.list"
        if list_file.is_file():
            try:
                for raw in list_file.read_text(encoding="utf-8", errors="replace").splitlines():
                    rel = raw.strip()
                    if not rel or rel == "/":
                        continue
                    target = root / rel.lstrip("/")
                    if target.is_file() or target.is_symlink():
                        try:
                            target.unlink()
                        except OSError:
                            pass
                removed.append(pkg)
            except OSError:
                skipped.append(pkg)
        else:
            skipped.append(pkg)

    if status_path.is_file() and removed:
        try:
            raw = status_path.read_text(encoding="utf-8", errors="replace")
            stanzas = re.split(r"\n\n+", raw)
            keep = []
            drop = set(removed)
            for st in stanzas:
                m = re.search(r"^Package:\s*(\S+)", st, re.M)
                name = m.group(1) if m else ""
                if name in drop:
                    continue
                keep.append(st.strip())
            status_path.write_text("\n\n".join(keep) + "\n", encoding="utf-8")
        except OSError:
            pass
    return {"removed": removed, "skipped_no_filelist": skipped, "package_manager": "deb"}


def _purge_rpm_packages(root: Path, packages: list[str]) -> dict[str, Any]:
    """Remove RPM packages from an unsquashed rootfs using rpm --root."""
    rpm_bin = shutil.which("rpm")
    if not rpm_bin:
        return {
            "removed": [],
            "skipped_no_filelist": list(packages),
            "package_manager": "rpm",
            "error": "rpm CLI not installed on controller",
        }
    removed: list[str] = []
    skipped: list[str] = []
    for pkg in packages:
        proc = run_cmd(
            [rpm_bin, "--root", str(root), "-e", "--nodeps", pkg],
            timeout=300,
        )
        if proc.returncode == 0:
            removed.append(pkg)
        else:
            skipped.append(pkg)
    return {"removed": removed, "skipped_no_filelist": skipped, "package_manager": "rpm"}


def _purge_packages_from_root(root: Path, packages: list[str]) -> dict[str, Any]:
    """Remove packages from an unsquashed rootfs (dpkg or rpm)."""
    fmt = detect_root_pkg_format(root)
    if fmt == "rpm":
        return _purge_rpm_packages(root, packages)
    if fmt == "deb":
        return _purge_dpkg_packages(root, packages)
    # Best-effort dpkg path for unknown layouts
    out = _purge_dpkg_packages(root, packages)
    if not out.get("removed"):
        out["package_manager"] = "unknown"
        out["error"] = "could not detect deb/rpm package DB in squashfs root"
    return out


def offline_linux_process(
    *,
    iso_path: Path,
    work: Path,
    image_bank: Path,
    image_name: str,
    flavor: str,
    package_globs: list[str],
    strip_labels: list[str] | None = None,
    seven_z: str = "",
    log_cb=None,
) -> dict[str, Any]:
    """Inventory, optionally strip squashfs packages, bank a Linux ISO artifact."""
    notes: list[str] = []
    def log(msg: str) -> None:
        notes.append(msg)
        if log_cb:
            try:
                log_cb(msg)
            except Exception:
                pass

    tools_ok = all(shutil.which(x) for x in ("unsquashfs", "mksquashfs", "xorriso")) and bool(seven_z)
    inv = inventory_linux_iso(iso_path, seven_z=seven_z)
    notes.extend(inv.get("notes") or [])
    packages = list(inv.get("packages") or [])
    before_names = [p["name"] for p in packages]
    log(f"linux inventory packages={len(before_names)}")

    targets = match_linux_strip_targets(packages, list(package_globs or []))
    strip_mode = "none"
    removed: list[str] = []
    banked_iso = image_bank / f"{image_name}.iso"

    if flavor != "stripped":
        strip_mode = "full_copy"
        log("full flavor — banking ISO without package deletes")
        shutil.copy2(iso_path, banked_iso)
        return {
            "ok": True,
            "banked_iso_path": str(banked_iso),
            "iso_path": str(banked_iso),
            "path": str(banked_iso),
            "source_image": str(banked_iso),
            "source_iso": str(banked_iso),
            "strip_mode": strip_mode,
            "removed": [],
            "before_packages": before_names,
            "after_packages": before_names,
            "inventory": packages,
            "notes": notes,
        }

    if not package_globs:
        strip_mode = "noop_empty_selection"
        log("strip: no package globs selected — banking original ISO")
        shutil.copy2(iso_path, banked_iso)
        return {
            "ok": True,
            "banked_iso_path": str(banked_iso),
            "iso_path": str(banked_iso),
            "path": str(banked_iso),
            "source_image": str(banked_iso),
            "source_iso": str(banked_iso),
            "strip_mode": strip_mode,
            "removed": [],
            "before_packages": before_names,
            "after_packages": before_names,
            "inventory": packages,
            "notes": notes,
        }

    if not targets:
        strip_mode = "noop_no_match"
        log(
            "strip: catalog globs matched no packages on this ISO "
            "(inventory-driven — nothing to remove)"
        )
        shutil.copy2(iso_path, banked_iso)
        return {
            "ok": True,
            "banked_iso_path": str(banked_iso),
            "iso_path": str(banked_iso),
            "path": str(banked_iso),
            "source_image": str(banked_iso),
            "source_iso": str(banked_iso),
            "strip_mode": strip_mode,
            "removed": [],
            "before_packages": before_names,
            "after_packages": before_names,
            "inventory": packages,
            "notes": notes,
            "labels": list(strip_labels or []),
        }

    squash_member = str(inv.get("squashfs_member") or "")
    if not squash_member:
        return {
            "ok": False,
            "error": (
                "Linux strip found matching packages but this ISO has no filesystem.squashfs "
                "(netinst/pool-only). Upload a live/desktop ISO for offline squashfs strip, "
                f"or bank full. matched={targets[:12]}"
            ),
            "notes": notes,
            "before_packages": before_names,
            "expanded": targets,
        }

    if not tools_ok:
        return {
            "ok": False,
            "error": "linux strip requires unsquashfs, mksquashfs, xorriso, and 7z on the controller",
            "notes": notes,
        }

    free = shutil.disk_usage(work).free if work.exists() else shutil.disk_usage("/").free
    # Need headroom for squash extract + rebuild
    if free < 2 * 1024**3:
        return {
            "ok": False,
            "error": f"insufficient free disk for Linux squashfs strip ({free} bytes free; need ≥2GB)",
            "notes": notes,
        }

    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    rootfs = work / "rootfs"
    squash_local = work / Path(squash_member).name
    squash_new = work / f"new-{Path(squash_member).name}"

    try:
        log(f"Extracting {squash_member} ({len(targets)} package target(s))")
        ex = run_cmd([seven_z, "e", "-y", f"-o{work}", str(iso_path), squash_member], timeout=1200)
        if ex.returncode != 0 or not squash_local.is_file():
            return {
                "ok": False,
                "error": f"squashfs extract failed: {(ex.stderr or ex.stdout or '')[:300]}",
                "notes": notes,
            }

        log(f"Unsquashing {squash_member}")
        if rootfs.exists():
            shutil.rmtree(rootfs, ignore_errors=True)
        us = run_cmd(["unsquashfs", "-d", str(rootfs), str(squash_local)], timeout=1800)
        if us.returncode != 0:
            return {
                "ok": False,
                "error": f"unsquashfs failed: {(us.stderr or us.stdout or '')[:300]}",
                "notes": notes,
            }

        pkg_fmt = detect_root_pkg_format(rootfs)
        log(f"rootfs package manager={pkg_fmt}")
        purge = _purge_packages_from_root(rootfs, targets)
        if purge.get("error"):
            return {"ok": False, "error": str(purge.get("error")), "notes": notes}
        removed = list(purge.get("removed") or [])
        for s in purge.get("skipped_no_filelist") or []:
            notes.append(f"skip: {s}")
        for label in strip_labels or []:
            notes.append(f"selection: {label}")
        log(f"strip removed_ok={len(removed)} attempted={len(targets)}")

        if not removed:
            return {
                "ok": False,
                "error": (
                    "linux strip matched packages but could not remove any "
                    f"(pkg_format={pkg_fmt}) — refusing false stripped image"
                ),
                "notes": notes,
                "expanded": targets,
                "before_packages": before_names,
            }

        log("Rebuilding squashfs")
        if squash_new.exists():
            squash_new.unlink()
        ms = run_cmd(
            ["mksquashfs", str(rootfs), str(squash_new), "-comp", "xz", "-noappend"],
            timeout=1800,
        )
        if ms.returncode != 0 or not squash_new.is_file():
            return {
                "ok": False,
                "error": f"mksquashfs failed: {(ms.stderr or ms.stdout or '')[:300]}",
                "notes": notes,
            }

        after_names = [n for n in before_names if n not in set(removed)]
        maps: list[tuple[Path, str]] = [(squash_new, squash_member)]

        names_only = iso_listing_paths(iso_path, seven_z=seven_z)
        manifest_member = find_iso_member(names_only, LINUX_MANIFEST_MEMBERS[:3])
        if manifest_member:
            man_local = work / Path(manifest_member).name
            run_cmd([seven_z, "e", "-y", f"-o{work}", str(iso_path), manifest_member], timeout=180)
            if man_local.is_file():
                drop = set(removed)
                lines = []
                for line in man_local.read_text(encoding="utf-8", errors="replace").splitlines():
                    name = line.split("\t", 1)[0].split()[0] if line.strip() else ""
                    if name in drop:
                        continue
                    lines.append(line)
                man_local.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
                maps.append((man_local, manifest_member))
                after_names = [p["name"] for p in parse_filesystem_manifest(man_local.read_text(encoding="utf-8", errors="replace"))]

        still = [n for n in removed if n in set(after_names)]
        if still:
            return {
                "ok": False,
                "error": f"strip verification failed — still listed: {', '.join(still[:8])}",
                "notes": notes,
                "before_packages": before_names,
                "after_packages": after_names,
            }

        if banked_iso.exists():
            banked_iso.unlink()
        log("Repacking ISO (xorriso boot replay)")
        xorriso = shutil.which("xorriso")
        if not xorriso:
            return {"ok": False, "error": "xorriso missing", "notes": notes}
        cmd = [xorriso, "-indev", str(iso_path), "-outdev", str(banked_iso), "-boot_image", "any", "replay"]
        for local_file, member in maps:
            cmd += ["-map", str(local_file), "/" + str(member).lstrip("/")]
        cmd.append("-commit")
        proc = run_cmd(cmd, timeout=3600)
        if proc.returncode != 0 or not banked_iso.is_file():
            log("xorriso replay failed — falling back to full ISO tree rebuild")
            tree = work / "iso-tree"
            if tree.exists():
                shutil.rmtree(tree, ignore_errors=True)
            tree.mkdir(parents=True, exist_ok=True)
            ex2 = run_cmd([seven_z, "x", "-y", f"-o{tree}", str(iso_path)], timeout=1800)
            if ex2.returncode != 0:
                return {
                    "ok": False,
                    "error": f"ISO extract fallback failed: {(ex2.stderr or ex2.stdout or '')[:300]}",
                    "notes": notes,
                }
            squash_dest = tree / squash_member
            squash_dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(squash_new, squash_dest)
            for local_file, member in maps[1:]:
                dest = tree / member
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(local_file, dest)
            rebuilt = rebuild_iso_from_tree(tree, banked_iso)
            if not rebuilt.get("ok"):
                return {"ok": False, "error": rebuilt.get("error"), "notes": notes}

        strip_mode = "delete"
        notes.append(
            f"strip verified: removed {len(removed)} package(s); "
            f"packages {len(before_names)} → {len(after_names)}"
        )
        return {
            "ok": True,
            "banked_iso_path": str(banked_iso),
            "iso_path": str(banked_iso),
            "path": str(banked_iso),
            "source_image": str(banked_iso),
            "source_iso": str(banked_iso),
            "strip_mode": strip_mode,
            "removed": removed,
            "expanded": targets,
            "before_packages": before_names,
            "after_packages": after_names,
            "inventory": packages,
            "package_manager": pkg_fmt,
            "notes": notes,
        }
    finally:
        shutil.rmtree(work, ignore_errors=True)
