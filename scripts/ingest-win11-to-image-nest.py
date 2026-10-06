#!/usr/bin/env python3
"""Download (or use) Win11 ISO → Image Nest bank + playbook registry refs.

Controller-only. Does not modify Hayabusa core, ZTP, or OpenTofu projects.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

DATA_DIR = Path("/var/lib/hayabusa-controller")
FETCH = Path(__file__).resolve().parent / "fetch-win11-iso.py"


def _import_store():
    sys.path.insert(0, "/opt/hayabusa-controller")
    from app.image_nest import ImageNestStore

    return ImageNestStore(DATA_DIR)


def _wait_job(store, job_id: str, *, timeout_sec: int = 7200) -> dict:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        job = store.get_job(job_id)
        if not job:
            raise RuntimeError(f"job {job_id} vanished")
        st = str(job.get("status") or "")
        if st in {"completed", "failed"}:
            return job
        time.sleep(5)
    raise RuntimeError(f"job {job_id} timed out after {timeout_sec}s")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iso-path", default="", help="Use an existing ISO instead of downloading")
    ap.add_argument("--download-to", default="/tmp/win11-retail.iso")
    ap.add_argument("--language", default="English")
    ap.add_argument("--flavor", default="full", choices=["full", "stripped"])
    ap.add_argument("--skip-download", action="store_true")
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--skip-verify", action="store_true")
    args = ap.parse_args()

    iso_path = Path(args.iso_path) if args.iso_path else Path(args.download_to)
    if not args.iso_path and not args.skip_download:
        cmd = [
            sys.executable,
            str(FETCH),
            "-o",
            str(iso_path),
            "--language",
            args.language,
        ]
        if args.skip_verify:
            cmd.append("--skip-verify")
        print("Fetching ISO from Microsoft…", file=sys.stderr)
        proc = subprocess.run(cmd, check=False)
        if proc.returncode != 0:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": "Microsoft download failed (Sentinel may block automated fetch). "
                        "Download the ISO in a browser, then rerun with --iso-path /path/to/file.iso",
                    },
                    indent=2,
                )
            )
            return 1

    if not iso_path.is_file():
        print(json.dumps({"ok": False, "error": f"ISO not found: {iso_path}"}, indent=2))
        return 1

    store = _import_store()
    label = f"Windows 11 25H2 {args.language} x64 (retail ISO)"
    meta = {
        "source_url": "https://www.microsoft.com/en-us/software-download/windows11",
        "language": args.language.lower().replace(" ", "-"),
        "arch": "x64",
        "edition": "win11-25h2-multi",
        "channel": "retail",
    }
    print(f"Ingesting {iso_path} into Image Nest…", file=sys.stderr)
    ing = store.ingest_path(path=iso_path, label=label, source_meta=meta)
    if not ing.get("ok"):
        print(json.dumps(ing, indent=2))
        return 1
    iso = ing["iso"]
    iso_ref = iso.get("registry_ref")
    out = {"ok": True, "iso": iso, "iso_registry_ref": iso_ref}

    if not args.skip_build:
        build = store.start_build(iso_id=str(iso.get("id")), flavor=args.flavor)
        if not build.get("ok"):
            print(json.dumps(build, indent=2))
            return 1
        job_id = str((build.get("job") or {}).get("id") or "")
        print(f"Bake job {job_id} ({args.flavor})…", file=sys.stderr)
        job = _wait_job(store, job_id)
        image = store.get_image(str(job.get("image_id") or ""))
        out["job"] = job
        out["image"] = image
        out["image_registry_ref"] = (image or {}).get("registry_ref")

    reg = store.list_registry()
    out["registry"] = {
        "repo_root": reg.get("repo_root"),
        "aliases": reg.get("aliases"),
        "playbook_refs_dir": reg.get("playbook_refs_dir"),
    }
    out["playbook_usage"] = {
        "ansible_extra_vars": "@/var/lib/hayabusa-controller/image-nest/playbook-refs/latest-win11-iso.vars.json",
        "vm_image_vars": "@/var/lib/hayabusa-controller/image-nest/playbook-refs/latest-win11-full.vars.json",
        "registry_index": "/var/lib/hayabusa-controller/image-nest/playbook-refs/registry-index.json",
    }
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
