#!/usr/bin/env python3
"""Fetch Windows 11 x64 retail ISO from Microsoft software-download (consumer API)."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

WIN11_PAGE = "https://www.microsoft.com/en-us/software-download/windows11"
PROFILE = "606624d44113"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
EXPECTED_SHA256_EN = "768984706B909479417B2368438909440F2967FF05C6A9195ED2667254E465E3"


def _get(url: str, *, referer: str = "", accept: str = "*/*") -> bytes:
    headers = {"User-Agent": USER_AGENT, "Accept": accept}
    if referer:
        headers["Referer"] = referer
    with urlopen(Request(url, headers=headers), timeout=180) as resp:
        return resp.read()


def _json_loads(raw: bytes) -> dict:
    data = json.loads(raw)
    if isinstance(data, str):
        data = json.loads(data)
    if not isinstance(data, dict):
        raise RuntimeError("unexpected JSON payload from Microsoft")
    return data


def resolve_download_url(*, language: str = "English") -> tuple[str, str, str]:
    page_html = _get(WIN11_PAGE, accept="").decode("utf-8", errors="replace")
    m = re.search(
        r'<option[^>]+value="(\d+)"[^>]*>Windows 11 \(multi-edition ISO for x64 devices\)',
        page_html,
        re.I,
    )
    if not m:
        raise RuntimeError("could not find x64 multi-edition option on Microsoft page")
    product_edition_id = m.group(1)

    session_id = str(uuid.uuid4())
    _get(
        f"https://vlscppe.microsoft.com/tags?org_id=y6jn8c31&session_id={session_id}",
        accept="",
    )

    sku_url = (
        "https://www.microsoft.com/software-download-connector/api/"
        f"getskuinformationbyproductedition?profile={PROFILE}"
        f"&ProductEditionId={product_edition_id}&SKU=undefined&friendlyFileName=undefined"
        f"&Locale=en-US&sessionID={session_id}"
    )
    sku_json = _json_loads(_get(sku_url, referer=WIN11_PAGE))
    skus = sku_json.get("Skus") or []
    sku_id = ""
    fname = "Win11_English_x64.iso"
    for row in skus:
        if not isinstance(row, dict):
            continue
        lang = str(row.get("Language") or row.get("LocalizedLanguage") or "")
        if lang == language:
            sku_id = str(row.get("Id") or "")
            fname = str(row.get("LocalizedProductDisplayName") or fname).replace(" ", "_") + ".iso"
            break
    if not sku_id:
        raise RuntimeError(f"language {language!r} not in SKU table")

    link_url = (
        "https://www.microsoft.com/software-download-connector/api/GetProductDownloadLinksBySku"
        f"?profile={PROFILE}&productEditionId=undefined&SKU={sku_id}"
        f"&friendlyFileName=undefined&Locale=en-US&sessionID={session_id}"
    )
    link_json = _json_loads(_get(link_url, referer=WIN11_PAGE))
    err = (link_json.get("Errors") or [{}])[0]
    if isinstance(err, dict) and err.get("Value"):
        raise RuntimeError(str(err["Value"]))
    opts = link_json.get("ProductDownloadOptions") or []
    uri = ""
    for opt in opts:
        if not isinstance(opt, dict):
            continue
        u = str(opt.get("Uri") or "")
        if not u or "arm64" in u.lower():
            continue
        uri = u
        fname = str(opt.get("FileName") or fname)
        break
    if not uri:
        raise RuntimeError("no x64 ISO download URI in Microsoft response")
    return uri, fname, product_edition_id


def download_iso(url: str, dest: Path, *, verify_sha256: str = "") -> dict:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    h = hashlib.sha256()
    total = 0
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=7200) as resp, open(tmp, "wb") as out:
        while True:
            chunk = resp.read(1024 * 1024)
            if not chunk:
                break
            out.write(chunk)
            h.update(chunk)
            total += len(chunk)
            if total % (256 * 1024 * 1024) < len(chunk):
                print(f"  … {total // (1024 * 1024)} MiB", file=sys.stderr)
    sha = h.hexdigest()
    if verify_sha256 and sha.lower() != verify_sha256.lower():
        tmp.unlink(missing_ok=True)
        raise RuntimeError(f"sha256 mismatch expected {verify_sha256} got {sha}")
    tmp.replace(dest)
    return {"bytes": total, "sha256": sha, "path": str(dest)}


def main() -> int:
    ap = argparse.ArgumentParser(description="Download Win11 x64 ISO from Microsoft")
    ap.add_argument("-o", "--output", default="", help="Destination .iso path")
    ap.add_argument("--language", default="English")
    ap.add_argument("--verify-sha256", default=EXPECTED_SHA256_EN)
    ap.add_argument("--skip-verify", action="store_true")
    ap.add_argument("--url-only", action="store_true")
    args = ap.parse_args()

    print(f"Resolving download link ({args.language})…", file=sys.stderr)
    url, fname, peid = resolve_download_url(language=args.language)
    print(f"Edition id {peid}", file=sys.stderr)
    print(f"Link: {url[:120]}…", file=sys.stderr)
    if args.url_only:
        print(url)
        return 0
    if not args.output:
        ap.error("-o/--output is required unless --url-only")
    out = Path(args.output)
    if out.is_dir():
        out = out / fname
    print(f"Downloading → {out}", file=sys.stderr)
    verify = "" if args.skip_verify else args.verify_sha256
    meta = download_iso(url, out, verify_sha256=verify)
    print(json.dumps({"ok": True, "filename": out.name, "product_edition_id": peid, **meta}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (HTTPError, URLError, RuntimeError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        raise SystemExit(1) from exc
