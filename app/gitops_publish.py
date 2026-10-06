"""Publish owned IaC paths to a team-bound GitHub/GitLab repo.

Only files the caller collected (must be ownership-filtered upstream) are sent.
Uses the team binding's vault PAT — never a personal dump of the whole workspace.
"""

from __future__ import annotations

import base64
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

logger = logging.getLogger("hayabusa-controller.gitops_publish")


def _http_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    body: dict[str, Any] | None = None,
    timeout: float = 60,
) -> tuple[int, dict[str, Any] | list[Any] | str]:
    data = None
    hdrs = dict(headers)
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            code = int(getattr(resp, "status", 200) or 200)
            if not raw:
                return code, {}
            try:
                return code, json.loads(raw)
            except json.JSONDecodeError:
                return code, raw
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        try:
            parsed: dict[str, Any] | list[Any] | str = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = raw
        return int(exc.code), parsed


def _github_put_file(
    *,
    base_url: str,
    repo: str,
    path: str,
    content: str,
    token: str,
    branch: str,
    message: str,
) -> dict[str, Any]:
    api = "https://api.github.com" if "github.com" in (base_url or "") else f"{base_url.rstrip('/')}/api/v3"
    enc_path = "/".join(urllib.parse.quote(p, safe="") for p in path.strip("/").split("/") if p)
    url = f"{api}/repos/{repo}/contents/{enc_path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "hayabusa-controller-gitops-publish",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    code, existing = _http_json("GET", f"{url}?ref={urllib.parse.quote(branch)}", headers=headers)
    sha = ""
    if code < 400 and isinstance(existing, dict):
        sha = str(existing.get("sha") or "")
    payload: dict[str, Any] = {
        "message": message[:200],
        "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
        "branch": branch,
    }
    if sha:
        payload["sha"] = sha
    code2, out = _http_json("PUT", url, headers=headers, body=payload)
    if code2 >= 400:
        err = out.get("message") if isinstance(out, dict) else str(out)[:300]
        return {"ok": False, "path": path, "error": err or f"HTTP {code2}", "status": code2}
    return {"ok": True, "path": path, "status": code2}


def _gitlab_put_file(
    *,
    base_url: str,
    repo: str,
    path: str,
    content: str,
    token: str,
    branch: str,
    message: str,
) -> dict[str, Any]:
    api = f"{base_url.rstrip('/')}/api/v4"
    project = urllib.parse.quote(repo, safe="")
    enc_path = urllib.parse.quote(path.strip("/"), safe="")
    headers = {
        "PRIVATE-TOKEN": token,
        "Accept": "application/json",
        "User-Agent": "hayabusa-controller-gitops-publish",
    }
    url = f"{api}/projects/{project}/repository/files/{enc_path}"
    payload = {"branch": branch, "content": content, "commit_message": message[:200]}
    code, out = _http_json("PUT", url, headers=headers, body=payload)
    if code in {400, 404}:
        code, out = _http_json("POST", url, headers=headers, body=payload)
    if code >= 400:
        err = out.get("message") if isinstance(out, dict) else str(out)[:300]
        return {"ok": False, "path": path, "error": err or f"HTTP {code}", "status": code}
    return {"ok": True, "path": path, "status": code}


def publish_files_to_binding(
    *,
    binding: dict[str, Any],
    token: str,
    files: list[dict[str, str]],
    commit_message: str,
) -> dict[str, Any]:
    """Push text files to the binding's repo. Returns summary (never includes token)."""
    provider = str(binding.get("provider") or "github").lower()
    base_url = str(binding.get("base_url") or "").rstrip("/")
    repo = str(binding.get("repo") or "").strip("/")
    branch = str(binding.get("ref") or "main").strip() or "main"
    bind_prefix = str(binding.get("path_prefix") or "").strip().strip("/")
    if not token or not repo:
        return {"ok": False, "error": "missing token or repo", "code": "bad_request"}

    results: list[dict[str, Any]] = []
    ok_n = 0
    fail_n = 0
    for item in files[:400]:
        if not isinstance(item, dict):
            continue
        rel = str(item.get("path") or "").strip().lstrip("/")
        content = item.get("content")
        if not rel or not isinstance(content, str):
            continue
        if ".." in rel.split("/"):
            continue
        dest = f"{bind_prefix}/{rel}" if bind_prefix else rel
        msg = commit_message or f"Hayabusa GitOps publish: {rel}"
        if provider == "gitlab":
            row = _gitlab_put_file(
                base_url=base_url,
                repo=repo,
                path=dest,
                content=content,
                token=token,
                branch=branch,
                message=msg,
            )
        else:
            row = _github_put_file(
                base_url=base_url,
                repo=repo,
                path=dest,
                content=content,
                token=token,
                branch=branch,
                message=msg,
            )
        results.append({"path": rel, "dest": dest, "ok": bool(row.get("ok")), "error": row.get("error") or ""})
        if row.get("ok"):
            ok_n += 1
        else:
            fail_n += 1
            logger.info("gitops publish failed path=%s err=%s", rel, row.get("error"))

    return {
        "ok": fail_n == 0 and ok_n > 0,
        "published": ok_n,
        "failed": fail_n,
        "provider": provider,
        "repo": repo,
        "ref": branch,
        "results": results[:80],
        "message": (
            f"Published {ok_n} file(s) to {provider}:{repo}@{branch}"
            + (f" ({fail_n} failed)" if fail_n else "")
        ),
        "hayabusa_saw_secret_values": False,
    }
