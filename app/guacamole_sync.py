"""
Controller-scoped Apache Guacamole provisioning (REST API).

Provisions one Guacamole user per signed-in controller account and SSH
connections for hosts discovered on this controller's LAN. SSH credentials
come from the local secrets vault (same keys Guacamole broker RPC uses).
"""
from __future__ import annotations

import json
import logging
import os
import re
import secrets
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

_LOCK = threading.Lock()
_ENTITY_PREFIX = "ctrl-"
_CONN_NAME_PREFIX = "ctrl|"
_DATA_SOURCE = "postgresql"
_DEFAULT_USER_KEYS = (
    "guacamole_peer_ssh_user",
    "guacamole_ssh_user",
    "ssh_user",
)
_DEFAULT_PASSWORD_KEYS = (
    "guacamole_peer_ssh_password",
    "guacamole_ssh_password",
    "ssh_password",
)


def guacamole_sync_enabled() -> bool:
    return str(os.environ.get("CONTROLLER_GUACAMOLE_SYNC_ENABLED", "1")).strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def _guac_internal_base() -> str:
    return (os.environ.get("CONTROLLER_GUACAMOLE_INTERNAL_URL") or "http://127.0.0.1:9000").rstrip("/")


def _guac_admin_credentials() -> tuple[str, str]:
    user = (os.environ.get("GUACAMOLE_ADMIN_USER") or "guacadmin").strip() or "guacadmin"
    password = (os.environ.get("GUACAMOLE_ADMIN_PASSWORD") or "guacadmin").strip()
    return user, password


def _guac_admin_configured() -> bool:
    _, password = _guac_admin_credentials()
    return bool(password)


def _secrets_path(data_dir: str | None = None) -> str:
    override = (os.environ.get("CONTROLLER_GUACAMOLE_SECRETS_FILE") or "").strip()
    if override:
        return override
    root = (data_dir or os.environ.get("HAYABUSA_CONTROLLER_DATA") or "/var/lib/hayabusa-controller").rstrip("/")
    return f"{root}/guacamole_account_secrets.json"


def _safe_label(value: str, *, max_len: int = 96) -> str:
    v = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(value or "").strip()).strip("-")
    return (v[:max_len] if v else "x")


def entity_username_for_account(account_id: str) -> str:
    return f"{_ENTITY_PREFIX}{_safe_label(account_id, max_len=80)}"[:128]


def group_name_lan(account_id: str) -> str:
    return f"ctrl-lan-{_safe_label(account_id, max_len=80)}"[:128]


def _load_secrets(path: str) -> dict:
    try:
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception as exc:
        logger.warning("guacamole secrets read: %s", exc)
    return {"version": 1, "accounts": {}}


def _save_secrets(path: str, state: dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
        f.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _account_password(path: str, account_id: str, username: str) -> str:
    with _LOCK:
        state = _load_secrets(path)
        accounts = state.setdefault("accounts", {})
        rec = accounts.get(account_id)
        if isinstance(rec, dict) and rec.get("password"):
            return str(rec["password"])
        password = secrets.token_urlsafe(24)
        accounts[account_id] = {"username": username, "password": password}
        state["accounts"] = accounts
        _save_secrets(path, state)
        return password


def _guac_api_request(
    method: str,
    path: str,
    *,
    token: str | None = None,
    json_body: dict | list | None = None,
    form_body: dict[str, str] | None = None,
    timeout: int = 25,
) -> tuple[int, Any]:
    base = _guac_internal_base()
    url = f"{base}/guacamole/api{path}"
    headers: dict[str, str] = {}
    if token:
        headers["Guacamole-Token"] = token
    data: bytes | None = None
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif form_body is not None:
        data = urllib.parse.urlencode(form_body).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, method=method.upper(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            if not raw:
                return resp.status, None
            return resp.status, json.loads(raw.decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            payload = json.loads(body.decode("utf-8", errors="replace")) if body else None
        except Exception:
            payload = body.decode("utf-8", errors="replace")[:500] if body else None
        return exc.code, payload


def guacamole_obtain_token(username: str, password: str) -> dict | None:
    status, payload = _guac_api_request(
        "POST",
        "/tokens",
        token=None,
        form_body={"username": username, "password": password},
    )
    if status == 200 and isinstance(payload, dict) and payload.get("authToken"):
        return payload
    logger.warning("guacamole token HTTP %s for %s: %s", status, username, payload)
    return None


def _guac_admin_token() -> str | None:
    user, password = _guac_admin_credentials()
    payload = guacamole_obtain_token(user, password)
    if payload and payload.get("authToken"):
        return str(payload["authToken"])
    return None


def _session_path(subpath: str) -> str:
    return f"/session/data/{_DATA_SOURCE}{subpath}"


def _get_root_tree(admin_token: str) -> dict:
    status, payload = _guac_api_request(
        "GET",
        _session_path("/connectionGroups/ROOT/tree"),
        token=admin_token,
    )
    if status != 200 or not isinstance(payload, dict):
        raise RuntimeError(f"Guacamole tree fetch failed ({status}): {payload}")
    return payload


def _iter_connection_groups(node: dict):
    for child in node.get("childConnectionGroups") or []:
        if not isinstance(child, dict):
            continue
        yield child
        yield from _iter_connection_groups(child)


def _find_group_identifier(tree: dict, name: str, *, parent_identifier: str = "ROOT") -> str | None:
    for group in _iter_connection_groups(tree):
        if str(group.get("name") or "") == name and str(group.get("parentIdentifier") or "ROOT") == parent_identifier:
            return str(group.get("identifier") or "")
    return None


def _group_child_connections(tree: dict, group_identifier: str) -> list[dict]:
    if str(tree.get("identifier") or "") == group_identifier:
        return [c for c in (tree.get("childConnections") or []) if isinstance(c, dict)]
    for group in _iter_connection_groups(tree):
        if str(group.get("identifier") or "") == group_identifier:
            return [c for c in (group.get("childConnections") or []) if isinstance(c, dict)]
    return []


def _ensure_connection_group(admin_token: str, name: str) -> str:
    tree = _get_root_tree(admin_token)
    existing = _find_group_identifier(tree, name, parent_identifier="ROOT")
    if existing:
        return existing
    status, payload = _guac_api_request(
        "POST",
        _session_path("/connectionGroups"),
        token=admin_token,
        json_body={
            "name": name,
            "parentIdentifier": "ROOT",
            "type": "ORGANIZATIONAL",
            "attributes": {},
        },
    )
    if status != 200 or not isinstance(payload, dict):
        raise RuntimeError(f"create connection group {name!r} failed ({status}): {payload}")
    return str(payload.get("identifier") or "")


def _create_guacamole_user(admin_token: str, username: str, password: str) -> None:
    status, payload = _guac_api_request(
        "POST",
        _session_path("/users"),
        token=admin_token,
        json_body={
            "username": username,
            "password": password,
            "attributes": {"disabled": "", "expired": ""},
        },
    )
    if status in (200, 204):
        return
    if status == 400 and isinstance(payload, dict) and "exists" in str(payload.get("message", "")).lower():
        return
    raise RuntimeError(f"create user {username!r} failed ({status}): {payload}")


def _delete_guacamole_user(admin_token: str, username: str) -> None:
    status, payload = _guac_api_request(
        "DELETE",
        _session_path(f"/users/{urllib.parse.quote(username, safe='')}"),
        token=admin_token,
    )
    if status not in (200, 204, 404):
        logger.warning("delete user %s failed (%s): %s", username, status, payload)


def _ensure_guacamole_user(admin_token: str, username: str, password: str) -> None:
    status, users = _guac_api_request("GET", _session_path("/users"), token=admin_token)
    if status != 200:
        raise RuntimeError(f"list users failed ({status}): {users}")
    exists = isinstance(users, dict) and username in users
    if not exists:
        _create_guacamole_user(admin_token, username, password)
        return
    status, payload = _guac_api_request(
        "PUT",
        _session_path(f"/users/{urllib.parse.quote(username, safe='')}"),
        token=admin_token,
        json_body={"username": username, "password": password},
    )
    if status in (200, 204):
        return
    if status == 500:
        logger.warning("guacamole user %s password PUT failed; recreating user via REST", username)
        _delete_guacamole_user(admin_token, username)
        _create_guacamole_user(admin_token, username, password)
        return
    raise RuntimeError(f"set password for {username!r} failed ({status}): {payload}")


def _connection_title(host: dict) -> str:
    hn = str(host.get("hostname") or host.get("name") or "").strip() or str(host.get("ip") or "host")
    ip = str(host.get("ip") or "").strip()
    return f"{hn} ({ip})"[:128]


def _peer_key(host: dict) -> str:
    return f"lan:{_safe_label(str(host.get('ip') or ''), max_len=48)}"


def _connection_guac_name(peer_key: str, host: dict) -> str:
    return f"{_CONN_NAME_PREFIX}{peer_key}|{_connection_title(host)}"[:128]


def _peer_key_from_connection_name(name: str) -> str | None:
    if not name.startswith(_CONN_NAME_PREFIX):
        return None
    rest = name[len(_CONN_NAME_PREFIX) :]
    if "|" not in rest:
        return None
    pk, _, _title = rest.partition("|")
    return pk.strip() or None


def _connection_body(
    *,
    name: str,
    identifier: str | None,
    parent_identifier: str,
    hostname: str,
    ssh_user: str,
    ssh_password: str | None,
) -> dict:
    params: dict[str, str] = {
        "hostname": hostname,
        "port": "22",
        "username": ssh_user,
    }
    if ssh_password:
        params["password"] = ssh_password
    body: dict[str, Any] = {
        "name": name,
        "parentIdentifier": parent_identifier,
        "protocol": "ssh",
        "parameters": params,
        "attributes": {},
    }
    if identifier:
        body["identifier"] = identifier
    return body


def _upsert_ssh_connection(
    admin_token: str,
    *,
    group_id: str,
    peer_key: str,
    host: dict,
    ssh_user: str,
    ssh_password: str | None,
    tree: dict,
) -> dict:
    guac_name = _connection_guac_name(peer_key, host)
    ip = str(host.get("ip") or "").strip()
    existing_id: str | None = None
    for conn in _group_child_connections(tree, group_id):
        cid = str(conn.get("identifier") or "")
        cname = str(conn.get("name") or "")
        pk = _peer_key_from_connection_name(cname)
        if pk == peer_key or cname == guac_name:
            existing_id = cid
            break
    body = _connection_body(
        name=guac_name,
        identifier=existing_id,
        parent_identifier=group_id,
        hostname=ip,
        ssh_user=ssh_user,
        ssh_password=ssh_password,
    )
    if existing_id:
        status, payload = _guac_api_request(
            "PUT",
            _session_path(f"/connections/{urllib.parse.quote(existing_id, safe='')}"),
            token=admin_token,
            json_body=body,
        )
        if status not in (200, 204):
            raise RuntimeError(f"update connection {existing_id} failed ({status}): {payload}")
        conn_id = existing_id
    else:
        status, payload = _guac_api_request(
            "POST",
            _session_path("/connections"),
            token=admin_token,
            json_body=body,
        )
        if status != 200 or not isinstance(payload, dict):
            raise RuntimeError(f"create connection failed ({status}): {payload}")
        conn_id = str(payload.get("identifier") or "")
    return {
        "connection_id": conn_id,
        "hostname": ip,
        "name": _connection_title(host),
        "peer_key": peer_key,
    }


def _delete_connection(admin_token: str, connection_id: str) -> None:
    status, payload = _guac_api_request(
        "DELETE",
        _session_path(f"/connections/{urllib.parse.quote(connection_id, safe='')}"),
        token=admin_token,
    )
    if status not in (200, 204, 404):
        logger.warning("delete connection %s: %s %s", connection_id, status, payload)


def _prune_stale_connections(admin_token: str, tree: dict, group_id: str, keep_peer_keys: set[str]) -> None:
    for conn in _group_child_connections(tree, group_id):
        cname = str(conn.get("name") or "")
        pk = _peer_key_from_connection_name(cname)
        if not pk or pk in keep_peer_keys:
            continue
        _delete_connection(admin_token, str(conn.get("identifier") or ""))


def _grant_user_permissions(
    admin_token: str,
    username: str,
    *,
    connection_ids: list[str],
    group_ids: list[str],
) -> None:
    ops: list[dict] = []
    for gid in group_ids:
        if gid:
            ops.append({"op": "add", "path": f"/connectionGroupPermissions/{gid}", "value": "READ"})
    for cid in connection_ids:
        if cid:
            ops.append({"op": "add", "path": f"/connectionPermissions/{cid}", "value": "READ"})
    if not ops:
        return
    status, payload = _guac_api_request(
        "PATCH",
        _session_path(f"/users/{urllib.parse.quote(username, safe='')}/permissions"),
        token=admin_token,
        json_body=ops,
    )
    if status not in (200, 204):
        logger.warning("grant permissions for %s failed (%s): %s", username, status, payload)


def _resolve_ssh_from_vault(vault: Any) -> tuple[str, str | None]:
    ssh_user = ""
    ssh_password = None
    if vault is None:
        return (os.environ.get("CONTROLLER_PEER_SSH_USER") or "root").strip() or "root", (
            os.environ.get("CONTROLLER_PEER_SSH_PASSWORD") or ""
        ).strip() or None
    for key in _DEFAULT_USER_KEYS:
        try:
            val = vault.get(key, allow_reserved=False)
        except Exception:
            val = None
        if val is not None and str(val).strip():
            ssh_user = str(val).strip()
            break
    for key in _DEFAULT_PASSWORD_KEYS:
        try:
            val = vault.get(key, allow_reserved=False)
        except Exception:
            val = None
        if val is not None and str(val).strip():
            ssh_password = str(val).strip()
            break
    if not ssh_user:
        ssh_user = (os.environ.get("CONTROLLER_PEER_SSH_USER") or "root").strip() or "root"
    if not ssh_password:
        env_pw = (os.environ.get("CONTROLLER_PEER_SSH_PASSWORD") or "").strip()
        ssh_password = env_pw or None
    return ssh_user, ssh_password


def guacamole_sync_for_user(
    *,
    account_id: str,
    display_name: str = "",
    vault: Any = None,
    data_dir: str | None = None,
    lan_hosts: list[dict] | None = None,
) -> dict[str, Any]:
    """Provision Guacamole user + LAN SSH connections for a controller session user."""
    if not guacamole_sync_enabled():
        return {"success": False, "error": "Guacamole sync disabled", "synced": False}
    if not _guac_admin_configured():
        return {"success": False, "error": "Guacamole admin credentials not configured", "synced": False}

    admin_token = _guac_admin_token()
    if not admin_token:
        return {"success": False, "error": "Guacamole admin authentication failed", "synced": False}

    account_id = _safe_label(account_id or display_name or "user", max_len=80)
    username = entity_username_for_account(account_id)
    password = _account_password(_secrets_path(data_dir), account_id, username)
    ssh_user, ssh_password = _resolve_ssh_from_vault(vault)

    hosts: list[dict] = []
    for h in lan_hosts or []:
        if not isinstance(h, dict):
            continue
        ip = str(h.get("ip") or "").strip()
        if not ip or ":" in ip or ip.startswith("127."):
            continue
        if h.get("self"):
            continue
        hosts.append(h)

    connections: list[dict] = []
    try:
        _ensure_guacamole_user(admin_token, username, password)
        group_id = _ensure_connection_group(admin_token, group_name_lan(account_id))
        keep: set[str] = set()
        tree = _get_root_tree(admin_token)
        for host in hosts[:200]:
            pk = _peer_key(host)
            keep.add(pk)
            tree = _get_root_tree(admin_token)
            connections.append(
                _upsert_ssh_connection(
                    admin_token,
                    group_id=group_id,
                    peer_key=pk,
                    host=host,
                    ssh_user=ssh_user,
                    ssh_password=ssh_password,
                    tree=tree,
                )
            )
        tree = _get_root_tree(admin_token)
        _prune_stale_connections(admin_token, tree, group_id, keep)
        _grant_user_permissions(
            admin_token,
            username,
            connection_ids=[str(c.get("connection_id") or "") for c in connections],
            group_ids=[group_id],
        )
    except Exception as exc:
        logger.exception("controller guacamole sync failed")
        return {"success": False, "error": str(exc), "synced": False}

    token_payload = guacamole_obtain_token(username, password)
    return {
        "success": True,
        "synced": True,
        "username": username,
        "account_id": account_id,
        "connections": connections,
        "authToken": (token_payload or {}).get("authToken"),
        "dataSource": (token_payload or {}).get("dataSource") or _DATA_SOURCE,
        "availableDataSources": (token_payload or {}).get("availableDataSources") or [_DATA_SOURCE],
    }
