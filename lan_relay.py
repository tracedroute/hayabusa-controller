"""Thin LAN relay: hydrate secret *names* locally and open SSH to LAN devices.

Hayabusa Core runs Ansible/OpenTofu/SECops. This module must NOT invoke
ansible-playbook, tofu, nuclei, or other product tool stacks — only SSH/TCP
forwarding with vault values that never leave this process in RPC responses.
"""

from __future__ import annotations

import logging
import os
import re
import secrets
import shlex
import subprocess
import tempfile
import threading
import time
from typing import Any, Callable

logger = logging.getLogger("hayabusa-controller.lan_relay")

_SECRET_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
# Playbook markers Core may leave literal; we expand only on the controller.
_SECRET_MARKERS = (
    re.compile(r"\{\{\s*hayabusa_secret:([A-Za-z][A-Za-z0-9_.-]{0,127})\s*\}\}"),
    re.compile(r"<<SECRET:([A-Za-z][A-Za-z0-9_.-]{0,127})>>"),
    re.compile(r"\{\{\s*hayabusa_secret\(['\"]([A-Za-z][A-Za-z0-9_.-]{0,127})['\"]\)\s*\}\}"),
)

_LOCK = threading.RLock()
_SESSIONS: dict[str, dict[str, Any]] = {}
_SESSION_TTL_SEC = 30 * 60


def _now() -> float:
    return time.time()


def _purge_expired() -> None:
    cutoff = _now() - _SESSION_TTL_SEC
    dead = [sid for sid, row in _SESSIONS.items() if float(row.get("opened_at") or 0) < cutoff]
    for sid in dead:
        _SESSIONS.pop(sid, None)


def _ssh_string(payload: bytes) -> bytes:
    import struct

    return struct.pack(">I", len(payload)) + payload


def is_secret_name(key: str) -> bool:
    k = (key or "").strip()
    if not k or not _SECRET_NAME_RE.match(k):
        return False
    # Reject values that look like passwords (too long / whitespace / obvious secrets).
    if any(ch.isspace() for ch in k):
        return False
    if len(k) > 128:
        return False
    return True


def expand_secret_markers(text: str, resolve: Callable[[str], str | None]) -> str:
    """Replace secret-name markers using resolve(name)->value. Never used in RPC replies."""

    def _sub(match: re.Match[str]) -> str:
        name = match.group(1)
        val = resolve(name)
        return val if val is not None else match.group(0)

    out = text
    for pat in _SECRET_MARKERS:
        out = pat.sub(_sub, out)
    return out


class LanRelay:
    def __init__(
        self,
        *,
        vault_get: Callable[[str], str | None],
        job_approved: Callable[[str], bool],
        job_touch: Callable[[str], None] | None = None,
    ) -> None:
        self._vault_get = vault_get
        self._job_approved = job_approved
        self._job_touch = job_touch

    def open_session(self, params: dict[str, Any]) -> dict[str, Any]:
        """Open an SSH session to a LAN host using a vault secret *name*."""
        params = dict(params) if isinstance(params, dict) else {}
        # Hard reject any attempt to pass raw passwords from Core.
        for bad in ("password", "secret_value", "secret_values", "token", "private_key_pem"):
            if params.get(bad):
                return {
                    "ok": False,
                    "error": f"{bad} is not accepted — send secret_key name only",
                    "code": "secret_value_rejected",
                }

        job_id = str(params.get("job_id") or "").strip()
        host = str(params.get("host") or params.get("hostname") or "").strip()
        username = str(params.get("username") or params.get("user") or "").strip() or "root"
        secret_key = str(params.get("secret_key") or params.get("password_secret_key") or "").strip()
        try:
            port = int(params.get("port") or 22)
        except (TypeError, ValueError):
            port = 22
        port = max(1, min(port, 65535))

        if not job_id:
            return {"ok": False, "error": "job_id required", "code": "bad_request"}
        if not host or ".." in host or any(ch.isspace() for ch in host):
            return {"ok": False, "error": "invalid host", "code": "bad_host"}
        if not is_secret_name(secret_key):
            return {
                "ok": False,
                "error": "secret_key must be a vault secret name",
                "code": "bad_secret_key",
            }
        if not self._job_approved(job_id):
            return {
                "ok": False,
                "error": "job not LAN-approved for relay",
                "code": "not_approved",
            }

        password = self._vault_get(secret_key)
        if password is None or password == "":
            return {
                "ok": False,
                "error": f"vault secret missing: {secret_key}",
                "code": "secret_missing",
            }

        sid = secrets.token_hex(16)
        with _LOCK:
            _purge_expired()
            _SESSIONS[sid] = {
                "id": sid,
                "job_id": job_id,
                "host": host,
                "port": port,
                "username": username,
                "secret_key": secret_key,
                "password": password,
                "opened_at": _now(),
            }
        logger.info(
            "lan.relay session opened id=%s job=%s host=%s user=%s secret_key=%s",
            sid[:8],
            job_id[:12],
            host,
            username,
            secret_key,
        )
        return {
            "ok": True,
            "session_id": sid,
            "host": host,
            "port": port,
            "username": username,
            "secret_key": secret_key,
            "protocol": "ssh",
            "values_ephemeral": True,
            "hayabusa_saw_secret_values": False,
        }

    def _get_session(self, session_id: str) -> dict[str, Any] | None:
        with _LOCK:
            _purge_expired()
            row = _SESSIONS.get(str(session_id or "").strip())
            return dict(row) if isinstance(row, dict) else None

    def close_session(self, params: dict[str, Any]) -> dict[str, Any]:
        sid = str(params.get("session_id") or params.get("id") or "").strip()
        with _LOCK:
            row = _SESSIONS.pop(sid, None)
        if row and isinstance(row.get("password"), str):
            row["password"] = ""
        return {"ok": True, "closed": bool(row), "session_id": sid}

    def _ssh_run(
        self,
        *,
        host: str,
        port: int,
        username: str,
        password: str,
        argv: list[str],
        input_bytes: bytes | None = None,
        timeout_sec: int = 120,
    ) -> dict[str, Any]:
        """Run ssh with askpass so the password never appears on argv."""
        ask = tempfile.NamedTemporaryFile("w", prefix="hayabusa-askpass-", delete=False, encoding="utf-8")
        try:
            ask.write("#!/bin/sh\nprintf '%s\\n' \"$HAYABUSA_RELAY_PASS\"\n")
            ask.close()
            os.chmod(ask.name, 0o700)
            env = os.environ.copy()
            env["HAYABUSA_RELAY_PASS"] = password
            env["SSH_ASKPASS"] = ask.name
            env["SSH_ASKPASS_REQUIRE"] = "force"
            env["DISPLAY"] = env.get("DISPLAY") or ":99"
            # Prefer batch + askpass; disable host key prompts for appliance LAN use.
            base = [
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "GlobalKnownHostsFile=/dev/null",
                "-o",
                "PreferredAuthentications=password,keyboard-interactive",
                "-o",
                "PubkeyAuthentication=no",
                "-o",
                "NumberOfPasswordPrompts=1",
                "-p",
                str(port),
                "-l",
                username,
                host,
            ]
            cmd = base + argv
            try:
                proc = subprocess.run(
                    cmd,
                    input=input_bytes,
                    capture_output=True,
                    timeout=max(5, min(int(timeout_sec), 3600)),
                    env=env,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return {
                    "ok": False,
                    "error": "ssh timeout",
                    "code": "timeout",
                    "returncode": 124,
                    "stdout": "",
                    "stderr": "ssh timeout",
                }
            except FileNotFoundError:
                return {
                    "ok": False,
                    "error": "ssh client not installed on controller",
                    "code": "ssh_missing",
                    "returncode": 127,
                    "stdout": "",
                    "stderr": "ssh not found",
                }
            stdout = proc.stdout.decode("utf-8", errors="replace") if proc.stdout else ""
            stderr = proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""
            # Never echo password if ssh printed it somehow.
            if password and len(password) >= 4:
                stdout = stdout.replace(password, "****")
                stderr = stderr.replace(password, "****")
            return {
                "ok": proc.returncode == 0,
                "returncode": int(proc.returncode),
                "stdout": stdout[:200000],
                "stderr": stderr[:80000],
                "error": "" if proc.returncode == 0 else (stderr.strip() or f"ssh exit {proc.returncode}")[:400],
            }
        finally:
            try:
                os.unlink(ask.name)
            except OSError:
                pass
            env_pass = os.environ.get("HAYABUSA_RELAY_PASS")
            if env_pass:
                os.environ.pop("HAYABUSA_RELAY_PASS", None)

    def exec_command(self, params: dict[str, Any]) -> dict[str, Any]:
        sess = self._get_session(str(params.get("session_id") or ""))
        if not sess:
            return {"ok": False, "error": "session not found", "code": "no_session"}
        if not self._job_approved(str(sess.get("job_id") or "")):
            return {"ok": False, "error": "job not approved", "code": "not_approved"}

        command = params.get("command")
        if isinstance(command, list):
            remote = " ".join(str(c) for c in command[:80])
        else:
            remote = str(command or "").strip()
        if not remote:
            return {"ok": False, "error": "command required", "code": "bad_request"}

        def _resolve(name: str) -> str | None:
            return self._vault_get(name)

        remote = expand_secret_markers(remote, _resolve)
        try:
            timeout_sec = int(params.get("timeout_sec") or params.get("timeout") or 120)
        except (TypeError, ValueError):
            timeout_sec = 120

        result = self._ssh_run(
            host=str(sess["host"]),
            port=int(sess["port"]),
            username=str(sess["username"]),
            password=str(sess["password"]),
            argv=[f"bash -lc {shlex.quote(remote)}"],
            timeout_sec=timeout_sec,
        )
        result["session_id"] = sess["id"]
        result["hayabusa_saw_secret_values"] = False
        return result

    def put_file(self, params: dict[str, Any]) -> dict[str, Any]:
        sess = self._get_session(str(params.get("session_id") or ""))
        if not sess:
            return {"ok": False, "error": "session not found", "code": "no_session"}
        if not self._job_approved(str(sess.get("job_id") or "")):
            return {"ok": False, "error": "job not approved", "code": "not_approved"}

        dest = str(params.get("dest") or params.get("path") or "").strip()
        if not dest or ".." in dest.split("/"):
            return {"ok": False, "error": "invalid dest path", "code": "bad_path"}

        encoding = str(params.get("encoding") or "utf-8").strip().lower()
        raw: bytes
        if encoding in {"base64", "b64"}:
            import base64

            b64 = params.get("content_b64") or params.get("content") or ""
            if not isinstance(b64, str) or not b64:
                return {"ok": False, "error": "content_b64 required", "code": "bad_request"}
            try:
                raw = base64.b64decode(b64, validate=False)
            except Exception as exc:  # noqa: BLE001
                return {"ok": False, "error": f"invalid base64: {exc}"[:200], "code": "bad_b64"}
        else:
            content = params.get("content")
            if not isinstance(content, str):
                return {"ok": False, "error": "content string required", "code": "bad_request"}

            def _resolve(name: str) -> str | None:
                return self._vault_get(name)

            expanded = expand_secret_markers(content, _resolve)
            raw = expanded.encode("utf-8")

        if len(raw) > 2_000_000:
            return {"ok": False, "error": "content too large", "code": "too_large"}

        dest_q = shlex.quote(dest)
        result = self._ssh_run(
            host=str(sess["host"]),
            port=int(sess["port"]),
            username=str(sess["username"]),
            password=str(sess["password"]),
            argv=[f"bash -lc {shlex.quote(f'cat > {dest_q}')}"],
            input_bytes=raw,
            timeout_sec=int(params.get("timeout_sec") or 120),
        )
        # Do not return file body.
        result.pop("stdout", None)
        result["session_id"] = sess["id"]
        result["bytes"] = len(raw)
        result["dest"] = dest
        result["hayabusa_saw_secret_values"] = False
        result["ok"] = bool(result.get("ok"))
        return result

    def http_forward(self, params: dict[str, Any]) -> dict[str, Any]:
        """Forward one HTTPS call to a private LAN host.

        Core runs OpenTofu. Password markers in the request body are expanded
        here and the vault value is never returned. This does not invoke tofu
        or ansible.
        """
        import base64
        import ipaddress
        import ssl
        import urllib.error
        import urllib.parse
        import urllib.request

        params = dict(params) if isinstance(params, dict) else {}
        for bad in ("password", "secret_value", "secret_values", "token", "private_key_pem"):
            if params.get(bad):
                return {
                    "ok": False,
                    "error": f"{bad} is not accepted — send secret names only",
                    "code": "secret_value_rejected",
                }

        job_id = str(params.get("job_id") or "").strip()
        host = str(params.get("host") or "").strip()
        secret_keys = params.get("secret_keys") if isinstance(params.get("secret_keys"), list) else []
        allowed = {str(k).strip() for k in secret_keys if is_secret_name(str(k).strip())}
        method = str(params.get("method") or "GET").strip().upper()
        path = str(params.get("path") or "/").strip()
        if not job_id:
            return {"ok": False, "error": "job_id required", "code": "bad_request"}
        if method not in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"}:
            return {"ok": False, "error": "method not allowed", "code": "bad_method"}
        if not path.startswith("/") or path.startswith("//") or "\\" in path:
            return {"ok": False, "error": "invalid path", "code": "bad_path"}
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return {"ok": False, "error": "host must be a private IP", "code": "bad_host"}
        if (not ip.is_private) or ip.is_link_local or ip.is_loopback or ip.is_multicast or ip.is_unspecified:
            return {"ok": False, "error": "host must be a private LAN address", "code": "bad_host"}
        try:
            port = int(params.get("port") or 443)
        except (TypeError, ValueError):
            port = 443
        if port < 1 or port > 65535:
            return {"ok": False, "error": "invalid port", "code": "bad_port"}
        if not self._job_approved(job_id):
            return {"ok": False, "error": "job not LAN-approved for relay", "code": "not_approved"}
        if self._job_touch is not None:
            self._job_touch(job_id)

        raw_b64 = params.get("body_b64") or ""
        if raw_b64 and not isinstance(raw_b64, str):
            return {"ok": False, "error": "body_b64 must be a string", "code": "bad_request"}
        try:
            body = base64.b64decode(raw_b64, validate=False) if raw_b64 else b""
        except Exception:
            return {"ok": False, "error": "invalid body_b64", "code": "bad_b64"}
        if len(body) > 4_000_000:
            return {"ok": False, "error": "body too large", "code": "too_large"}

        headers_in = params.get("headers") if isinstance(params.get("headers"), dict) else {}
        headers: dict[str, str] = {}
        for key, val in list(headers_in.items())[:20]:
            name = str(key or "").strip()
            if name.lower() not in {"content-type", "accept", "cookie", "csrfpreventiontoken", "authorization"}:
                continue
            headers[name] = str(val or "")[:8000]

        used: list[str] = []

        def _resolve(name: str) -> str | None:
            if allowed and name not in allowed:
                return None
            if not is_secret_name(name):
                return None
            val = self._vault_get(name)
            if val:
                used.append(val)
            return val

        if body and (b"hayabusa_secret" in body or b"<<SECRET:" in body):
            text = body.decode("utf-8", errors="replace")
            ctype = headers.get("Content-Type") or headers.get("content-type") or ""
            if "application/x-www-form-urlencoded" in ctype.lower() or "password=" in text:
                pairs = urllib.parse.parse_qsl(text, keep_blank_values=True)
                body = urllib.parse.urlencode(
                    [(key, expand_secret_markers(val, _resolve)) for key, val in pairs]
                ).encode("utf-8")
            else:
                body = expand_secret_markers(text, _resolve).encode("utf-8")

        url = f"https://{host}:{port}{path}"
        data = None if method in {"GET", "HEAD"} else body
        req = urllib.request.Request(url, data=data, method=method)
        for key, val in headers.items():
            req.add_header(key, val)
        req.add_header("Host", f"{host}:{port}")
        ctx = ssl._create_unverified_context()
        status = 502
        resp_body = b""
        resp_headers: dict[str, str] = {}
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
                status = int(getattr(resp, "status", 200) or 200)
                resp_body = resp.read(6_000_001)
                resp_headers = {k: v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as exc:
            status = int(exc.code or 502)
            try:
                resp_body = exc.read(6_000_001) or b""
            except Exception:
                resp_body = b""
            resp_headers = {k: v for k, v in (exc.headers.items() if exc.headers else [])}
        except Exception as exc:  # noqa: BLE001
            logger.info(
                "lan.relay http failed job=%s host=%s port=%s method=%s",
                job_id[:12],
                host,
                port,
                method,
            )
            return {
                "ok": False,
                "error": "upstream unreachable",
                "code": "upstream_failed",
                "hayabusa_saw_secret_values": False,
            }
        if len(resp_body) > 6_000_000:
            return {
                "ok": False,
                "error": "upstream response too large",
                "code": "too_large",
                "hayabusa_saw_secret_values": False,
            }
        for secret in used:
            if not secret:
                continue
            encoded = secret.encode("utf-8", errors="ignore")
            if len(secret) >= 12:
                resp_body = resp_body.replace(encoded, b"****")
                for key, val in list(resp_headers.items()):
                    resp_headers[key] = str(val).replace(secret, "****")
            else:
                # Short vault values can match ordinary JSON keys. Scrub values only.
                resp_body = resp_body.replace(b': "' + encoded + b'"', b': "****"')
                resp_body = resp_body.replace(b':"' + encoded + b'"', b':"****"')
        keep = {}
        for key, val in resp_headers.items():
            if key.lower() in {"content-type", "set-cookie", "csrfpreventiontoken"}:
                keep[key] = str(val)[:8000]
        logger.info(
            "lan.relay http job=%s host=%s port=%s method=%s status=%s",
            job_id[:12],
            host,
            port,
            method,
            status,
        )
        return {
            "ok": True,
            "status": status,
            "headers": keep,
            "body_b64": base64.b64encode(resp_body).decode("ascii"),
            "hayabusa_saw_secret_values": False,
        }

    def _relay_keypair(self) -> tuple[str, str]:
        """Ed25519 key that stays on this controller. Core only ever sees the public key."""
        base = (os.environ.get("CONTROLLER_DATA_DIR") or "/var/lib/hayabusa-controller").strip()
        directory = os.path.join(base, "ssh-relay")
        priv = os.path.join(directory, "id_ed25519")
        pub = os.path.join(directory, "id_ed25519.pub")
        os.makedirs(directory, mode=0o700, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
        if not (os.path.isfile(priv) and os.path.isfile(pub)):
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-f", priv, "-N", "", "-C", "hayabusa-lan-relay"],
                check=True,
                capture_output=True,
                timeout=20,
            )
        os.chmod(priv, 0o600)
        return priv, pub

    def ssh_prepare(self, params: dict[str, Any]) -> dict[str, Any]:
        """Install this controller's relay public key on a LAN host. Password stays here."""
        import ipaddress

        params = dict(params) if isinstance(params, dict) else {}
        for bad in ("password", "secret_value", "secret_values", "token", "private_key_pem"):
            if params.get(bad):
                return {
                    "ok": False,
                    "error": f"{bad} is not accepted — send secret names only",
                    "code": "secret_value_rejected",
                }
        job_id = str(params.get("job_id") or "").strip()
        host = str(params.get("host") or "").strip()
        secret_key = str(params.get("secret_key") or "").strip()
        username = str(params.get("username") or "root").strip() or "root"
        try:
            port = int(params.get("port") or 22)
        except (TypeError, ValueError):
            port = 22
        if not job_id:
            return {"ok": False, "error": "job_id required", "code": "bad_request"}
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", username):
            return {"ok": False, "error": "invalid username", "code": "bad_user"}
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return {"ok": False, "error": "host must be a private IP", "code": "bad_host"}
        if (not ip.is_private) or ip.is_link_local or ip.is_loopback or ip.is_multicast or ip.is_unspecified:
            return {"ok": False, "error": "host must be a private LAN address", "code": "bad_host"}
        if not is_secret_name(secret_key):
            return {"ok": False, "error": "secret_key must be a vault secret name", "code": "bad_secret_key"}
        if not self._job_approved(job_id):
            return {"ok": False, "error": "job not LAN-approved for relay", "code": "not_approved"}
        if self._job_touch is not None:
            self._job_touch(job_id)
        try:
            _priv, pub_path = self._relay_keypair()
            public_key = open(pub_path, encoding="utf-8").read().strip()
        except (OSError, subprocess.SubprocessError) as exc:
            logger.warning("lan.relay ssh key unavailable: %s", type(exc).__name__)
            return {"ok": False, "error": "relay key unavailable", "code": "ssh_key_unavailable"}
        if not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]{40,}={0,2} hayabusa-lan-relay", public_key):
            return {"ok": False, "error": "relay public key rejected", "code": "bad_public_key"}
        opened = self.open_session(
            {
                "job_id": job_id,
                "host": host,
                "port": port,
                "username": username,
                "secret_key": secret_key,
            }
        )
        if not opened.get("ok"):
            opened["hayabusa_saw_secret_values"] = False
            return opened
        sid = str(opened.get("session_id") or "")
        quoted = shlex.quote(public_key)
        command = (
            "umask 077; mkdir -p ~/.ssh; chmod 700 ~/.ssh; "
            "touch ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys; "
            f"grep -qxF {quoted} ~/.ssh/authorized_keys || printf '%s\\n' {quoted} >> ~/.ssh/authorized_keys"
        )
        try:
            installed = self.exec_command({"session_id": sid, "command": command, "timeout_sec": 60})
        finally:
            self.close_session({"session_id": sid})
        if not installed.get("ok"):
            return {
                "ok": False,
                "error": "could not install relay key on the LAN host",
                "code": "ssh_prepare_failed",
                "hayabusa_saw_secret_values": False,
            }
        logger.info("lan.relay ssh key installed job=%s host=%s user=%s", job_id[:12], host, username)
        return {
            "ok": True,
            "public_key": public_key,
            "username": username,
            "host": host,
            "port": port,
            "hayabusa_saw_secret_values": False,
        }

    def ssh_sign(self, params: dict[str, Any]) -> dict[str, Any]:
        """Sign one SSH challenge. The private key never leaves this controller."""
        import base64

        params = dict(params) if isinstance(params, dict) else {}
        for bad in ("password", "secret_value", "secret_values", "token", "private_key_pem"):
            if params.get(bad):
                return {
                    "ok": False,
                    "error": f"{bad} is not accepted",
                    "code": "secret_value_rejected",
                }
        job_id = str(params.get("job_id") or "").strip()
        if not job_id or not self._job_approved(job_id):
            return {"ok": False, "error": "job not LAN-approved for relay", "code": "not_approved"}
        if self._job_touch is not None:
            self._job_touch(job_id)
        raw_b64 = params.get("data_b64") or ""
        if not isinstance(raw_b64, str) or not raw_b64:
            return {"ok": False, "error": "data_b64 required", "code": "bad_request"}
        try:
            data = base64.b64decode(raw_b64, validate=False)
        except Exception:
            return {"ok": False, "error": "invalid data_b64", "code": "bad_b64"}
        if not data or len(data) > 1_000_000:
            return {"ok": False, "error": "sign payload rejected", "code": "bad_request"}
        try:
            from cryptography.hazmat.primitives.serialization import load_ssh_private_key

            priv, _pub = self._relay_keypair()
            key = load_ssh_private_key(open(priv, "rb").read(), password=None)
            raw_sig = key.sign(data)
        except Exception as exc:  # noqa: BLE001
            logger.warning("lan.relay ssh_sign failed job=%s err=%s", job_id[:12], type(exc).__name__)
            return {"ok": False, "error": "sign failed", "code": "sign_failed", "hayabusa_saw_secret_values": False}
        blob = _ssh_string(b"ssh-ed25519") + _ssh_string(raw_sig)
        logger.info("lan.relay ssh_sign job=%s bytes=%s", job_id[:12], len(data))
        return {
            "ok": True,
            "signature_b64": base64.b64encode(blob).decode("ascii"),
            "hayabusa_saw_secret_values": False,
        }

    def ping(self, params: dict[str, Any]) -> dict[str, Any]:
        """Connectivity check: open, echo, close — for Core health checks."""
        opened = self.open_session(params)
        if not opened.get("ok"):
            return opened
        sid = str(opened.get("session_id") or "")
        try:
            exec_out = self.exec_command(
                {"session_id": sid, "command": "echo hayabusa-lan-relay-ok", "timeout_sec": 30}
            )
            return {
                "ok": bool(exec_out.get("ok")),
                "session_id": sid,
                "stdout": str(exec_out.get("stdout") or "")[:200],
                "stderr": str(exec_out.get("stderr") or "")[:200],
                "error": exec_out.get("error") or "",
                "hayabusa_saw_secret_values": False,
            }
        finally:
            self.close_session({"session_id": sid})
