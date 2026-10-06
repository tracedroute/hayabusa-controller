#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${CONTROLLER_DATA_DIR:-/var/lib/hayabusa-controller}"
WS_DIR="${CONTROLLER_DEVOPS_WORKSPACE:-$DATA_DIR/iac/workspace}"
DEFAULTS="${CONTROLLER_DEVOPS_DEFAULTS:-/opt/hayabusa-controller/devops_iac_defaults}"
BOOTSTRAP="${DATA_DIR}/bootstrap.env"
mkdir -p "$DATA_DIR" "$DATA_DIR/secrets" "$WS_DIR" "$DATA_DIR/state" "$DATA_DIR/tailscale"
chmod 700 "$DATA_DIR" || true

# Zero-config: generate strong secrets on first boot, persist in the data volume.
export CONTROLLER_ALLOW_LAN_BIND="${CONTROLLER_ALLOW_LAN_BIND:-1}"
export CONTROLLER_LISTEN_HOST="${CONTROLLER_LISTEN_HOST:-0.0.0.0}"
export CONTROLLER_LISTEN_PORT="${CONTROLLER_LISTEN_PORT:-8790}"

# Compose/operator env wins over stale loopback values persisted in bootstrap.env.
# Browser OAuth must never be sent to 127.0.0.1 (that is the client's loopback).
_PRESERVE_HAYABUSA_PUBLIC_URL="${HAYABUSA_PUBLIC_URL:-}"
_BOOTSTRAP_FIRST_CREATE=0

_print_creds_banner() {
  local lan_ip show_pw pw
  lan_ip="$(python - <<'PY' 2>/dev/null || echo 127.0.0.1
import os
os.chdir("/opt/hayabusa-controller")
from app.lan import detect_lan_ipv4
print(detect_lan_ipv4() or "127.0.0.1")
PY
)"
  # Always print username + password in the console (also persisted in bootstrap.env).
  show_pw=1
  pw="${CONTROLLER_MANUAL_PASSWORD:-}"
  cat <<EOF

============================================================
 Hayabusa Controller
 Open:     http://${lan_ip}:${CONTROLLER_LISTEN_PORT}
 Username: admin
 Password: ${pw:-"(missing — check ${BOOTSTRAP})"}
 Saved:    ${BOOTSTRAP}
 After first sign-in the password is invalid. Whitelist GitHub (preferred), Google, or Discord with 2FA as Owner, then finish /setup.
============================================================

EOF
}

if [[ -f "$BOOTSTRAP" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$BOOTSTRAP"
  set +a
  # Never keep an empty pre-login password — mint a fresh random one.
  if [[ -z "${CONTROLLER_MANUAL_PASSWORD:-}" ]]; then
    _rand_pass() { openssl rand -base64 18 | tr -d '/+=' | head -c 20; }
    CONTROLLER_MANUAL_PASSWORD="$(_rand_pass)"
    export CONTROLLER_MANUAL_PASSWORD
    if grep -q '^CONTROLLER_MANUAL_PASSWORD=' "$BOOTSTRAP" 2>/dev/null; then
      # rewrite in place
      tmp="${BOOTSTRAP}.tmp.$$"
      grep -v '^CONTROLLER_MANUAL_PASSWORD=' "$BOOTSTRAP" >"$tmp" || true
      echo "CONTROLLER_MANUAL_PASSWORD=${CONTROLLER_MANUAL_PASSWORD}" >>"$tmp"
      mv "$tmp" "$BOOTSTRAP"
    else
      echo "CONTROLLER_MANUAL_PASSWORD=${CONTROLLER_MANUAL_PASSWORD}" >>"$BOOTSTRAP"
    fi
    chmod 600 "$BOOTSTRAP" || true
    _BOOTSTRAP_FIRST_CREATE=1
    echo "[hayabusa-controller] Minted missing CONTROLLER_MANUAL_PASSWORD in ${BOOTSTRAP}"
    mkdir -p "${DATA_DIR}/state"
    cat >"${DATA_DIR}/state/auth_settings.json" <<EOF
{
  "version": 1,
  "local_password_login_enabled": true,
  "must_change_password": false,
  "needs_sso_admin": true,
  "require_2fa": true,
  "updated_at": null,
  "updated_by": "bootstrap"
}
EOF
    chmod 600 "${DATA_DIR}/state/auth_settings.json" || true
  fi
  if [[ -n "${_PRESERVE_HAYABUSA_PUBLIC_URL}" ]]; then
    case "${HAYABUSA_PUBLIC_URL:-}" in
      http://127.*|https://127.*|http://localhost*|https://localhost*|http://\[::1\]*|https://\[::1\]*|"")
        export HAYABUSA_PUBLIC_URL="${_PRESERVE_HAYABUSA_PUBLIC_URL}"
        ;;
    esac
  fi
elif [[ -z "${CONTROLLER_SECRET_KEY:-}" ]]; then
  _BOOTSTRAP_FIRST_CREATE=1
  _rand_hex() { openssl rand -hex 32; }
  _rand_pass() { openssl rand -base64 18 | tr -d '/+=' | head -c 20; }
  CONTROLLER_SECRET_KEY="$(_rand_hex)"
  CONTROLLER_MANUAL_PASSWORD="$(_rand_pass)"
  HAYABUSA_CONTROLLER_BRIDGE_TOKEN="$(_rand_hex)"
  HAYABUSA_WS_URL="${HAYABUSA_WS_URL:-ws://127.0.0.1:8791}"
  HAYABUSA_WS_MESH_URL="${HAYABUSA_WS_MESH_URL:-$HAYABUSA_WS_URL}"
  cat >"$BOOTSTRAP" <<EOF
CONTROLLER_SECRET_KEY=${CONTROLLER_SECRET_KEY}
CONTROLLER_MANUAL_PASSWORD=${CONTROLLER_MANUAL_PASSWORD}
HAYABUSA_CONTROLLER_BRIDGE_TOKEN=${HAYABUSA_CONTROLLER_BRIDGE_TOKEN}
HAYABUSA_WS_URL=${HAYABUSA_WS_URL}
HAYABUSA_WS_MESH_URL=${HAYABUSA_WS_MESH_URL}
EOF
  chmod 600 "$BOOTSTRAP"
  export CONTROLLER_SECRET_KEY CONTROLLER_MANUAL_PASSWORD HAYABUSA_CONTROLLER_BRIDGE_TOKEN
  export HAYABUSA_WS_URL HAYABUSA_WS_MESH_URL
  # Force a new password after the first bootstrap login.
  mkdir -p "${DATA_DIR}/state"
  cat >"${DATA_DIR}/state/auth_settings.json" <<EOF
{
  "version": 1,
  "local_password_login_enabled": true,
  "must_change_password": false,
  "needs_sso_admin": true,
  "require_2fa": true,
  "updated_at": null,
  "updated_by": "bootstrap"
}
EOF
  chmod 600 "${DATA_DIR}/state/auth_settings.json" || true
fi

# Always remind where break-glass admin creds live (password printed in console).
if [[ -n "${CONTROLLER_MANUAL_PASSWORD:-}" ]]; then
  _print_creds_banner
fi

if [[ -d "$DEFAULTS" ]]; then
  # When GitOps is enabled, packaged defaults must not overwrite the workspace.
  GITOPS_ENABLED=0
  if [[ -f "$DATA_DIR/state/gitops.json" ]] && grep -q '"enabled"[[:space:]]*:[[:space:]]*true' "$DATA_DIR/state/gitops.json" 2>/dev/null; then
    GITOPS_ENABLED=1
  fi
  if [[ "$GITOPS_ENABLED" == "1" ]]; then
    echo "[hayabusa-controller] GitOps enabled — skipping defaults rsync into Ansible/OpenTofu workspace"
  else
  echo "[hayabusa-controller] syncing Ansible/OpenTofu workspace from Hayabusa defaults (master)..."
  # Exact Hayabusa layout: Ansible/ + OpenTofu/ + README.txt (not a flat dump into workspace root).
  mkdir -p "$WS_DIR/Ansible" "$WS_DIR/OpenTofu"
  if [[ -d "$DEFAULTS/Ansible" ]]; then
    rsync -a --delete "$DEFAULTS/Ansible/" "$WS_DIR/Ansible/" || true
  fi
  if [[ -d "$DEFAULTS/OpenTofu" ]]; then
    rsync -a --delete "$DEFAULTS/OpenTofu/" "$WS_DIR/OpenTofu/" || true
  fi
  if [[ -f "$DEFAULTS/README.txt" ]]; then
    cp -a "$DEFAULTS/README.txt" "$WS_DIR/README.txt" || true
  fi
  # Drop legacy flattened top-level clones once Ansible/ holds the master copy.
  for name in \
    ansible \
    bare-metal-ztp \
    "IoT Devices" \
    openPLC \
    residential-routers-and-switches \
    residential-routers-and-switches-apis \
    "SCADA & PLC" \
    ztp
  do
    if [[ -d "$WS_DIR/$name" && -e "$WS_DIR/Ansible/$name" ]]; then
      rm -rf "$WS_DIR/$name" || true
    elif [[ -d "$WS_DIR/$name" && "$name" == "ansible" && -d "$WS_DIR/Ansible" ]]; then
      rm -rf "$WS_DIR/$name" || true
    fi
  done
  # lowercase ansible stub (older IacStore) even if Ansible has no child named ansible
  if [[ -d "$WS_DIR/ansible" && -d "$WS_DIR/Ansible" ]]; then
    rm -rf "$WS_DIR/ansible" || true
  fi
  date +%s >"$WS_DIR/.hayabusa_defaults_seeded" 2>/dev/null || true
  fi
fi

# Start tailscaled (prefer kernel TUN when /dev/net/tun exists so mesh TCP works natively).
# Always expose a local SOCKS5 so the control-plane WS can dial 100.64/10 even in
# userspace mode (normal sockets have no CGNAT route without a TUN).
#
# Host-network note: only one kernel Tailscale interface (tailscale0) can exist per
# host. If Hayabusa hub already owns it (same machine lab), fall back to userspace.
# Also: never share the hub's default sock path — that blocks peregrine-main after reboot.
if command -v tailscaled >/dev/null 2>&1; then
  echo "[hayabusa-controller] starting tailscaled..."
  mkdir -p /var/run/tailscale "${TAILSCALE_STATE_DIR:-$DATA_DIR/tailscale}"
  # Dedicated socket so collocated hub (Peregrine) can own /var/run/tailscale/tailscaled.sock
  export TS_SOCKET="${TS_SOCKET:-/var/run/tailscale/controller.sock}"
  export TS_SOCKS5="${TS_SOCKS5:-127.0.0.1:1055}"
  TS_ARGS=(
    --state="${TAILSCALE_STATE_DIR:-$DATA_DIR/tailscale}/tailscaled.state"
    --socket="$TS_SOCKET"
    --socks5-server="$TS_SOCKS5"
  )
  USE_USERSPACE=0
  if [[ "${CONTROLLER_TAILSCALE_USERSPACE:-}" == "1" || "${CONTROLLER_TAILSCALE_USERSPACE:-}" == "true" ]]; then
    USE_USERSPACE=1
  elif [[ ! -e /dev/net/tun ]]; then
    USE_USERSPACE=1
  elif ip link show tailscale0 >/dev/null 2>&1; then
    # Another Tailscale (often Hayabusa hub on host network) already holds the TUN.
    USE_USERSPACE=1
    echo "[hayabusa-controller] tailscale0 already present — using userspace to avoid clobbering hub mesh"
  fi
  if [[ "$USE_USERSPACE" == "1" ]]; then
    TS_ARGS+=(--tun=userspace-networking)
    echo "[hayabusa-controller] tailscaled mode=userspace socket=$TS_SOCKET"
  else
    echo "[hayabusa-controller] tailscaled mode=kernel-tun socket=$TS_SOCKET"
  fi
  # SOCKS is always useful: mesh control WS dials 100.64/10 through it when needed.
  echo "[hayabusa-controller] mesh SOCKS5 on $TS_SOCKS5"
  tailscaled "${TS_ARGS[@]}" >/var/log/tailscaled.log 2>&1 &
  # Brief settle so `tailscale up` during enroll does not race the daemon
  sleep 1
else
  echo "[hayabusa-controller] tailscaled unavailable — mesh joins will FAIL until Tailscale is installed (no simulated join)"
fi

HOST="${CONTROLLER_LISTEN_HOST:-0.0.0.0}"
PORT="${CONTROLLER_LISTEN_PORT:-8790}"

# Resolve TLS (optional explicit certs, or CONTROLLER_TLS_AUTO_SELF_SIGNED=1).
TLS_ARGS=()
TLS_META="$(python - <<'PY'
import json, os
from pathlib import Path
os.environ.setdefault("CONTROLLER_DATA_DIR", "/var/lib/hayabusa-controller")
from app.lan import tls_paths, resolve_public_base_url, detect_lan_ipv4
data = Path(os.environ["CONTROLLER_DATA_DIR"])
tls = tls_paths(data)
port = int(os.environ.get("CONTROLLER_LISTEN_PORT") or "8790")
url, auto = resolve_public_base_url(listen_port=port, tls_enabled=bool(tls["enabled"]))
print(json.dumps({
  "enabled": bool(tls["enabled"]),
  "cert": str(tls["cert"]) if tls["cert"] else "",
  "key": str(tls["key"]) if tls["key"] else "",
  "auto": bool(tls["auto"]),
  "public_base_url": url,
  "public_base_auto": auto,
  "lan_ip": detect_lan_ipv4() or "",
}))
PY
)"
if [[ -n "$TLS_META" ]]; then
  echo "[hayabusa-controller] lan/tls: $TLS_META"
  CERT="$(python -c 'import json,sys; print(json.loads(sys.argv[1]).get("cert") or "")' "$TLS_META")"
  KEY="$(python -c 'import json,sys; print(json.loads(sys.argv[1]).get("key") or "")' "$TLS_META")"
  if [[ -n "$CERT" && -n "$KEY" && -f "$CERT" && -f "$KEY" ]]; then
    TLS_ARGS=(--ssl-certfile "$CERT" --ssl-keyfile "$KEY")
    echo "[hayabusa-controller] HTTPS enabled (cert=$CERT)"
  fi
fi

# When HTTPS is on, also serve a plain-HTTP redirect so http://LAN-IP still works.
# Default redirect port: 8789 (avoids needing bind on :80). Set CONTROLLER_HTTP_REDIRECT_PORT=80
# if you want classic appliance behavior. Set 0 to disable.
if [[ ${#TLS_ARGS[@]} -gt 0 ]]; then
  REDIR_PORT="${CONTROLLER_HTTP_REDIRECT_PORT-8789}"
  if [[ -n "$REDIR_PORT" && "$REDIR_PORT" != "0" ]]; then
    export CONTROLLER_HTTP_REDIRECT_PORT="$REDIR_PORT"
    echo "[hayabusa-controller] starting HTTP→HTTPS redirect on :$REDIR_PORT"
    python /opt/hayabusa-controller/scripts/http_https_redirect.py >/var/log/hayabusa-http-redirect.log 2>&1 &
  fi
fi

# Do not exec — keep this shell as PID 1 so backgrounded tailscaled is not reaped.
python -m uvicorn app.main:app --host "$HOST" --port "$PORT" "${TLS_ARGS[@]}"
