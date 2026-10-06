"""LAN / TLS helpers for Hayabusa Controller public URL and HTTPS."""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("hayabusa-controller.lan")


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _env_truthy(name: str) -> bool:
    return _env(name).lower() in {"1", "true", "yes", "on"}


def is_safe_lan_hostname(host: str) -> bool:
    h = (host or "").strip().lower().strip("[]")
    if not h:
        return False
    if h in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        ip = ipaddress.ip_address(h)
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local)
    except ValueError:
        return h.endswith((".local", ".lan", ".internal", ".home.arpa"))


_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
_OVERLAY_IFACE_PREFIXES = (
    "docker",
    "br-",
    "veth",
    "cni",
    "flannel",
    "virbr",
    "tun",
    "tailscale",
    "wg",
    "wog",  # host WireGuard overlays (not real site / WAN identity)
    "ipsec",
    "vti",
    "kube-",
    "nodelocal",
    "zt",
)
_PREFER_IFACE_PREFIXES = ("en", "eth", "wl", "bond", "lan", "em", "p")


def _is_cgnat_ipv4(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    return addr.version == 4 and addr in _CGNAT_NET


def _ok_site_ipv4(ip: str, *, private_only: bool = False) -> bool:
    """Real site address: RFC1918 LAN and/or global public. Never mesh CGNAT."""
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    if addr.version != 4 or addr.is_loopback or addr.is_link_local or addr in _CGNAT_NET:
        return False
    if private_only:
        return bool(addr.is_private)
    return bool(addr.is_private or getattr(addr, "is_global", False))


def detect_lan_ipv4() -> str | None:
    """
    Best-effort primary site IPv4 for this appliance (public base URL / TLS SAN).

    Prefers private LAN on physical NICs. On cloud/VPS hosts where the only address
    on en*/eth* is a global public IP, that real WAN address is used.

    Never returns mesh CGNAT (100.64/10) or overlay VPN interfaces (tailscale/wg/wog/…).
    CONTROLLER_LAN_IP wins when set (pin the site address if auto-detect is wrong).
    """
    pinned = _env("CONTROLLER_LAN_IP")
    if pinned:
        try:
            addr = ipaddress.ip_address(pinned)
            if _ok_site_ipv4(str(addr)):
                return str(addr)
            logger.warning("CONTROLLER_LAN_IP=%s is not a usable site address; ignoring", pinned)
        except ValueError:
            logger.warning("CONTROLLER_LAN_IP=%s is not a valid IP; ignoring", pinned)

    def _iface_ok(name: str, *, prefer_only: bool) -> bool:
        n = (name or "").lower()
        if any(n.startswith(p) for p in _OVERLAY_IFACE_PREFIXES):
            return False
        if prefer_only:
            return any(n.startswith(p) for p in _PREFER_IFACE_PREFIXES)
        return True

    def _from_iface(iface: str, *, private_only: bool) -> str | None:
        try:
            import subprocess

            out = subprocess.check_output(
                ["ip", "-4", "-o", "addr", "show", "dev", iface],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
            for part in out.split():
                if "/" in part and part[0].isdigit():
                    cand = part.split("/", 1)[0]
                    if _ok_site_ipv4(cand, private_only=private_only):
                        return cand
        except Exception:  # noqa: BLE001
            pass
        return None

    iface = _env("CONTROLLER_LAN_IFACE")
    if iface:
        hit = _from_iface(iface, private_only=False)
        if hit:
            return hit

    def _scan(*, private_only: bool, prefer_only: bool) -> str | None:
        try:
            import subprocess

            out = subprocess.check_output(
                ["ip", "-4", "-o", "addr", "show", "scope", "global"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
        except Exception:  # noqa: BLE001
            return None
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            ifname = parts[1]
            if not _iface_ok(ifname, prefer_only=prefer_only):
                continue
            ip = None
            for i, p in enumerate(parts):
                if p == "inet" and i + 1 < len(parts):
                    ip = parts[i + 1].split("/", 1)[0]
                    break
            if ip and _ok_site_ipv4(ip, private_only=private_only):
                return ip
        return None

    # 1) Private LAN on preferred NICs  2) Private on any non-overlay
    # 3) Global public on preferred NICs (VPS)  4) Global on any non-overlay
    for private_only, prefer_only in (
        (True, True),
        (True, False),
        (False, True),
        (False, False),
    ):
        hit = _scan(private_only=private_only, prefer_only=prefer_only)
        if hit:
            return hit

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("1.1.1.1", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        if _ok_site_ipv4(ip):
            return ip
    except Exception:  # noqa: BLE001
        pass
    return None


def resolve_public_base_url(
    *,
    listen_port: int,
    tls_enabled: bool,
    configured: str | None = None,
) -> tuple[str, bool]:
    """
    Returns (url, auto_detected).
    CONTROLLER_PUBLIC_BASE_URL=auto|lan|detect → http(s)://<site-ip>:port
    Uses the real site address (LAN or WAN), never mesh/VPN overlay IPs.
    Empty + LAN bind → same auto behavior. Explicit URL wins.
    """
    raw = (configured if configured is not None else _env("CONTROLLER_PUBLIC_BASE_URL")).strip()
    auto_tokens = {"auto", "lan", "detect"}
    lan_bind = _env_truthy("CONTROLLER_ALLOW_LAN_BIND") or _env("CONTROLLER_LISTEN_HOST") in {
        "0.0.0.0",
        "::",
        "[::]",
    }
    want_auto = raw.lower() in auto_tokens or (not raw and lan_bind)
    if want_auto:
        ip = detect_lan_ipv4() or "127.0.0.1"
        if _is_cgnat_ipv4(ip):
            logger.warning("refusing CGNAT site IP %s for public base; using 127.0.0.1", ip)
            ip = "127.0.0.1"
        scheme = "https" if tls_enabled else "http"
        url = f"{scheme}://{ip}:{int(listen_port)}"
        logger.info("CONTROLLER_PUBLIC_BASE_URL auto-detected → %s", url)
        return url, True
    if not raw:
        return f"http://127.0.0.1:{int(listen_port)}", False
    return raw.rstrip("/"), False


def public_base_aliases() -> list[str]:
    raw = _env("CONTROLLER_PUBLIC_BASE_ALIASES")
    return [a.strip().rstrip("/") for a in raw.split(",") if a.strip()]


def browser_public_base(request_host: str, request_scheme: str, configured_base: str) -> str:
    """
    Origin for OAuth return_to / redirects: use the Host the browser actually used
    when it is LAN-safe or matches configured/alias hosts.
    """
    host_header = (request_host or "").strip()
    if not host_header:
        return configured_base.rstrip("/")
    hostname = host_header.split("%")[0]
    if hostname.startswith("["):
        end = hostname.find("]")
        host_only = hostname[1:end] if end > 0 else hostname.strip("[]")
    else:
        host_only = hostname.rsplit(":", 1)[0] if hostname.count(":") == 1 else hostname

    configured_host = urlparse(configured_base).hostname or ""
    aliases = public_base_aliases()
    alias_by_host: dict[str, str] = {}
    for a in aliases:
        h = (urlparse(a).hostname or "").lower()
        if h:
            alias_by_host[h] = a.rstrip("/")
    host_l = host_only.lower().strip("[]")

    if host_l in alias_by_host:
        return alias_by_host[host_l]

    allowed = is_safe_lan_hostname(host_l) or (
        configured_host and host_l == configured_host.lower()
    )
    if not allowed:
        return configured_base.rstrip("/")

    scheme = (request_scheme or "http").lower()
    if scheme not in {"http", "https"}:
        scheme = "https" if configured_base.lower().startswith("https://") else "http"
    if configured_host and host_l == configured_host.lower() and configured_base.lower().startswith("https://"):
        scheme = "https"
    return f"{scheme}://{host_header}".rstrip("/")


def _cert_covers_lan_ip(cert_path: Path, lan_ip: str | None) -> bool:
    """True if existing cert is usable for this LAN IP (or no LAN IP required)."""
    if not lan_ip:
        return True
    try:
        from cryptography import x509

        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        want = ipaddress.ip_address(lan_ip)
        for name in san:
            try:
                if getattr(name, "value", None) == want:
                    return True
            except Exception:  # noqa: BLE001
                continue
        # Also accept CN match
        from cryptography.x509.oid import NameOID

        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn and cn[0].value == lan_ip:
            return True
    except Exception:  # noqa: BLE001
        return False
    return False


def ensure_self_signed_tls(data_dir: Path, *, lan_ip: str | None, listen_port: int) -> tuple[Path, Path]:
    """Create (or reuse) a self-signed cert for LAN HTTPS. Returns (cert, key)."""
    tls_dir = data_dir / "tls"
    tls_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(tls_dir, 0o700)
    except OSError:
        pass
    cert_path = tls_dir / "cert.pem"
    key_path = tls_dir / "key.pem"
    if cert_path.is_file() and key_path.is_file() and _cert_covers_lan_ip(cert_path, lan_ip):
        return cert_path, key_path
    if cert_path.is_file() or key_path.is_file():
        # Stale cert from a previous IP / first boot before LAN was known — rotate.
        for p in (cert_path, key_path):
            try:
                if p.is_file():
                    p.rename(p.with_suffix(p.suffix + ".bak"))
            except OSError:
                try:
                    p.unlink(missing_ok=True)  # type: ignore[call-arg]
                except TypeError:
                    if p.is_file():
                        p.unlink()
                except OSError:
                    pass
        logger.info("rotating self-signed TLS cert so SAN includes LAN IP %s", lan_ip or "(none)")

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    hostnames = ["localhost", "hayabusa-controller.local"]
    if lan_ip:
        hostnames.append(lan_ip)
    cn = lan_ip or "localhost"
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    alt_names: list[x509.GeneralName] = [
        x509.DNSName("localhost"),
        x509.DNSName("hayabusa-controller.local"),
    ]
    for h in hostnames:
        try:
            alt_names.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError:
            if h not in {"localhost", "hayabusa-controller.local"}:
                alt_names.append(x509.DNSName(h))
    seen: set[str] = set()
    unique_alt: list[x509.GeneralName] = []
    for n in alt_names:
        k = str(n)
        if k in seen:
            continue
        seen.add(k)
        unique_alt.append(n)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(unique_alt), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    try:
        os.chmod(key_path, 0o600)
        os.chmod(cert_path, 0o644)
    except OSError:
        pass
    logger.info("generated self-signed TLS cert for LAN HTTPS at %s", cert_path)
    return cert_path, key_path


def tls_paths(data_dir: Path) -> dict[str, Any]:
    """Resolve TLS cert/key; optionally auto-generate self-signed for secure LAN."""
    cert = _env("CONTROLLER_TLS_CERT")
    key = _env("CONTROLLER_TLS_KEY")
    if cert and key:
        return {"enabled": True, "cert": Path(cert), "key": Path(key), "auto": False}
    if _env_truthy("CONTROLLER_TLS_AUTO_SELF_SIGNED"):
        port = int(_env("CONTROLLER_LISTEN_PORT", "8790") or "8790")
        lan = detect_lan_ipv4()
        c, k = ensure_self_signed_tls(data_dir, lan_ip=lan, listen_port=port)
        return {"enabled": True, "cert": c, "key": k, "auto": True}
    return {"enabled": False, "cert": None, "key": None, "auto": False}
