#!/usr/bin/env python3
"""Generate API scaffolds for residential router/switch inventory."""

from __future__ import annotations

import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_IF_EXISTS = {"app/main.py"}

# (brand_dir, api_folder_name, title, client_type, default_host, extra_env_lines, api_supported)
ROUTERS: list[tuple] = [
    # Comcast
    ("comcast", "xfinity-xb10-router-api", "Xfinity Advanced Gateway XB10", "generic_gateway", "https://10.0.0.1", [], True),
    ("comcast", "xfinity-xb8-router-api", "Xfinity Advanced Gateway XB8", "generic_gateway", "https://10.0.0.1", [], True),
    ("comcast", "xfinity-xb7-router-api", "Xfinity Wireless Gateway XB7", "generic_gateway", "https://10.0.0.1", [], True),
    ("comcast", "xfinity-xb6-router-api", "Xfinity Gateway XB6", "generic_gateway", "https://10.0.0.1", [], True),
    # Verizon (g3100 + cr1000a exist)
    ("verizon", "fios-wnc-cr200a-router-api", "Verizon Internet Gateway WNC-CR200A", "verizon_luci", "https://192.168.1.1", [], True),
    ("verizon", "fios-arc-xci55ax-router-api", "Verizon Internet Gateway ARC-XCI55AX", "verizon_luci", "https://192.168.1.1", [], True),
    ("verizon", "fios-ask-ncm1100-router-api", "Verizon Internet Gateway ASK-NCM1100", "verizon_luci", "https://192.168.1.1", [], True),
    ("verizon", "fios-ask-ncq1338-router-api", "Verizon Internet Gateway ASK-NCQ1338", "verizon_luci", "https://192.168.1.1", [], True),
    # T-Mobile
    ("t-mobile", "tmobile-g5ar-router-api", "T-Mobile 5G Gateway G5AR/G5SE", "generic_gateway", "http://192.168.12.1", [], True),
    ("t-mobile", "tmobile-sagemcom-5688w-router-api", "Sagemcom Fast 5688W", "generic_gateway", "http://192.168.12.1", [], True),
    ("t-mobile", "tmobile-arcadyan-kvd21-router-api", "Arcadyan KVD21", "generic_gateway", "http://192.168.12.1", [], True),
    ("t-mobile", "tmobile-nokia-fastmile-router-api", "Nokia FastMile 5G Gateway", "generic_gateway", "http://192.168.1.1", [], True),
    # AT&T
    ("att", "att-allfi-pro-router-api", "AT&T All-Fi Pro Gateway Wi-Fi 7", "generic_gateway", "http://192.168.1.254", [], True),
    ("att", "att-bgw320-router-api", "AT&T BGW320", "generic_gateway", "http://192.168.1.254", [], True),
    ("att", "att-cgw450-router-api", "AT&T All-Fi Hub CGW450", "generic_gateway", "http://192.168.1.254", [], True),
    ("att", "att-bgw210-router-api", "AT&T BGW210", "generic_gateway", "http://192.168.1.254", [], True),
    ("att", "att-pace-5268ac-router-api", "Pace 5268AC", "generic_gateway", "http://192.168.1.254", [], True),
    # TP-Link routers
    ("tp-link", "tplink-archer-be-router-api", "TP-Link Archer BE900/BE9700/BE6500/BE550/BE230", "tplink_luci", "http://192.168.0.1", [], True),
    ("tp-link", "tplink-archer-axe-router-api", "TP-Link Archer AXE95/AXE75 Wi-Fi 6E", "tplink_luci", "http://192.168.0.1", [], True),
    ("tp-link", "tplink-archer-ax-router-api", "TP-Link Archer AX55/AX20 Wi-Fi 6", "tplink_luci", "http://192.168.0.1", [], True),
    ("tp-link", "tplink-deco-be-router-api", "TP-Link Deco BE85/BE63/BE65 Pro", "tplink_luci", "http://192.168.0.1", [], True),
    ("tp-link", "tplink-deco-xe-router-api", "TP-Link Deco XE75 Wi-Fi 6E", "tplink_luci", "http://192.168.0.1", [], True),
    ("tp-link", "tplink-deco-x-router-api", "TP-Link Deco X20/X55", "tplink_luci", "http://192.168.0.1", [], True),
    # Netgear
    ("netgear", "netgear-nighthawk-rs-router-api", "Netgear Nighthawk RS700S/RS300", "netgear_soap", "192.168.1.1", [], True),
    ("netgear", "netgear-nighthawk-raxe-router-api", "Netgear Nighthawk RAXE500/RAXE300", "netgear_soap", "192.168.1.1", [], True),
    ("netgear", "netgear-nighthawk-rax-router-api", "Netgear Nighthawk RAX70/RAX40", "netgear_soap", "192.168.1.1", [], True),
    ("netgear", "netgear-orbi-970-router-api", "Netgear Orbi 970 Series RBE971", "netgear_soap", "192.168.1.1", ["ROUTER_PORT=80"], True),
    ("netgear", "netgear-orbi-860-router-api", "Netgear Orbi 860 Series RBK863", "netgear_soap", "192.168.1.1", ["ROUTER_PORT=80"], True),
    ("netgear", "netgear-orbi-770-router-api", "Netgear Orbi 770 Series", "netgear_soap", "192.168.1.1", ["ROUTER_PORT=80"], True),
    # ASUS
    ("asus", "asus-rog-gt-be98-router-api", "ASUS ROG Rapture GT-BE98 Pro/GT6", "asus_http", "http://192.168.50.1", [], True),
    ("asus", "asus-rt-be-router-api", "ASUS RT-BE96U/RT-BE92U", "asus_http", "http://192.168.50.1", [], True),
    ("asus", "asus-rt-ax-router-api", "ASUS RT-AX88U Pro/RT-AX68U", "asus_http", "http://192.168.50.1", [], True),
    ("asus", "asus-zenwifi-bq-router-api", "ASUS ZenWiFi BQ16 Pro/BT10", "asus_http", "http://192.168.50.1", [], True),
    ("asus", "asus-zenwifi-xt-router-api", "ASUS ZenWiFi XT8/XD6", "asus_http", "http://192.168.50.1", [], True),
    # eero
    ("amazon-eero", "eero-max-7-router-api", "Amazon eero Max 7", "eero_local", "http://192.168.4.1", [], True),
    ("amazon-eero", "eero-pro-7-router-api", "Amazon eero Pro 7", "eero_local", "http://192.168.4.1", [], True),
    ("amazon-eero", "eero-pro-6e-router-api", "Amazon eero Pro 6E", "eero_local", "http://192.168.4.1", [], True),
    ("amazon-eero", "eero-6-router-api", "Amazon eero 6+/6", "eero_local", "http://192.168.4.1", [], True),
    # Google Nest
    ("google-nest", "nest-wifi-pro-router-api", "Google Nest Wifi Pro", "nest_local", "http://192.168.86.1", [], True),
    ("google-nest", "nest-wifi-router-api", "Google Nest Wifi", "nest_local", "http://192.168.86.1", [], True),
    ("google-nest", "google-wifi-router-api", "Google Wifi Legacy", "nest_local", "http://192.168.86.1", [], True),
    # Linksys
    ("linksys", "linksys-velop-pro-7-router-api", "Linksys Velop Pro 7", "linksys_http", "http://192.168.1.1", [], True),
    ("linksys", "linksys-velop-pro-6e-router-api", "Linksys Velop Pro 6E", "linksys_http", "http://192.168.1.1", [], True),
    ("linksys", "linksys-hydra-pro-6e-router-api", "Linksys Hydra Pro 6E", "linksys_http", "http://192.168.1.1", [], True),
    ("linksys", "linksys-mr9600-router-api", "Linksys MR9600", "linksys_http", "http://192.168.1.1", [], True),
    # Ubiquiti (dream router exists)
    ("ubiquiti", "unifi-express-router-api", "UniFi Express", "unifi_integration", "https://192.168.1.1", [], True),
    ("ubiquiti", "unifi-cloud-gateway-max-router-api", "UniFi Cloud Gateway Max", "unifi_integration", "https://192.168.1.1", [], True),
]

SWITCHES: list[tuple] = [
    # Netgear unmanaged
    ("netgear", "netgear-gs305-switch-api", "Netgear GS305", "unmanaged", "192.168.1.1", [], False),
    ("netgear", "netgear-gs308-switch-api", "Netgear GS308", "unmanaged", "192.168.1.1", [], False),
    ("netgear", "netgear-gs105-switch-api", "Netgear GS105", "unmanaged", "192.168.1.1", [], False),
    ("netgear", "netgear-gs108-switch-api", "Netgear GS108", "unmanaged", "192.168.1.1", [], False),
    ("netgear", "netgear-gs308e-switch-api", "Netgear GS308E", "generic_switch", "192.168.0.1", [], True),
    ("netgear", "netgear-ms108-switch-api", "Netgear MS105/MS108 Multi-Gig", "generic_switch", "192.168.0.1", [], True),
    # TP-Link
    ("tp-link", "tl-sg108e-switch-api", "TP-Link TL-SG108E", "tplink_easy_smart", "192.168.1.213", ["SWITCH_MODEL=TL-SG108E"], True),
    ("tp-link", "tl-sg105-switch-api", "TP-Link TL-SG105 Unmanaged", "unmanaged", "192.168.1.1", [], False),
    ("tp-link", "tl-sg108-switch-api", "TP-Link TL-SG108 Unmanaged", "unmanaged", "192.168.1.1", [], False),
    ("tp-link", "tl-sg1005d-switch-api", "TP-Link TL-SG1005D", "unmanaged", "192.168.1.1", [], False),
    ("tp-link", "tl-sg105-m2-switch-api", "TP-Link TL-SG105-M2 Multi-Gig", "unmanaged", "192.168.1.1", [], False),
    # Linksys
    ("linksys", "lgs105-switch-api", "Linksys LGS105", "generic_switch", "192.168.1.1", [], True),
    ("linksys", "lgs108-switch-api", "Linksys LGS108", "generic_switch", "192.168.1.1", [], True),
    # D-Link unmanaged
    ("d-link", "dgs-105-switch-api", "D-Link DGS-105", "unmanaged", "192.168.0.1", [], False),
    ("d-link", "dgs-108-switch-api", "D-Link DGS-108", "unmanaged", "192.168.0.1", [], False),
    ("d-link", "dgs-1008g-switch-api", "D-Link DGS-1008G", "unmanaged", "192.168.0.1", [], False),
    # Ubiquiti
    ("ubiquiti", "unifi-flex-mini-switch-api", "UniFi Flex Mini", "unifi_integration", "https://192.168.1.1", [], True),
    ("ubiquiti", "unifi-switch-lite-8-poe-api", "UniFi Switch Lite 8 PoE", "unifi_integration", "https://192.168.1.1", [], True),
    ("ubiquiti", "unifi-switch-ultra-60w-api", "UniFi Switch Ultra 60W", "unifi_integration", "https://192.168.1.1", [], True),
]

EXISTING_PORTS = {
    "fios-g3100-router-api": 8787,
    "fios-cr1000a-router-api": 8788,
    "unifi-dream-router-api": 8789,
    "tl-sg105e-switch-api": 8790,
}

PORT_COUNTER = 8801


def env_block(client_type: str, host: str, title: str, extra: list[str], supported: bool, api_key: str, port: int, example: bool) -> str:
    lines = [f"# {title}", f"API_SUPPORTED={'true' if supported else 'false'}", ""]
    if client_type == "verizon_luci":
        lines += [
            f"ROUTER_HOST={host}",
            "ROUTER_USERNAME=admin",
            f"ROUTER_PASSWORD={'your-admin-password' if example else ''}",
            "ROUTER_TLS_HOSTNAME=mynetworksettings.com",
            "ROUTER_VERIFY_TLS=false",
            "",
        ]
    elif client_type == "tplink_easy_smart":
        model = next((e.split("=")[1] for e in extra if e.startswith("SWITCH_MODEL=")), "TL-SG105E")
        lines += [
            f"SWITCH_HOST={host}",
            "SWITCH_USERNAME=admin",
            f"SWITCH_PASSWORD={'your-switch-password' if example else ''}",
            f"SWITCH_MODEL={model}",
            "",
        ]
    elif client_type == "tplink_luci":
        lines += [
            f"ROUTER_HOST={host}",
            "ROUTER_USERNAME=admin",
            f"ROUTER_PASSWORD={'your-router-password' if example else ''}",
            "ROUTER_ENCRYPTED_PASSWORD=",
            "",
        ]
    elif client_type == "netgear_soap":
        lines += [
            f"ROUTER_HOST={host}",
            "ROUTER_USERNAME=admin",
            f"ROUTER_PASSWORD={'your-router-password' if example else ''}",
            "ROUTER_PORT=5000",
            "ROUTER_SSL=false",
            "",
        ]
        for e in extra:
            if e not in lines:
                lines.insert(-1, e)
    elif client_type == "unifi_integration":
        lines += [
            f"UNIFI_HOST={host}",
            f"UNIFI_API_KEY={'your-integration-api-key' if example else ''}",
            "UNIFI_SITE_ID=default",
            "UNIFI_VERIFY_TLS=false",
            "",
        ]
    elif client_type in ("eero_local", "nest_local"):
        lines += [
            f"ROUTER_HOST={host}",
            f"ROUTER_PASSWORD={'your-router-password' if example else ''}",
            "ROUTER_SESSION_TOKEN=",
            "",
        ]
    elif client_type in ("asus_http", "linksys_http"):
        lines += [
            f"ROUTER_HOST={host}",
            "ROUTER_USERNAME=admin",
            f"ROUTER_PASSWORD={'your-router-password' if example else ''}",
            "",
        ]
    elif client_type in ("generic_gateway", "generic_switch"):
        lines += [
            f"DEVICE_HOST={host}",
            "DEVICE_USERNAME=admin",
            f"DEVICE_PASSWORD={'your-device-password' if example else ''}",
            "",
        ]
    elif client_type == "unmanaged":
        lines += [
            f"DEVICE_HOST={host}",
            "# Unmanaged device — no login credentials available",
            "DEVICE_USERNAME=",
            "DEVICE_PASSWORD=",
            "",
        ]
    lines += [
        "# API server",
        "API_HOST=0.0.0.0",
        f"API_PORT={port}",
        f"API_KEY={'change-me-to-a-long-random-string' if example else api_key}",
    ]
    if client_type not in ("unifi_integration", "unmanaged"):
        lines.append("AUTO_LOGIN=true")
    return "\n".join(lines) + "\n"


CONFIG_PY = '''from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    api_supported: bool = {api_supported}
    device_host: str = "{host}"
    device_username: str = "admin"
    device_password: str = ""
    router_host: str = "{host}"
    router_username: str = "admin"
    router_password: str = ""
    router_encrypted_password: str = ""
    router_tls_hostname: str = "mynetworksettings.com"
    router_verify_tls: bool = False
    router_port: int = 5000
    router_ssl: bool = False
    switch_host: str = "{host}"
    switch_username: str = "admin"
    switch_password: str = ""
    switch_model: str = "TL-SG105E"
    unifi_host: str = "{host}"
    unifi_api_key: str = ""
    unifi_site_id: str = "default"
    unifi_verify_tls: bool = False
    router_session_token: str = ""
    api_key: str = ""
    api_host: str = "0.0.0.0"
    api_port: int = {port}
    auto_login: bool = True


settings = Settings()
'''

CLIENT_PY = '''from __future__ import annotations

from typing import Any

import requests

from .config import settings


class DeviceClient:
    """{title} — scaffold client ({client_type})."""

    def is_reachable(self) -> bool:
        if not settings.api_supported:
            try:
                import socket
                host = settings.device_host.replace("https://", "").replace("http://", "").split("/")[0]
                s = socket.create_connection((host, 80), timeout=3)
                s.close()
                return True
            except OSError:
                return False
        try:
            url = settings.router_host or settings.switch_host or settings.unifi_host or settings.device_host
            if not url.startswith("http"):
                url = f"http://{{url}}"
            r = requests.get(url, timeout=5, verify=settings.unifi_verify_tls)
            return r.status_code < 500
        except requests.RequestException:
            return False

    def ensure_logged_in(self) -> None:
        if not settings.api_supported:
            raise RuntimeError("This device has no programmable local API (unmanaged or unsupported).")
        pwd = (
            settings.router_password
            or settings.switch_password
            or settings.device_password
            or settings.unifi_api_key
        )
        if not pwd:
            raise RuntimeError("Credentials not configured. Set password/API key in .env")

    def status(self) -> dict[str, Any]:
        self.ensure_logged_in()
        return {{
            "device": "{title}",
            "client_type": "{client_type}",
            "tested": False,
            "note": "Implement device-specific client when hardware is available",
        }}
'''

MAIN_PY = '''from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException

from .client import DeviceClient
from .config import settings

_client: DeviceClient | None = None


def get_client() -> DeviceClient:
    if _client is None:
        raise HTTPException(status_code=503, detail="Client not initialized")
    return _client


def require_api_key(x_api_key: Annotated[str | None, Header()] = None) -> None:
    if settings.api_key and x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key header")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _client
    _client = DeviceClient()
    yield


app = FastAPI(
    title="{title} API",
    description="REST API scaffold for {title}",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
def health(client: DeviceClient = Depends(get_client)) -> dict[str, Any]:
    return {{
        "status": "ok" if client.is_reachable() else "degraded",
        "reachable": client.is_reachable(),
        "api_supported": settings.api_supported,
        "tested": False,
        "device": "{title}",
    }}


@app.get("/status", dependencies=[Depends(require_api_key)])
def status(client: DeviceClient = Depends(get_client)) -> dict[str, Any]:
    return client.status()
'''

REQUIREMENTS = "fastapi>=0.115.0\\nuvicorn[standard]>=0.32.0\\nrequests>=2.32.0\\npydantic-settings>=2.6.0\\n"


def next_port(name: str) -> int:
    global PORT_COUNTER
    if name in EXISTING_PORTS:
        return EXISTING_PORTS[name]
    p = PORT_COUNTER
    PORT_COUNTER += 1
    return p


def generate(base: Path, brand: str, name: str, title: str, client_type: str, host: str, extra: list, supported: bool) -> bool:
    api_dir = base / brand / name
    if (api_dir / "app" / "main.py").exists():
        return False
    port = next_port(name)
    api_key = secrets.token_urlsafe(32)
    api_dir.mkdir(parents=True, exist_ok=True)
    (api_dir / "app").mkdir(exist_ok=True)
    (api_dir / "requirements.txt").write_text(REQUIREMENTS.replace("\\n", "\n"))
    (api_dir / ".env").write_text(env_block(client_type, host, title, extra, supported, api_key, port, False))
    (api_dir / ".env.example").write_text(env_block(client_type, host, title, extra, supported, api_key, port, True))
    (api_dir / "app" / "__init__.py").write_text("")
    (api_dir / "app" / "config.py").write_text(
        CONFIG_PY.format(api_supported=str(supported).lower(), host=host, port=port)
    )
    (api_dir / "app" / "client.py").write_text(
        CLIENT_PY.format(title=title, client_type=client_type)
    )
    (api_dir / "app" / "main.py").write_text(MAIN_PY.format(title=title))
    return True


def main() -> None:
    created = []
    skipped = []
    for item in ROUTERS:
        if generate(ROOT / "routers", *item):
            created.append(item[1])
        else:
            skipped.append(item[1])
    for item in SWITCHES:
        if generate(ROOT / "switches", *item):
            created.append(item[1])
        else:
            skipped.append(item[1])

    manifest = ["# Residential Routers & Switches API Manifest", "", "| API | Port | Path |", "|-----|------|------|"]
    for base, kind in [(ROOT / "routers", "routers"), (ROOT / "switches", "switches")]:
        for api in sorted(base.rglob("*-api")):
            if not (api / "app" / "main.py").exists():
                continue
            env = api / ".env"
            port = "?"
            if env.exists():
                for line in env.read_text().splitlines():
                    if line.startswith("API_PORT="):
                        port = line.split("=", 1)[1]
            rel = api.relative_to(ROOT)
            manifest.append(f"| {api.name} | {port} | `{rel}` |")
    (ROOT / "API-MANIFEST.md").write_text("\n".join(manifest) + "\n")
    print(f"Created: {len(created)}, Skipped (existing): {len(skipped)}")
    for c in created:
        print(f"  + {c}")


if __name__ == "__main__":
    main()
