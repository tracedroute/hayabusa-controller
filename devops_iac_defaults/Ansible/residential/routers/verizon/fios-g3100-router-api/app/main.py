from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, Field

from .client import AVAILABLE_CGIS, G3100Client
from .config import settings

_client: G3100Client | None = None


def get_client() -> G3100Client:
    if _client is None:
        raise HTTPException(status_code=503, detail="Router client not initialized")
    return _client


def require_api_key(
    request: Request,
) -> None:
    x_api_key = request.headers.get("X-API-Key") or request.headers.get("x-api-key")
    if settings.api_key and x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key header")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _client
    _client = G3100Client()
    if settings.auto_login and settings.router_password:
        try:
            _client.ensure_logged_in()
        except Exception:
            pass
    yield
    if _client is not None:
        try:
            _client.logout_session()
        except Exception:
            pass


app = FastAPI(
    title="Fios G3100 Router API",
    description="REST API wrapper for the Verizon Fios G3100 router at 192.168.1.1",
    version="1.0.0",
    lifespan=lifespan,
)


class LoginRequest(BaseModel):
    username: str = "admin"
    password: str
    keep_login: bool = True


class DnsEntryRequest(BaseModel):
    hostname: str
    ip: str


class PortForwardRequest(BaseModel):
    name: str
    private_ip: str
    forward_port: int
    dest_port: int
    enable: bool = True


class DbRequest(BaseModel):
    payload: dict[str, Any] = Field(..., description="Router UI payload for /db.cgi (type/to/body).")
    token: str | None = Field(default=None, description="Optional apply token override.")
    confirm: bool = Field(
        default=False,
        description="Must be true to execute (safety guard; prevents accidental config changes).",
    )


class ApplyAbstractRequest(BaseModel):
    form: dict[str, Any] = Field(..., description="Form fields router UI sends to /apply_abstract.cgi.")
    token: str | None = Field(default=None, description="Optional apply token override.")
    confirm: bool = Field(
        default=False,
        description="Must be true to execute (safety guard; prevents accidental config changes).",
    )


@app.get("/health")
def health(client: G3100Client = Depends(get_client)) -> dict[str, Any]:
    try:
        info = client.router_info()
        logged_in = info.get("islogin") == "1"
        return {
            "status": "ok",
            "router_reachable": True,
            "logged_in": logged_in,
            "model": info.get("model"),
            "router_ip": info.get("routerip"),
        }
    except Exception as exc:
        return {"status": "degraded", "router_reachable": False, "error": str(exc)}


@app.get("/router/info", dependencies=[Depends(require_api_key)])
def router_info(client: G3100Client = Depends(get_client)) -> dict[str, Any]:
    return client.router_info()


@app.get("/auth/status", dependencies=[Depends(require_api_key)])
def auth_status(client: G3100Client = Depends(get_client)) -> dict[str, Any]:
    return client.login_status()


@app.post("/auth/login", dependencies=[Depends(require_api_key)])
def auth_login(body: LoginRequest, client: G3100Client = Depends(get_client)) -> dict[str, Any]:
    client.login(body.username, body.password, keep_login=body.keep_login)
    status = client.login_status()
    if status.get("islogin") != "1":
        raise HTTPException(status_code=401, detail="Login failed")
    return {"logged_in": True, "expires": status.get("expires")}


@app.post("/auth/logout", dependencies=[Depends(require_api_key)])
def auth_logout(client: G3100Client = Depends(get_client)) -> dict[str, bool]:
    client.logout_session()
    return {"logged_out": True}


@app.get("/status", dependencies=[Depends(require_api_key)])
def status(client: G3100Client = Depends(get_client)) -> dict[str, Any]:
    client.ensure_logged_in()
    return client.status_summary()


@app.get("/devices", dependencies=[Depends(require_api_key)])
def devices(client: G3100Client = Depends(get_client)) -> list[dict[str, Any]]:
    client.ensure_logged_in()
    return client.fetch_known_devices()


@app.get("/wifi", dependencies=[Depends(require_api_key)])
def wifi(client: G3100Client = Depends(get_client)) -> dict[str, Any]:
    client.ensure_logged_in()
    return client.fetch_wifi_primary()


@app.get("/network", dependencies=[Depends(require_api_key)])
def network(client: G3100Client = Depends(get_client)) -> dict[str, Any]:
    client.ensure_logged_in()
    return client.fetch_network_connections()


@app.get("/dns", dependencies=[Depends(require_api_key)])
def list_dns(client: G3100Client = Depends(get_client)) -> dict[str, Any]:
    client.ensure_logged_in()
    return {
        "ipv4": client.get_dns_entries_v4(),
        "ipv6": client.get_dns_entries_v6(),
    }


@app.post("/dns", dependencies=[Depends(require_api_key)])
def add_dns(body: DnsEntryRequest, client: G3100Client = Depends(get_client)) -> dict[str, Any]:
    client.ensure_logged_in()
    slot = client.add_dns_ipv4(body.hostname, body.ip)
    return {"slot": slot, "hostname": body.hostname, "ip": body.ip}


@app.delete("/dns/{hostname}", dependencies=[Depends(require_api_key)])
def remove_dns(
    hostname: str,
    remove_all: bool = Query(default=False),
    client: G3100Client = Depends(get_client),
) -> dict[str, Any]:
    client.ensure_logged_in()
    removed = client.remove_dns_ipv4_by_hostname(hostname, remove_all=remove_all)
    return {"removed_slots": removed}


@app.get("/port-forward", dependencies=[Depends(require_api_key)])
def list_port_forward(client: G3100Client = Depends(get_client)) -> dict[str, Any]:
    client.ensure_logged_in()
    return client.get_port_forwarding_settings()


@app.post("/port-forward", dependencies=[Depends(require_api_key)])
def add_port_forward(
    body: PortForwardRequest,
    client: G3100Client = Depends(get_client),
) -> dict[str, Any]:
    client.ensure_logged_in()
    rule_id = client.add_port_forward(
        name=body.name,
        private_ip=body.private_ip,
        forward_port=body.forward_port,
        dest_port=body.dest_port,
        enable=body.enable,
    )
    return {"id": rule_id, **body.model_dump()}


@app.delete("/port-forward/{rule_id}", dependencies=[Depends(require_api_key)])
def remove_port_forward(
    rule_id: int,
    client: G3100Client = Depends(get_client),
) -> dict[str, Any]:
    client.ensure_logged_in()
    result = client.remove_port_forward(rule_id=rule_id)
    return {"removed_id": rule_id, "result": result}


@app.get("/cgi", dependencies=[Depends(require_api_key)])
def list_cgis() -> dict[str, list[str]]:
    return {"available": AVAILABLE_CGIS}


@app.get("/cgi/{name}", dependencies=[Depends(require_api_key)])
def get_cgi(name: str, client: G3100Client = Depends(get_client)) -> dict[str, Any]:
    client.ensure_logged_in()
    try:
        return client.fetch_cgi(name)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---- low-level UI backend endpoints (for full capability) ----
@app.get("/ui/apply-token", dependencies=[Depends(require_api_key)])
def ui_apply_token(client: G3100Client = Depends(get_client)) -> dict[str, Any]:
    token = client.get_ui_apply_token()
    return {"token": token}


@app.post("/ui/db", dependencies=[Depends(require_api_key)])
def ui_db(body: DbRequest, client: G3100Client = Depends(get_client)) -> Any:
    if not body.confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to run /ui/db")
    return client.db(body.payload, token=body.token)


@app.post("/ui/apply-abstract", dependencies=[Depends(require_api_key)])
def ui_apply(body: ApplyAbstractRequest, client: G3100Client = Depends(get_client)) -> Any:
    if not body.confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to run /ui/apply-abstract")
    return client.apply_abstract(body.form, token=body.token)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=False,
    )
