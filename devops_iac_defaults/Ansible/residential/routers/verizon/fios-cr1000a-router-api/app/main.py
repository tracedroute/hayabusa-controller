from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel

from .client import CR1000AClient
from .config import settings

_client: CR1000AClient | None = None


def get_client() -> CR1000AClient:
    if _client is None:
        raise HTTPException(status_code=503, detail="Router client not initialized")
    return _client


def require_api_key(
    x_api_key: Annotated[str | None, Header()] = None,
) -> None:
    if settings.api_key and x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key header")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _client
    _client = CR1000AClient()
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
    title="Verizon Fios CR1000A Router API",
    description="REST API for Verizon CR1000A/CR1000B (untested without hardware)",
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


@app.get("/health")
def health(client: CR1000AClient = Depends(get_client)) -> dict[str, Any]:
    reachable = client.is_reachable()
    logged_in = False
    if reachable:
        try:
            logged_in = client.login_status().get("islogin") == "1"
        except Exception:
            pass
    return {
        "status": "ok" if reachable else "degraded",
        "router_reachable": reachable,
        "logged_in": logged_in,
        "model": "CR1000A",
        "tested": False,
        "note": "Scaffold only — requires CR1000A hardware to validate",
    }


@app.get("/auth/status", dependencies=[Depends(require_api_key)])
def auth_status(client: CR1000AClient = Depends(get_client)) -> dict[str, Any]:
    return client.login_status()


@app.post("/auth/login", dependencies=[Depends(require_api_key)])
def auth_login(body: LoginRequest, client: CR1000AClient = Depends(get_client)) -> dict[str, Any]:
    client.login(body.username, body.password, keep_login=body.keep_login)
    status = client.login_status()
    if status.get("islogin") != "1":
        raise HTTPException(status_code=401, detail="Login failed")
    return {"logged_in": True, "expires": status.get("expires")}


@app.get("/status", dependencies=[Depends(require_api_key)])
def status(client: CR1000AClient = Depends(get_client)) -> dict[str, Any]:
    client.ensure_logged_in()
    return client.status_summary()


@app.get("/devices", dependencies=[Depends(require_api_key)])
def devices(client: CR1000AClient = Depends(get_client)) -> list[dict[str, Any]]:
    client.ensure_logged_in()
    return client.fetch_known_devices()


@app.get("/dns", dependencies=[Depends(require_api_key)])
def list_dns(client: CR1000AClient = Depends(get_client)) -> dict[str, Any]:
    client.ensure_logged_in()
    return {
        "ipv4": client.get_dns_entries_v4(),
        "ipv6": client.get_dns_entries_v6(),
    }


@app.post("/dns", dependencies=[Depends(require_api_key)])
def add_dns(body: DnsEntryRequest, client: CR1000AClient = Depends(get_client)) -> dict[str, Any]:
    client.ensure_logged_in()
    slot = client.add_dns_ipv4(body.hostname, body.ip)
    return {"slot": slot, "hostname": body.hostname, "ip": body.ip}


@app.delete("/dns/{hostname}", dependencies=[Depends(require_api_key)])
def remove_dns(
    hostname: str,
    remove_all: bool = Query(default=False),
    client: CR1000AClient = Depends(get_client),
) -> dict[str, Any]:
    client.ensure_logged_in()
    removed = client.remove_dns_ipv4_by_hostname(hostname, remove_all=remove_all)
    return {"removed_slots": removed}


@app.get("/port-forward", dependencies=[Depends(require_api_key)])
def list_port_forward(client: CR1000AClient = Depends(get_client)) -> dict[str, Any]:
    client.ensure_logged_in()
    return client.get_port_forwarding_settings()


@app.post("/port-forward", dependencies=[Depends(require_api_key)])
def add_port_forward(
    body: PortForwardRequest,
    client: CR1000AClient = Depends(get_client),
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
    client: CR1000AClient = Depends(get_client),
) -> dict[str, Any]:
    client.ensure_logged_in()
    result = client.remove_port_forward(rule_id=rule_id)
    return {"removed_id": rule_id, "result": result}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host=settings.api_host, port=settings.api_port)
