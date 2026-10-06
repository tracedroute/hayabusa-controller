from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from .client import TpLinkSwitchClient
from .config import settings

_client: TpLinkSwitchClient | None = None


def get_client() -> TpLinkSwitchClient:
    if _client is None:
        raise HTTPException(status_code=503, detail="Switch client not initialized")
    return _client


def require_api_key(
    x_api_key: Annotated[str | None, Header()] = None,
) -> None:
    if settings.api_key and x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key header")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _client
    _client = TpLinkSwitchClient()
    if settings.auto_login and settings.switch_password:
        try:
            _client.ensure_logged_in()
        except Exception:
            pass
    yield
    if _client is not None:
        _client.logout()


app = FastAPI(
    title="TP-Link TL-SG105E Switch API",
    description="REST API for TP-Link Easy Smart managed switches",
    version="1.0.0",
    lifespan=lifespan,
)


class LoginRequest(BaseModel):
    username: str = "admin"
    password: str


class RpcRequest(BaseModel):
    method: str
    params: dict[str, Any] = {}
    confirm: bool = False


@app.get("/health")
def health(client: TpLinkSwitchClient = Depends(get_client)) -> dict[str, Any]:
    reachable = client.is_reachable()
    return {
        "status": "ok" if reachable else "degraded",
        "switch_reachable": reachable,
        "host": settings.switch_host,
        "model": settings.switch_model,
        "logged_in": client._logged_in,
        "tested": client._logged_in,
    }


@app.get("/system", dependencies=[Depends(require_api_key)])
def system(client: TpLinkSwitchClient = Depends(get_client)) -> dict[str, Any]:
    client.ensure_logged_in()
    return client.system_info()


@app.get("/ports", dependencies=[Depends(require_api_key)])
def ports(client: TpLinkSwitchClient = Depends(get_client)) -> list[dict[str, Any]]:
    client.ensure_logged_in()
    return client.port_settings()


@app.get("/ports/statistics", dependencies=[Depends(require_api_key)])
def port_stats(client: TpLinkSwitchClient = Depends(get_client)) -> list[dict[str, Any]]:
    client.ensure_logged_in()
    return client.port_statistics()


@app.get("/vlans/dot1q", dependencies=[Depends(require_api_key)])
def dot1q_vlans(client: TpLinkSwitchClient = Depends(get_client)) -> dict[str, Any]:
    client.ensure_logged_in()
    return client.dot1q_vlans()


@app.get("/vlans/port", dependencies=[Depends(require_api_key)])
def port_vlan(client: TpLinkSwitchClient = Depends(get_client)) -> dict[str, Any]:
    client.ensure_logged_in()
    return client.port_vlan()


@app.get("/mirror", dependencies=[Depends(require_api_key)])
def mirror(client: TpLinkSwitchClient = Depends(get_client)) -> dict[str, Any]:
    client.ensure_logged_in()
    return client.port_mirror()


@app.get("/igmp", dependencies=[Depends(require_api_key)])
def igmp(client: TpLinkSwitchClient = Depends(get_client)) -> dict[str, Any]:
    client.ensure_logged_in()
    return client.igmp_snooping()


@app.get("/qos", dependencies=[Depends(require_api_key)])
def qos(client: TpLinkSwitchClient = Depends(get_client)) -> dict[str, Any]:
    client.ensure_logged_in()
    return client.qos_settings()


@app.post("/rpc", dependencies=[Depends(require_api_key)])
def rpc(body: RpcRequest, client: TpLinkSwitchClient = Depends(get_client)) -> Any:
    try:
        return client.rpc(body.method, body.params, confirm=body.confirm)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/auth/login", dependencies=[Depends(require_api_key)])
def auth_login(body: LoginRequest) -> dict[str, bool]:
    global _client
    settings.switch_username = body.username
    settings.switch_password = body.password
    _client = TpLinkSwitchClient()
    _client._connect()
    return {"logged_in": True}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host=settings.api_host, port=settings.api_port)
