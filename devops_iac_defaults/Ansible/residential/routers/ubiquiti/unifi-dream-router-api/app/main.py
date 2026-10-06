from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel

from .client import UniFiClient
from .config import settings

_client: UniFiClient | None = None


def get_client() -> UniFiClient:
    if _client is None:
        raise HTTPException(status_code=503, detail="UniFi client not initialized")
    return _client


def require_api_key(
    x_api_key: Annotated[str | None, Header()] = None,
) -> None:
    if settings.api_key and x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key header")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _client
    _client = UniFiClient()
    yield


app = FastAPI(
    title="UniFi Dream Router API",
    description="REST API for Ubiquiti UniFi Network (Integration API v1)",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
def health(client: UniFiClient = Depends(get_client)) -> dict[str, Any]:
    return {
        "status": "ok" if client.is_reachable() else "degraded",
        "unifi_reachable": client.is_reachable(),
        "api_key_configured": client.has_api_key(),
        "tested": False,
        "note": "Scaffold only — requires UniFi gateway + Integration API key",
    }


@app.get("/devices", dependencies=[Depends(require_api_key)])
def devices(
    offset: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=200),
    client: UniFiClient = Depends(get_client),
) -> Any:
    return client.list_devices(offset=offset, limit=limit)


@app.get("/clients", dependencies=[Depends(require_api_key)])
def clients(
    offset: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=200),
    client: UniFiClient = Depends(get_client),
) -> Any:
    return client.list_clients(offset=offset, limit=limit)


@app.get("/networks", dependencies=[Depends(require_api_key)])
def networks(
    offset: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=200),
    client: UniFiClient = Depends(get_client),
) -> Any:
    return client.list_networks(offset=offset, limit=limit)


@app.get("/wlans", dependencies=[Depends(require_api_key)])
def wlans(
    offset: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=200),
    client: UniFiClient = Depends(get_client),
) -> Any:
    return client.list_wlans(offset=offset, limit=limit)


@app.get("/health/site", dependencies=[Depends(require_api_key)])
def site_health(client: UniFiClient = Depends(get_client)) -> Any:
    return client.site_health()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host=settings.api_host, port=settings.api_port)
