from __future__ import annotations

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
    title="Pace 5268AC API",
    description="REST API scaffold for Pace 5268AC",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
def health(client: DeviceClient = Depends(get_client)) -> dict[str, Any]:
    return {
        "status": "ok" if client.is_reachable() else "degraded",
        "reachable": client.is_reachable(),
        "api_supported": settings.api_supported,
        "tested": False,
        "device": "Pace 5268AC",
    }


@app.get("/status", dependencies=[Depends(require_api_key)])
def status(client: DeviceClient = Depends(get_client)) -> dict[str, Any]:
    return client.status()
