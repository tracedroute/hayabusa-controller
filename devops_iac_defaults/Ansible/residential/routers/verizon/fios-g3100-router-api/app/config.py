from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    router_host: str = "https://192.168.1.1"
    router_username: str = "admin"
    router_password: str = ""
    router_tls_hostname: str = "mynetworksettings.com"
    router_verify_tls: bool = False

    api_key: str = ""
    api_host: str = "0.0.0.0"
    api_port: int = 8787
    auto_login: bool = True


settings = Settings()


def _env_from_file(key: str) -> str | None:
    """
    Resolve a key from this project's .env file explicitly.

    Reason: when running in a long-lived shell, process env vars like API_KEY can
    override the .env-loaded settings in unexpected ways.
    """
    project_root = Path(__file__).resolve().parent.parent
    env_path = project_root / ".env"
    if not env_path.exists():
        return None
    for line in env_path.read_text().splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        if k.strip() == key:
            return v.strip().strip('"').strip("'")
    return None


# Force project .env values to win over any existing process env.
for _k in ("API_KEY", "ROUTER_PASSWORD", "ROUTER_USERNAME", "ROUTER_HOST", "ROUTER_TLS_HOSTNAME", "ROUTER_VERIFY_TLS"):
    v = _env_from_file(_k)
    if v is None:
        continue
    attr = _k.lower()
    if _k == "API_KEY":
        settings.api_key = v
    elif _k == "ROUTER_PASSWORD":
        settings.router_password = v
    elif _k == "ROUTER_USERNAME":
        settings.router_username = v
    elif _k == "ROUTER_HOST":
        settings.router_host = v
    elif _k == "ROUTER_TLS_HOSTNAME":
        settings.router_tls_hostname = v
    elif _k == "ROUTER_VERIFY_TLS":
        settings.router_verify_tls = v.lower() in ("1", "true", "yes", "on")
