from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    unifi_host: str = "https://192.168.1.1"
    unifi_api_key: str = ""
    unifi_site_id: str = "default"
    unifi_verify_tls: bool = False

    api_key: str = ""
    api_host: str = "0.0.0.0"
    api_port: int = 8789


settings = Settings()
