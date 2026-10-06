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
    api_port: int = 8788
    auto_login: bool = True


settings = Settings()
