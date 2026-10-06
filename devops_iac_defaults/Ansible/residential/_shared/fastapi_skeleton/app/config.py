from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    api_supported: bool = True
    device_host: str = "http://192.168.1.1"
    device_username: str = "admin"
    device_password: str = ""
    api_key: str = ""
    api_host: str = "0.0.0.0"
    api_port: int = 8838
    auto_login: bool = True


settings = Settings()
