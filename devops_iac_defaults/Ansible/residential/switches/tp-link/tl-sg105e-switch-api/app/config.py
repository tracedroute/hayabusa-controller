from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    switch_host: str = "192.168.1.213"
    switch_username: str = "admin"
    switch_password: str = ""
    switch_model: str = "TL-SG105E"

    api_key: str = ""
    api_host: str = "0.0.0.0"
    api_port: int = 8790
    auto_login: bool = True


settings = Settings()
