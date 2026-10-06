from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    api_supported: bool = true
    device_host: str = "http://192.168.1.1"
    device_username: str = "admin"
    device_password: str = ""
    router_host: str = "http://192.168.1.1"
    router_username: str = "admin"
    router_password: str = ""
    router_encrypted_password: str = ""
    router_tls_hostname: str = "mynetworksettings.com"
    router_verify_tls: bool = False
    router_port: int = 5000
    router_ssl: bool = False
    switch_host: str = "http://192.168.1.1"
    switch_username: str = "admin"
    switch_password: str = ""
    switch_model: str = "TL-SG105E"
    unifi_host: str = "http://192.168.1.1"
    unifi_api_key: str = ""
    unifi_site_id: str = "default"
    unifi_verify_tls: bool = False
    router_session_token: str = ""
    api_key: str = ""
    api_host: str = "0.0.0.0"
    api_port: int = 8842
    auto_login: bool = True


settings = Settings()
