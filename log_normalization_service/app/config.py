from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # SIEM connection
    siem_base_url: str = "http://localhost:8080"
    siem_api_token: str = ""
    siem_events_path: str = "/api/v1/events"
    siem_poll_interval_seconds: int = 5
    siem_verify_ssl: bool = True

    # Service
    service_host: str = "0.0.0.0"
    service_port: int = 8000
    log_level: str = "INFO"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
