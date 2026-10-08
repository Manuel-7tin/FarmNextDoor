from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "My FastAPI API"
    environment: str = "development"

    secret_key: str
    database_url: str

    frontend_urls: list[str] = [
        "http://localhost:3000"
    ]

    cookie_name: str = "session_id"
    cookie_secure: bool = False
    cookie_samesite: str = "lax"
    cookie_domain: str | None = None

    session_expire_hours: int = 12
    remember_me_days: int = 30

    public_api_url: str = "http://localhost:8000"

    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_username: str
    smtp_password: str
    email_from: str
    email_from_name: str = "My App"

    max_login_failures: int = 5
    lockout_minutes: int = 15

    ip_rate_limit_attempts: int = 20
    ip_rate_limit_window_minutes: int = 10

    email_verification_hours: int = 24
    password_reset_minutes: int = 30

    min_password_length: int = 8
    max_password_length: int = 128

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @field_validator("frontend_urls", mode="before")
    @classmethod
    def parse_frontend_urls(cls, value):
        if isinstance(value, str):
            return [
                item.strip()
                for item in value.split(",")
                if item.strip()
            ]

        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()