"""Environment-backed application configuration."""

from dataclasses import dataclass
from functools import lru_cache
import os


def _positive_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default


@dataclass(frozen=True)
class Settings:
    app_env: str
    database_url: str
    log_level: str
    cors_origins: tuple[str, ...]
    max_request_body_bytes: int


@lru_cache
def get_settings() -> Settings:
    origins = tuple(origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if origin.strip())
    return Settings(
        app_env=os.getenv("APP_ENV", "development"),
        database_url=os.getenv("DATABASE_URL", "sqlite:///./cyberqalqon.db"),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        cors_origins=origins,
        max_request_body_bytes=_positive_int("MAX_REQUEST_BODY_BYTES", 1_048_576),
    )
