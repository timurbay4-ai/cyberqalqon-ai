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


def _boolean(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_env: str
    database_url: str
    log_level: str
    cors_origins: tuple[str, ...]
    max_request_body_bytes: int
    sqlite_busy_timeout_ms: int
    sqlite_foreign_keys: bool
    api_access_token: str | None
    wazuh_ingest_token: str | None


def _optional_secret(name: str) -> str | None:
    value = os.getenv(name, "").strip()
    return value or None


@lru_cache
def get_settings() -> Settings:
    origins = tuple(origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if origin.strip())
    return Settings(
        app_env=os.getenv("APP_ENV", "development"),
        database_url=os.getenv("DATABASE_URL", "sqlite:///./cyberqalqon.db"),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        cors_origins=origins,
        max_request_body_bytes=_positive_int("MAX_REQUEST_BODY_BYTES", 1_048_576),
        sqlite_busy_timeout_ms=_positive_int("SQLITE_BUSY_TIMEOUT_MS", 5_000),
        sqlite_foreign_keys=_boolean("SQLITE_FOREIGN_KEYS"),
        api_access_token=_optional_secret("API_ACCESS_TOKEN"),
        wazuh_ingest_token=_optional_secret("WAZUH_INGEST_TOKEN"),
    )


def validate_runtime_settings(settings: Settings) -> None:
    if settings.app_env.lower() in {"prod", "production"} and (
        settings.api_access_token is None or settings.wazuh_ingest_token is None
    ):
        raise RuntimeError(
            "API_ACCESS_TOKEN and WAZUH_INGEST_TOKEN are required in production"
        )
