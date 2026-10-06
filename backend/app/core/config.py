"""Environment-backed application configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DATABASE_URL = "sqlite:///./backend/data/cyberqalqon.db"
DEFAULT_CORS_ORIGINS = (
    "http://localhost:5173",
    "http://localhost:3000",
)


def _parse_bool(value: str | None, *, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_positive_int(value: str | None, *, default: int, name: str) -> int:
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if parsed <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return parsed


def _parse_origins(value: str | None) -> tuple[str, ...]:
    if not value:
        return DEFAULT_CORS_ORIGINS
    origins = tuple(origin.strip().rstrip("/") for origin in value.split(",") if origin.strip())
    if not origins:
        raise ValueError("CORS_ORIGINS must contain at least one origin")
    if "*" in origins:
        raise ValueError("CORS_ORIGINS must list explicit origins; wildcard origins are not allowed")
    return origins


@dataclass(frozen=True, slots=True)
class Settings:
    """Runtime settings with secure defaults for the ingestion boundary."""

    app_env: str = "development"
    app_debug: bool = False
    database_url: str = DEFAULT_DATABASE_URL
    cors_origins: tuple[str, ...] = DEFAULT_CORS_ORIGINS
    wazuh_ingest_api_key: str | None = None
    max_ingest_bytes: int = 1_048_576
    analyst_session_ttl_seconds: int = 28_800
    session_cookie_secure: bool = False
    login_max_failures: int = 5
    login_lockout_seconds: int = 900

    def __post_init__(self) -> None:
        if "*" in self.cors_origins:
            raise ValueError("CORS_ORIGINS must list explicit origins; wildcard origins are not allowed")
        if self.app_env == "production" and not self.session_cookie_secure:
            raise ValueError("SESSION_COOKIE_SECURE must be true in production")
        for name, value in (
            ("analyst_session_ttl_seconds", self.analyst_session_ttl_seconds),
            ("login_max_failures", self.login_max_failures),
            ("login_lockout_seconds", self.login_lockout_seconds),
        ):
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv(REPOSITORY_ROOT / ".env", override=False)
        app_env = os.getenv("APP_ENV", "development").strip().lower()
        api_key = os.getenv("WAZUH_INGEST_API_KEY")
        if api_key is not None:
            api_key = api_key.strip() or None
        session_cookie_secure = _parse_bool(
            os.getenv("SESSION_COOKIE_SECURE"),
            default=app_env not in {"development", "test"},
        )
        if app_env == "production" and not session_cookie_secure:
            raise ValueError("SESSION_COOKIE_SECURE must be true in production")
        return cls(
            app_env=app_env,
            app_debug=_parse_bool(os.getenv("APP_DEBUG")),
            database_url=os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL).strip(),
            cors_origins=_parse_origins(os.getenv("CORS_ORIGINS")),
            wazuh_ingest_api_key=api_key,
            max_ingest_bytes=_parse_positive_int(
                os.getenv("MAX_INGEST_BYTES"),
                default=1_048_576,
                name="MAX_INGEST_BYTES",
            ),
            analyst_session_ttl_seconds=_parse_positive_int(
                os.getenv("ANALYST_SESSION_TTL_SECONDS"),
                default=28_800,
                name="ANALYST_SESSION_TTL_SECONDS",
            ),
            session_cookie_secure=session_cookie_secure,
            login_max_failures=_parse_positive_int(
                os.getenv("LOGIN_MAX_FAILURES"),
                default=5,
                name="LOGIN_MAX_FAILURES",
            ),
            login_lockout_seconds=_parse_positive_int(
                os.getenv("LOGIN_LOCKOUT_SECONDS"),
                default=900,
                name="LOGIN_LOCKOUT_SECONDS",
            ),
        )


@lru_cache
def get_settings() -> Settings:
    return Settings.from_env()
