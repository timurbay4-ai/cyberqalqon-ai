"""Environment-backed application configuration."""

from __future__ import annotations

import os
import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

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


def _parse_nonnegative_float(value: str | None, *, default: float, name: str) -> float:
    if value is None:
        return default
    try:
        parsed = float(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc
    if parsed < 0:
        raise ValueError(f"{name} must be zero or greater")
    return parsed


def _parse_positive_float(value: str | None, *, default: float, name: str) -> float:
    parsed = _parse_nonnegative_float(value, default=default, name=name)
    if parsed <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return parsed


def validate_ollama_base_url(value: str, *, allow_private_network: bool) -> str | None:
    """Return a safe diagnostic when an Ollama URL is not an allowed local endpoint."""

    try:
        parsed = urlsplit(value)
    except ValueError:
        return "OLLAMA_BASE_URL is not a valid URL"
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return "OLLAMA_BASE_URL must use http or https and include a host"
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        return "OLLAMA_BASE_URL must not contain credentials, a query, or a fragment"
    if parsed.path not in {"", "/"}:
        return "OLLAMA_BASE_URL must not contain a path"
    hostname = parsed.hostname.lower().rstrip(".")
    if hostname == "localhost":
        return None
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        if allow_private_network and hostname.endswith(".local"):
            return None
        return "OLLAMA_BASE_URL must use localhost, a loopback address, or an explicitly allowed private endpoint"
    if address.is_loopback:
        return None
    if allow_private_network and address.is_private:
        return None
    return "OLLAMA_BASE_URL must use localhost, a loopback address, or an explicitly allowed private endpoint"


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
    ai_enabled: bool = False
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = ""
    ollama_allow_private_network: bool = False
    ollama_connect_timeout_seconds: float = 3.0
    ollama_request_timeout_seconds: float = 90.0
    ai_max_context_bytes: int = 32_768
    ai_max_alerts_per_request: int = 20
    ai_max_notes_per_request: int = 20
    ai_max_history_per_request: int = 40
    ai_max_field_chars: int = 4_096
    ai_max_raw_event_chars: int = 8_192
    ai_max_output_chars: int = 16_384
    ai_max_concurrent_requests: int = 1
    ai_user_cooldown_seconds: float = 2.0
    ai_health_cache_seconds: float = 15.0

    def __post_init__(self) -> None:
        if "*" in self.cors_origins:
            raise ValueError("CORS_ORIGINS must list explicit origins; wildcard origins are not allowed")
        if self.app_env == "production" and not self.session_cookie_secure:
            raise ValueError("SESSION_COOKIE_SECURE must be true in production")
        for name, value in (
            ("analyst_session_ttl_seconds", self.analyst_session_ttl_seconds),
            ("login_max_failures", self.login_max_failures),
            ("login_lockout_seconds", self.login_lockout_seconds),
            ("ai_max_context_bytes", self.ai_max_context_bytes),
            ("ai_max_alerts_per_request", self.ai_max_alerts_per_request),
            ("ai_max_notes_per_request", self.ai_max_notes_per_request),
            ("ai_max_history_per_request", self.ai_max_history_per_request),
            ("ai_max_field_chars", self.ai_max_field_chars),
            ("ai_max_raw_event_chars", self.ai_max_raw_event_chars),
            ("ai_max_output_chars", self.ai_max_output_chars),
            ("ai_max_concurrent_requests", self.ai_max_concurrent_requests),
        ):
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")
        for name, value in (
            ("ollama_connect_timeout_seconds", self.ollama_connect_timeout_seconds),
            ("ollama_request_timeout_seconds", self.ollama_request_timeout_seconds),
            ("ai_health_cache_seconds", self.ai_health_cache_seconds),
        ):
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")
        if self.ai_user_cooldown_seconds < 0:
            raise ValueError("ai_user_cooldown_seconds must be zero or greater")

    @property
    def ai_configuration_error(self) -> str | None:
        if not self.ai_enabled:
            return None
        if not self.ollama_model.strip():
            return "OLLAMA_MODEL must be configured when AI_ENABLED is true"
        if len(self.ollama_model) > 256 or any(ord(character) < 32 for character in self.ollama_model):
            return "OLLAMA_MODEL must be a bounded printable model name"
        return validate_ollama_base_url(
            self.ollama_base_url,
            allow_private_network=self.ollama_allow_private_network,
        )

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
            ai_enabled=_parse_bool(os.getenv("AI_ENABLED")),
            ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").strip(),
            ollama_model=os.getenv("OLLAMA_MODEL", "").strip(),
            ollama_allow_private_network=_parse_bool(os.getenv("OLLAMA_ALLOW_PRIVATE_NETWORK")),
            ollama_connect_timeout_seconds=_parse_positive_float(
                os.getenv("OLLAMA_CONNECT_TIMEOUT_SECONDS"), default=3.0, name="OLLAMA_CONNECT_TIMEOUT_SECONDS"
            ),
            ollama_request_timeout_seconds=_parse_positive_float(
                os.getenv("OLLAMA_REQUEST_TIMEOUT_SECONDS"), default=90.0, name="OLLAMA_REQUEST_TIMEOUT_SECONDS"
            ),
            ai_max_context_bytes=_parse_positive_int(
                os.getenv("AI_MAX_CONTEXT_BYTES"), default=32_768, name="AI_MAX_CONTEXT_BYTES"
            ),
            ai_max_alerts_per_request=_parse_positive_int(
                os.getenv("AI_MAX_ALERTS_PER_REQUEST"), default=20, name="AI_MAX_ALERTS_PER_REQUEST"
            ),
            ai_max_notes_per_request=_parse_positive_int(
                os.getenv("AI_MAX_NOTES_PER_REQUEST"), default=20, name="AI_MAX_NOTES_PER_REQUEST"
            ),
            ai_max_history_per_request=_parse_positive_int(
                os.getenv("AI_MAX_HISTORY_PER_REQUEST"), default=40, name="AI_MAX_HISTORY_PER_REQUEST"
            ),
            ai_max_field_chars=_parse_positive_int(
                os.getenv("AI_MAX_FIELD_CHARS"), default=4_096, name="AI_MAX_FIELD_CHARS"
            ),
            ai_max_raw_event_chars=_parse_positive_int(
                os.getenv("AI_MAX_RAW_EVENT_CHARS"), default=8_192, name="AI_MAX_RAW_EVENT_CHARS"
            ),
            ai_max_output_chars=_parse_positive_int(
                os.getenv("AI_MAX_OUTPUT_CHARS"), default=16_384, name="AI_MAX_OUTPUT_CHARS"
            ),
            ai_max_concurrent_requests=_parse_positive_int(
                os.getenv("AI_MAX_CONCURRENT_REQUESTS"), default=1, name="AI_MAX_CONCURRENT_REQUESTS"
            ),
            ai_user_cooldown_seconds=_parse_nonnegative_float(
                os.getenv("AI_USER_COOLDOWN_SECONDS"), default=2.0, name="AI_USER_COOLDOWN_SECONDS"
            ),
            ai_health_cache_seconds=_parse_positive_float(
                os.getenv("AI_HEALTH_CACHE_SECONDS"), default=15.0, name="AI_HEALTH_CACHE_SECONDS"
            ),
        )


@lru_cache
def get_settings() -> Settings:
    return Settings.from_env()
