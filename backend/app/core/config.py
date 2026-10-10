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
    "http://127.0.0.1:5173",
    "http://localhost:3000",
)


def _parse_bool(value: str | None, *, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _secret_from_env(name: str) -> str | None:
    """Read one secret from either NAME or NAME_FILE without logging its value."""

    direct = os.getenv(name)
    secret_file = os.getenv(f"{name}_FILE")
    if direct is not None and secret_file:
        raise ValueError(f"Configure only one of {name} or {name}_FILE")
    if secret_file:
        path = Path(secret_file)
        try:
            value = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ValueError(f"Unable to read {name}_FILE") from exc
        if "\x00" in value:
            raise ValueError(f"{name}_FILE contains invalid data")
        direct = value
    return direct.strip() if direct is not None else None


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


def _parse_nonnegative_int(value: str | None, *, default: int, name: str) -> int:
    raw = str(default) if value is None or not value.strip() else value.strip()
    try:
        parsed = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if parsed < 0:
        raise ValueError(f"{name} must be zero or greater")
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


def validate_ollama_base_url(
    value: str,
    *,
    allow_private_network: bool,
    allowed_hosts: tuple[str, ...] = (),
) -> str | None:
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
        if allow_private_network and hostname in allowed_hosts:
            return None
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


def _parse_host_allowlist(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    hosts = tuple(host.strip().lower().rstrip(".") for host in value.split(",") if host.strip())
    for host in hosts:
        if not host or ":" in host or "/" in host or any(character.isspace() for character in host):
            raise ValueError("OLLAMA_ALLOWED_HOSTS must contain hostnames only")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            continue
        raise ValueError("OLLAMA_ALLOWED_HOSTS is for DNS hostnames; private IPs use the existing network opt-in")
    return hosts


@dataclass(frozen=True, slots=True)
class Settings:
    """Runtime settings with secure defaults for the ingestion boundary."""

    app_env: str = "development"
    app_debug: bool = False
    database_url: str = DEFAULT_DATABASE_URL
    cors_origins: tuple[str, ...] = DEFAULT_CORS_ORIGINS
    wazuh_ingest_api_key: str | None = None
    wazuh_api_url: str = "https://127.0.0.1:55000"
    wazuh_api_username: str | None = None
    wazuh_api_password: str | None = None
    wazuh_api_ca_bundle: str | None = None
    wazuh_api_timeout_seconds: float = 3.0
    max_ingest_bytes: int = 1_048_576
    max_event_ingest_bytes: int = 262_144
    security_event_retention_days: int = 30
    security_event_max_records: int = 100_000
    analyst_session_ttl_seconds: int = 28_800
    session_cookie_secure: bool = False
    login_max_failures: int = 5
    login_lockout_seconds: int = 900
    correlation_enabled: bool = True
    correlation_window_seconds: int = 900
    correlation_max_candidates: int = 200
    correlation_max_links: int = 50
    correlation_retry_attempts: int = 1
    ai_enabled: bool = False
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = ""
    ollama_allow_private_network: bool = False
    ollama_allowed_hosts: tuple[str, ...] = ()
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
            ("correlation_window_seconds", self.correlation_window_seconds),
            ("correlation_max_candidates", self.correlation_max_candidates),
            ("correlation_max_links", self.correlation_max_links),
            ("max_event_ingest_bytes", self.max_event_ingest_bytes),
            ("security_event_retention_days", self.security_event_retention_days),
            ("security_event_max_records", self.security_event_max_records),
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
            ("wazuh_api_timeout_seconds", self.wazuh_api_timeout_seconds),
            ("ollama_connect_timeout_seconds", self.ollama_connect_timeout_seconds),
            ("ollama_request_timeout_seconds", self.ollama_request_timeout_seconds),
            ("ai_health_cache_seconds", self.ai_health_cache_seconds),
        ):
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")
        if self.ai_user_cooldown_seconds < 0:
            raise ValueError("ai_user_cooldown_seconds must be zero or greater")
        if self.correlation_retry_attempts < 0 or self.correlation_retry_attempts > 3:
            raise ValueError("correlation_retry_attempts must be between zero and three")
        if self.correlation_window_seconds > 86_400:
            raise ValueError("correlation_window_seconds must not exceed 86400")
        if not 3 <= self.correlation_max_candidates <= 5_000:
            raise ValueError("correlation_max_candidates must be between three and 5000")
        if not 3 <= self.correlation_max_links <= 100:
            raise ValueError("correlation_max_links must be between three and 100")
        if self.correlation_max_links > self.correlation_max_candidates:
            raise ValueError("correlation_max_links must not exceed correlation_max_candidates")
        if self.max_event_ingest_bytes > 1_048_576:
            raise ValueError("max_event_ingest_bytes must not exceed 1048576")
        if self.security_event_retention_days > 3650:
            raise ValueError("security_event_retention_days must not exceed 3650")
        if not 100 <= self.security_event_max_records <= 10_000_000:
            raise ValueError("security_event_max_records must be between 100 and 10000000")
        if bool(self.wazuh_api_username) != bool(self.wazuh_api_password):
            raise ValueError("WAZUH_API_USERNAME and WAZUH_API_PASSWORD must be configured together")
        parsed_wazuh_api = urlsplit(self.wazuh_api_url)
        if (
            parsed_wazuh_api.scheme != "https"
            or parsed_wazuh_api.hostname not in {"127.0.0.1", "::1", "localhost"}
            or parsed_wazuh_api.username
            or parsed_wazuh_api.password
            or parsed_wazuh_api.query
            or parsed_wazuh_api.fragment
            or parsed_wazuh_api.path not in {"", "/"}
        ):
            raise ValueError("WAZUH_API_URL must be an HTTPS loopback origin without credentials or a path")

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
            allowed_hosts=self.ollama_allowed_hosts,
        )

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv(REPOSITORY_ROOT / ".env", override=False)
        app_env = os.getenv("APP_ENV", "development").strip().lower()
        api_key = _secret_from_env("WAZUH_INGEST_API_KEY") or None
        wazuh_api_username = _secret_from_env("WAZUH_API_USERNAME") or None
        wazuh_api_password = _secret_from_env("WAZUH_API_PASSWORD") or None
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
            wazuh_api_url=os.getenv("WAZUH_API_URL", "https://127.0.0.1:55000").strip().rstrip("/"),
            wazuh_api_username=wazuh_api_username,
            wazuh_api_password=wazuh_api_password,
            wazuh_api_ca_bundle=os.getenv("WAZUH_API_CA_BUNDLE", "").strip() or None,
            wazuh_api_timeout_seconds=_parse_positive_float(
                os.getenv("WAZUH_API_TIMEOUT_SECONDS"), default=3.0, name="WAZUH_API_TIMEOUT_SECONDS"
            ),
            max_ingest_bytes=_parse_positive_int(
                os.getenv("MAX_INGEST_BYTES"),
                default=1_048_576,
                name="MAX_INGEST_BYTES",
            ),
            max_event_ingest_bytes=_parse_positive_int(
                os.getenv("MAX_EVENT_INGEST_BYTES"),
                default=262_144,
                name="MAX_EVENT_INGEST_BYTES",
            ),
            security_event_retention_days=_parse_positive_int(
                os.getenv("SECURITY_EVENT_RETENTION_DAYS"),
                default=30,
                name="SECURITY_EVENT_RETENTION_DAYS",
            ),
            security_event_max_records=_parse_positive_int(
                os.getenv("SECURITY_EVENT_MAX_RECORDS"),
                default=100_000,
                name="SECURITY_EVENT_MAX_RECORDS",
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
            correlation_enabled=_parse_bool(os.getenv("CORRELATION_ENABLED"), default=True),
            correlation_window_seconds=_parse_positive_int(
                os.getenv("CORRELATION_WINDOW_SECONDS"), default=900, name="CORRELATION_WINDOW_SECONDS"
            ),
            correlation_max_candidates=_parse_positive_int(
                os.getenv("CORRELATION_MAX_CANDIDATES"), default=200, name="CORRELATION_MAX_CANDIDATES"
            ),
            correlation_max_links=_parse_positive_int(
                os.getenv("CORRELATION_MAX_LINKS"), default=50, name="CORRELATION_MAX_LINKS"
            ),
            correlation_retry_attempts=_parse_nonnegative_int(
                os.getenv("CORRELATION_RETRY_ATTEMPTS"), default=1, name="CORRELATION_RETRY_ATTEMPTS"
            ),
            ai_enabled=_parse_bool(os.getenv("AI_ENABLED")),
            ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").strip(),
            ollama_model=os.getenv("OLLAMA_MODEL", "").strip(),
            ollama_allow_private_network=_parse_bool(os.getenv("OLLAMA_ALLOW_PRIVATE_NETWORK")),
            ollama_allowed_hosts=_parse_host_allowlist(os.getenv("OLLAMA_ALLOWED_HOSTS")),
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
