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
    api_access_token: str | None
    wazuh_ingest_token: str | None
    ai_provider: str
    ai_model: str | None
    ai_base_url: str
    ai_timeout_seconds: int
    ai_max_input_chars: int
    ai_max_concurrent_requests: int
    ai_temperature: float


def _optional_secret(name: str) -> str | None:
    value = os.getenv(name, "").strip()
    return value or None


def _temperature() -> float:
    try:
        value = float(os.getenv("AI_TEMPERATURE", "0.1"))
    except ValueError:
        return 0.1
    return min(max(value, 0.0), 1.0)


@lru_cache
def get_settings() -> Settings:
    origins = tuple(origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if origin.strip())
    return Settings(
        app_env=os.getenv("APP_ENV", "development"),
        database_url=os.getenv("DATABASE_URL", "sqlite:///./cyberqalqon.db"),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        cors_origins=origins,
        max_request_body_bytes=_positive_int("MAX_REQUEST_BODY_BYTES", 1_048_576),
        api_access_token=_optional_secret("API_ACCESS_TOKEN"),
        wazuh_ingest_token=_optional_secret("WAZUH_INGEST_TOKEN"),
        ai_provider=os.getenv("AI_PROVIDER", "noop").strip().lower() or "noop",
        ai_model=_optional_secret("AI_MODEL"),
        ai_base_url=os.getenv("AI_BASE_URL", "http://127.0.0.1:11434").strip().rstrip("/"),
        ai_timeout_seconds=_positive_int("AI_TIMEOUT_SECONDS", 120),
        ai_max_input_chars=_positive_int("AI_MAX_INPUT_CHARS", 16000),
        ai_max_concurrent_requests=_positive_int("AI_MAX_CONCURRENT_REQUESTS", 1),
        ai_temperature=_temperature(),
    )


def validate_runtime_settings(settings: Settings) -> None:
    if settings.app_env.lower() in {"prod", "production"} and (
        settings.api_access_token is None or settings.wazuh_ingest_token is None
    ):
        raise RuntimeError(
            "API_ACCESS_TOKEN and WAZUH_INGEST_TOKEN are required in production"
        )
    if settings.ai_provider not in {"noop", "ollama"}:
        raise RuntimeError("AI_PROVIDER must be 'noop' or 'ollama'")
    if settings.ai_provider == "ollama" and not settings.ai_model:
        raise RuntimeError("AI_MODEL is required when AI_PROVIDER=ollama")
