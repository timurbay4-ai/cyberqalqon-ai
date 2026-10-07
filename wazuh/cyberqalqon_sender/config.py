"""Strict environment-backed configuration for the standalone sender."""

from __future__ import annotations

import math
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


class ConfigurationError(ValueError):
    """Raised when sender configuration is missing, malformed, or unsafe."""


def _default_database_path() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
        return base / "CyberQalqon" / "sender.db"
    return Path("/var/lib/cyberqalqon-sender/sender.db")


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ConfigurationError(f"{name} is required")
    return value


def _boolean(env: Mapping[str, str], name: str, *, default: bool = False) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be true or false")


def _integer(
    env: Mapping[str, str],
    name: str,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    raw = env.get(name)
    if raw is None:
        return default
    try:
        value = int(raw.strip())
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return value


def _number(
    env: Mapping[str, str],
    name: str,
    *,
    default: float,
    minimum: float,
    maximum: float,
    inclusive_minimum: bool = False,
) -> float:
    raw = env.get(name)
    if raw is None:
        return default
    try:
        value = float(raw.strip())
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number") from exc
    lower_ok = value >= minimum if inclusive_minimum else value > minimum
    if not lower_ok or value > maximum:
        relation = "at least" if inclusive_minimum else "greater than"
        raise ConfigurationError(f"{name} must be {relation} {minimum} and at most {maximum}")
    return value


def _normalize_backend_url(raw: str, *, allow_insecure_http: bool) -> str:
    try:
        parsed = urlsplit(raw)
        _ = parsed.port
    except ValueError as exc:
        raise ConfigurationError("CYBERQALQON_URL is malformed") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigurationError("CYBERQALQON_URL must be an absolute http(s) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ConfigurationError("CYBERQALQON_URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ConfigurationError("CYBERQALQON_URL must not contain a query or fragment")
    if parsed.path not in {"", "/"}:
        raise ConfigurationError(
            "CYBERQALQON_URL must be an origin/base URL without an API path"
        )
    hostname = parsed.hostname.lower()
    if parsed.scheme == "http" and not (
        allow_insecure_http and hostname in LOOPBACK_HOSTS
    ):
        raise ConfigurationError(
            "plain HTTP is restricted to loopback and requires "
            "CYBERQALQON_ALLOW_INSECURE_HTTP=true"
        )
    netloc = parsed.netloc.lower()
    return urlunsplit((parsed.scheme.lower(), netloc, "", "", ""))


@dataclass(frozen=True, slots=True)
class SenderConfig:
    backend_url: str
    api_key: str = field(repr=False)
    database_path: Path
    connect_timeout_seconds: float = 5.0
    request_timeout_seconds: float = 15.0
    max_attempts: int = 8
    backoff_base_seconds: float = 2.0
    backoff_max_seconds: float = 300.0
    backoff_jitter_ratio: float = 0.20
    queue_max_items: int = 10_000
    queue_max_bytes: int = 536_870_912
    dead_letter_max_items: int = 1_000
    dead_letter_max_bytes: int = 134_217_728
    max_payload_bytes: int = 1_048_576
    lease_seconds: float = 60.0
    worker_batch_size: int = 100
    worker_poll_seconds: float = 5.0
    sqlite_busy_timeout_seconds: float = 5.0
    ca_bundle: Path | None = None
    log_level: str = "INFO"
    allow_insecure_http: bool = False

    def __post_init__(self) -> None:
        normalized_url = _normalize_backend_url(
            self.backend_url,
            allow_insecure_http=self.allow_insecure_http,
        )
        object.__setattr__(self, "backend_url", normalized_url)
        if (
            self.api_key != self.api_key.strip()
            or len(self.api_key) < 16
            or re.search(r"[\x00-\x1f\x7f]", self.api_key)
        ):
            raise ConfigurationError(
                "CYBERQALQON_INGEST_API_KEY must contain at least 16 non-control characters"
            )
        numeric_ranges = (
            ("CYBERQALQON_CONNECT_TIMEOUT_SECONDS", self.connect_timeout_seconds, 0, 120, False),
            ("CYBERQALQON_REQUEST_TIMEOUT_SECONDS", self.request_timeout_seconds, 0, 300, False),
            ("CYBERQALQON_MAX_ATTEMPTS", self.max_attempts, 1, 100, True),
            ("CYBERQALQON_BACKOFF_BASE_SECONDS", self.backoff_base_seconds, 0, 86_400, False),
            ("CYBERQALQON_BACKOFF_MAX_SECONDS", self.backoff_max_seconds, 0, 86_400, False),
            ("CYBERQALQON_QUEUE_MAX_ITEMS", self.queue_max_items, 1, 1_000_000, True),
            ("CYBERQALQON_QUEUE_MAX_BYTES", self.queue_max_bytes, 1_024, 1_099_511_627_776, True),
            ("CYBERQALQON_DEAD_LETTER_MAX_ITEMS", self.dead_letter_max_items, 1, 1_000_000, True),
            ("CYBERQALQON_DEAD_LETTER_MAX_BYTES", self.dead_letter_max_bytes, 1_024, 1_099_511_627_776, True),
            ("CYBERQALQON_MAX_PAYLOAD_BYTES", self.max_payload_bytes, 1_024, 104_857_600, True),
            ("CYBERQALQON_LEASE_SECONDS", self.lease_seconds, 0, 86_400, False),
            ("CYBERQALQON_WORKER_BATCH_SIZE", self.worker_batch_size, 1, 1_000, True),
            ("CYBERQALQON_WORKER_POLL_SECONDS", self.worker_poll_seconds, 0.05, 300, True),
            ("CYBERQALQON_SQLITE_BUSY_TIMEOUT_SECONDS", self.sqlite_busy_timeout_seconds, 0, 60, False),
        )
        integer_names = {
            "CYBERQALQON_MAX_ATTEMPTS",
            "CYBERQALQON_QUEUE_MAX_ITEMS",
            "CYBERQALQON_QUEUE_MAX_BYTES",
            "CYBERQALQON_DEAD_LETTER_MAX_ITEMS",
            "CYBERQALQON_DEAD_LETTER_MAX_BYTES",
            "CYBERQALQON_MAX_PAYLOAD_BYTES",
            "CYBERQALQON_WORKER_BATCH_SIZE",
        }
        for name, value, minimum, maximum, inclusive_minimum in numeric_ranges:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ConfigurationError(f"{name} must be numeric")
            if name in integer_names and not isinstance(value, int):
                raise ConfigurationError(f"{name} must be an integer")
            if not math.isfinite(value):
                raise ConfigurationError(f"{name} must be finite")
            lower_invalid = value < minimum if inclusive_minimum else value <= minimum
            if lower_invalid or value > maximum:
                relation = "at least" if inclusive_minimum else "greater than"
                raise ConfigurationError(
                    f"{name} must be {relation} {minimum} and at most {maximum}"
                )
        if not 0 <= self.backoff_jitter_ratio <= 0.5:
            raise ConfigurationError(
                "CYBERQALQON_BACKOFF_JITTER_RATIO must be between 0 and 0.5"
            )
        if self.backoff_max_seconds < self.backoff_base_seconds:
            raise ConfigurationError(
                "CYBERQALQON_BACKOFF_MAX_SECONDS must be at least the base delay"
            )
        if self.queue_max_bytes < self.max_payload_bytes:
            raise ConfigurationError(
                "CYBERQALQON_QUEUE_MAX_BYTES must be at least CYBERQALQON_MAX_PAYLOAD_BYTES"
            )
        if self.dead_letter_max_bytes < self.max_payload_bytes:
            raise ConfigurationError(
                "CYBERQALQON_DEAD_LETTER_MAX_BYTES must be at least CYBERQALQON_MAX_PAYLOAD_BYTES"
            )
        if self.lease_seconds < max(10.0, self.request_timeout_seconds * 2):
            raise ConfigurationError(
                "CYBERQALQON_LEASE_SECONDS must be at least twice the request timeout and at least 10"
            )
        database_path = Path(self.database_path).expanduser()
        object.__setattr__(self, "database_path", database_path)
        if not database_path.is_absolute():
            raise ConfigurationError("CYBERQALQON_SENDER_DB must be an absolute path")
        if self.ca_bundle is not None:
            ca_bundle = Path(self.ca_bundle).expanduser()
            object.__setattr__(self, "ca_bundle", ca_bundle)
            if not ca_bundle.is_absolute() or not ca_bundle.is_file():
                raise ConfigurationError(
                    "CYBERQALQON_CA_BUNDLE must name an existing absolute file"
                )
        if self.log_level not in LOG_LEVELS:
            raise ConfigurationError(
                "CYBERQALQON_LOG_LEVEL must be DEBUG, INFO, WARNING, ERROR, or CRITICAL"
            )

    @property
    def ingest_url(self) -> str:
        return f"{self.backend_url}/api/v1/alerts/ingest"

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        overrides: Mapping[str, str] | None = None,
    ) -> "SenderConfig":
        values = dict(os.environ if env is None else env)
        if overrides:
            values.update({key: value for key, value in overrides.items() if value})

        allow_insecure = _boolean(
            values, "CYBERQALQON_ALLOW_INSECURE_HTTP", default=False
        )
        backend_url = _normalize_backend_url(
            _required(values, "CYBERQALQON_URL"),
            allow_insecure_http=allow_insecure,
        )
        api_key = _required(values, "CYBERQALQON_INGEST_API_KEY")

        database_raw = values.get("CYBERQALQON_SENDER_DB")
        database_path = (
            Path(database_raw.strip()).expanduser()
            if database_raw and database_raw.strip()
            else _default_database_path()
        )
        ca_raw = values.get("CYBERQALQON_CA_BUNDLE", "").strip()
        ca_bundle = Path(ca_raw).expanduser() if ca_raw else None

        request_timeout = _number(
            values,
            "CYBERQALQON_REQUEST_TIMEOUT_SECONDS",
            default=15.0,
            minimum=0,
            maximum=300,
        )
        return cls(
            backend_url=backend_url,
            api_key=api_key,
            database_path=database_path,
            connect_timeout_seconds=_number(
                values,
                "CYBERQALQON_CONNECT_TIMEOUT_SECONDS",
                default=5.0,
                minimum=0,
                maximum=120,
            ),
            request_timeout_seconds=request_timeout,
            max_attempts=_integer(
                values,
                "CYBERQALQON_MAX_ATTEMPTS",
                default=8,
                minimum=1,
                maximum=100,
            ),
            backoff_base_seconds=_number(
                values,
                "CYBERQALQON_BACKOFF_BASE_SECONDS",
                default=2.0,
                minimum=0,
                maximum=86_400,
            ),
            backoff_max_seconds=_number(
                values,
                "CYBERQALQON_BACKOFF_MAX_SECONDS",
                default=300.0,
                minimum=0,
                maximum=86_400,
            ),
            backoff_jitter_ratio=_number(
                values,
                "CYBERQALQON_BACKOFF_JITTER_RATIO",
                default=0.20,
                minimum=0,
                maximum=0.50,
                inclusive_minimum=True,
            ),
            queue_max_items=_integer(
                values,
                "CYBERQALQON_QUEUE_MAX_ITEMS",
                default=10_000,
                minimum=1,
                maximum=1_000_000,
            ),
            queue_max_bytes=_integer(
                values,
                "CYBERQALQON_QUEUE_MAX_BYTES",
                default=536_870_912,
                minimum=1_024,
                maximum=1_099_511_627_776,
            ),
            dead_letter_max_items=_integer(
                values,
                "CYBERQALQON_DEAD_LETTER_MAX_ITEMS",
                default=1_000,
                minimum=1,
                maximum=1_000_000,
            ),
            dead_letter_max_bytes=_integer(
                values,
                "CYBERQALQON_DEAD_LETTER_MAX_BYTES",
                default=134_217_728,
                minimum=1_024,
                maximum=1_099_511_627_776,
            ),
            max_payload_bytes=_integer(
                values,
                "CYBERQALQON_MAX_PAYLOAD_BYTES",
                default=1_048_576,
                minimum=1_024,
                maximum=104_857_600,
            ),
            lease_seconds=_number(
                values,
                "CYBERQALQON_LEASE_SECONDS",
                default=max(60.0, request_timeout * 2),
                minimum=0,
                maximum=86_400,
            ),
            worker_batch_size=_integer(
                values,
                "CYBERQALQON_WORKER_BATCH_SIZE",
                default=100,
                minimum=1,
                maximum=1_000,
            ),
            worker_poll_seconds=_number(
                values,
                "CYBERQALQON_WORKER_POLL_SECONDS",
                default=5.0,
                minimum=0.05,
                maximum=300,
                inclusive_minimum=True,
            ),
            sqlite_busy_timeout_seconds=_number(
                values,
                "CYBERQALQON_SQLITE_BUSY_TIMEOUT_SECONDS",
                default=5.0,
                minimum=0,
                maximum=60,
            ),
            ca_bundle=ca_bundle,
            log_level=values.get("CYBERQALQON_LOG_LEVEL", "INFO").strip().upper(),
            allow_insecure_http=allow_insecure,
        )
