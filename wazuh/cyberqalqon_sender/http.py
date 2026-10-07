"""Centralized HTTP delivery and failure classification."""

from __future__ import annotations

import json
import math
import ssl
from collections.abc import Callable
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from .config import SenderConfig
from .logging import safe_text
from .models import DeliveryClassification, DeliveryResult, FailureCategory


MAX_RESPONSE_BYTES = 65_536


def _safe_backend_message(body: bytes, *, fallback: str) -> str:
    if not body:
        return fallback
    try:
        parsed: Any = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        return fallback
    if not isinstance(parsed, dict):
        return fallback
    detail = parsed.get("detail")
    if isinstance(detail, dict):
        code = detail.get("code")
        message = detail.get("message")
        if isinstance(code, str) and isinstance(message, str):
            return safe_text(f"{code}: {message}")
        if isinstance(message, str):
            return safe_text(message)
    return fallback


def _validated_success(status: int, body: bytes) -> DeliveryResult:
    try:
        parsed: Any = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        parsed = None
    if not isinstance(parsed, dict):
        return DeliveryResult(
            DeliveryClassification.TRANSIENT_FAILURE,
            FailureCategory.PROTOCOL,
            "backend returned a malformed success response; retry is safe",
            status,
        )
    response_status = parsed.get("status")
    duplicate = parsed.get("duplicate")
    if status == 201 and response_status == "created" and duplicate is False:
        return DeliveryResult(DeliveryClassification.DELIVERED, http_status=status)
    if status == 200 and response_status == "duplicate" and duplicate is True:
        return DeliveryResult(DeliveryClassification.DUPLICATE, http_status=status)
    return DeliveryResult(
        DeliveryClassification.TRANSIENT_FAILURE,
        FailureCategory.PROTOCOL,
        "backend success response did not match the ingestion contract; retry is safe",
        status,
    )


def _retry_after_seconds(
    value: str | None,
    *,
    now: Callable[[], datetime],
    maximum: float,
) -> float | None:
    if not value:
        return None
    stripped = value.strip()
    try:
        seconds = float(stripped)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(stripped)
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=timezone.utc)
            seconds = (retry_at - now()).total_seconds()
        except (TypeError, ValueError, OverflowError):
            return None
    if not math.isfinite(seconds) or seconds < 0:
        return None
    return min(seconds, maximum)


def classify_response(
    status: int,
    body: bytes,
    *,
    retry_after: str | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    maximum_retry_after: float = 300.0,
) -> DeliveryResult:
    """Map the backend protocol into one explicit sender outcome."""

    if status in {200, 201}:
        return _validated_success(status, body)
    if 200 <= status < 300:
        return DeliveryResult(
            DeliveryClassification.TRANSIENT_FAILURE,
            FailureCategory.PROTOCOL,
            f"unexpected backend success status {status}; retry is safe",
            status,
        )
    if status == 409:
        return DeliveryResult(
            DeliveryClassification.CONFLICT,
            FailureCategory.CONFLICT,
            _safe_backend_message(body, fallback="backend reported an alert identifier conflict"),
            status,
        )
    if status == 429:
        return DeliveryResult(
            DeliveryClassification.TRANSIENT_FAILURE,
            FailureCategory.RATE_LIMITED,
            "backend rate limited the sender",
            status,
            _retry_after_seconds(
                retry_after,
                now=now,
                maximum=maximum_retry_after,
            ),
        )
    if status in {408, 500, 502, 503, 504} or 500 <= status < 600:
        return DeliveryResult(
            DeliveryClassification.TRANSIENT_FAILURE,
            FailureCategory.SERVER,
            _safe_backend_message(body, fallback=f"backend returned transient HTTP {status}"),
            status,
        )

    permanent_categories = {
        400: FailureCategory.BAD_REQUEST,
        401: FailureCategory.AUTHENTICATION,
        403: FailureCategory.AUTHORIZATION,
        413: FailureCategory.PAYLOAD_TOO_LARGE,
        415: FailureCategory.UNSUPPORTED_MEDIA_TYPE,
        422: FailureCategory.VALIDATION,
    }
    category = permanent_categories.get(status, FailureCategory.PROTOCOL)
    return DeliveryResult(
        DeliveryClassification.PERMANENT_FAILURE,
        category,
        _safe_backend_message(body, fallback=f"backend returned permanent HTTP {status}"),
        status,
    )


class HttpDeliveryClient:
    """TLS-verifying backend client with bounded response handling."""

    def __init__(
        self,
        config: SenderConfig,
        *,
        transport: httpx.BaseTransport | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._config = config
        self._now = now
        context = ssl.create_default_context(
            cafile=str(config.ca_bundle) if config.ca_bundle is not None else None
        )
        timeout = httpx.Timeout(
            config.request_timeout_seconds,
            connect=config.connect_timeout_seconds,
        )
        self._client = httpx.Client(
            timeout=timeout,
            verify=context,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "HttpDeliveryClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @staticmethod
    def _bounded_body(response: httpx.Response) -> tuple[bytes, bool]:
        chunks: list[bytes] = []
        received = 0
        for chunk in response.iter_bytes():
            received += len(chunk)
            if received > MAX_RESPONSE_BYTES:
                return b"", True
            chunks.append(chunk)
        return b"".join(chunks), False

    def deliver(self, payload: bytes) -> DeliveryResult:
        try:
            with self._client.stream(
                "POST",
                self._config.ingest_url,
                headers={
                    "Content-Type": "application/json",
                    "X-API-Key": self._config.api_key,
                },
                content=payload,
            ) as response:
                body, oversized = self._bounded_body(response)
                if oversized:
                    return DeliveryResult(
                        DeliveryClassification.TRANSIENT_FAILURE,
                        FailureCategory.PROTOCOL,
                        "backend response exceeded the sender response limit; retry is safe",
                        response.status_code,
                    )
                return classify_response(
                    response.status_code,
                    body,
                    retry_after=response.headers.get("Retry-After"),
                    now=self._now,
                    maximum_retry_after=self._config.backoff_max_seconds,
                )
        except httpx.ConnectTimeout:
            return DeliveryResult(
                DeliveryClassification.TRANSIENT_FAILURE,
                FailureCategory.CONNECT_TIMEOUT,
                "connection to backend timed out",
            )
        except (httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout, httpx.TimeoutException):
            return DeliveryResult(
                DeliveryClassification.TRANSIENT_FAILURE,
                FailureCategory.REQUEST_TIMEOUT,
                "backend request timed out",
            )
        except (httpx.ConnectError, httpx.NetworkError):
            return DeliveryResult(
                DeliveryClassification.TRANSIENT_FAILURE,
                FailureCategory.NETWORK,
                "backend network connection failed",
            )
        except httpx.ProtocolError:
            return DeliveryResult(
                DeliveryClassification.TRANSIENT_FAILURE,
                FailureCategory.PROTOCOL,
                "backend protocol failure; retry is safe",
            )
        except httpx.HTTPError:
            return DeliveryResult(
                DeliveryClassification.TRANSIENT_FAILURE,
                FailureCategory.UNEXPECTED,
                "unexpected HTTP client failure; retry is safe",
            )
