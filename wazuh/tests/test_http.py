from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest

from cyberqalqon_sender.config import SenderConfig
from cyberqalqon_sender.http import HttpDeliveryClient, classify_response
from cyberqalqon_sender.models import DeliveryClassification, FailureCategory


CREATED = b'{"status":"created","duplicate":false}'
DUPLICATE = b'{"status":"duplicate","duplicate":true}'


def _client(
    config: SenderConfig,
    handler,
) -> HttpDeliveryClient:
    return HttpDeliveryClient(config, transport=httpx.MockTransport(handler))


def test_first_delivery_sends_exact_protocol(config: SenderConfig) -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["url"] = str(request.url)
        captured["content_type"] = request.headers["Content-Type"]
        captured["api_key"] = request.headers["X-API-Key"]
        captured["body"] = request.content
        return httpx.Response(201, content=CREATED)

    with _client(config, handler) as client:
        result = client.deliver(b'{"id":"one"}')

    assert result.classification == DeliveryClassification.DELIVERED
    assert captured == {
        "method": "POST",
        "url": "http://127.0.0.1:8000/api/v1/alerts/ingest",
        "content_type": "application/json",
        "api_key": config.api_key,
        "body": b'{"id":"one"}',
    }


def test_duplicate_is_delivered_equivalent(config: SenderConfig) -> None:
    with _client(config, lambda _request: httpx.Response(200, content=DUPLICATE)) as client:
        result = client.deliver(b"{}")
    assert result.classification == DeliveryClassification.DUPLICATE
    assert result.delivered_equivalent


@pytest.mark.parametrize(
    ("status", "classification", "category"),
    [
        (400, DeliveryClassification.PERMANENT_FAILURE, FailureCategory.BAD_REQUEST),
        (401, DeliveryClassification.PERMANENT_FAILURE, FailureCategory.AUTHENTICATION),
        (403, DeliveryClassification.PERMANENT_FAILURE, FailureCategory.AUTHORIZATION),
        (409, DeliveryClassification.CONFLICT, FailureCategory.CONFLICT),
        (413, DeliveryClassification.PERMANENT_FAILURE, FailureCategory.PAYLOAD_TOO_LARGE),
        (415, DeliveryClassification.PERMANENT_FAILURE, FailureCategory.UNSUPPORTED_MEDIA_TYPE),
        (422, DeliveryClassification.PERMANENT_FAILURE, FailureCategory.VALIDATION),
        (429, DeliveryClassification.TRANSIENT_FAILURE, FailureCategory.RATE_LIMITED),
        (500, DeliveryClassification.TRANSIENT_FAILURE, FailureCategory.SERVER),
        (502, DeliveryClassification.TRANSIENT_FAILURE, FailureCategory.SERVER),
        (503, DeliveryClassification.TRANSIENT_FAILURE, FailureCategory.SERVER),
        (504, DeliveryClassification.TRANSIENT_FAILURE, FailureCategory.SERVER),
    ],
)
def test_status_classification(
    status: int,
    classification: DeliveryClassification,
    category: FailureCategory,
) -> None:
    result = classify_response(status, b"{}")
    assert result.classification == classification
    assert result.failure_category == category


@pytest.mark.parametrize(
    ("exception", "category"),
    [
        (httpx.ConnectError("offline"), FailureCategory.NETWORK),
        (httpx.ConnectTimeout("connect timeout"), FailureCategory.CONNECT_TIMEOUT),
        (httpx.ReadTimeout("read timeout"), FailureCategory.REQUEST_TIMEOUT),
    ],
)
def test_network_failures_are_transient(
    config: SenderConfig,
    exception: httpx.HTTPError,
    category: FailureCategory,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        exception.request = request
        raise exception

    with _client(config, handler) as client:
        result = client.deliver(b"{}")
    assert result.classification == DeliveryClassification.TRANSIENT_FAILURE
    assert result.failure_category == category


@pytest.mark.parametrize("status", [200, 201])
def test_malformed_success_is_retried_conservatively(status: int) -> None:
    result = classify_response(status, b"not-json")
    assert result.classification == DeliveryClassification.TRANSIENT_FAILURE
    assert result.failure_category == FailureCategory.PROTOCOL


def test_wrong_success_contract_is_retried_conservatively() -> None:
    result = classify_response(201, DUPLICATE)
    assert result.classification == DeliveryClassification.TRANSIENT_FAILURE


def test_retry_after_seconds_and_date_are_bounded() -> None:
    seconds = classify_response(429, b"{}", retry_after="120", maximum_retry_after=300)
    assert seconds.retry_after_seconds == 120

    date = classify_response(
        429,
        b"{}",
        retry_after="Wed, 07 Oct 2026 12:02:00 GMT",
        now=lambda: datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc),
        maximum_retry_after=90,
    )
    assert date.retry_after_seconds == 90

    invalid = classify_response(429, b"{}", retry_after="later")
    assert invalid.retry_after_seconds is None
    non_finite = classify_response(429, b"{}", retry_after="NaN")
    assert non_finite.retry_after_seconds is None


def test_unexpected_2xx_and_redirect_are_not_delivery() -> None:
    assert classify_response(204, b"").classification == DeliveryClassification.TRANSIENT_FAILURE
    redirect = classify_response(307, b"")
    assert redirect.classification == DeliveryClassification.PERMANENT_FAILURE
    assert redirect.failure_category == FailureCategory.PROTOCOL


def test_response_body_is_bounded(config: SenderConfig) -> None:
    body = b"x" * 70_000
    with _client(config, lambda _request: httpx.Response(500, content=body)) as client:
        result = client.deliver(b"{}")
    assert result.classification == DeliveryClassification.TRANSIENT_FAILURE
    assert result.failure_category == FailureCategory.PROTOCOL


def test_backend_error_message_is_sanitized_and_bounded() -> None:
    body = (
        '{"detail":{"code":"bad","message":"line1\\n\\u001b[31m'
        + ("x" * 500)
        + '"}}'
    ).encode()
    result = classify_response(400, body)
    assert result.safe_message is not None
    assert "\n" not in result.safe_message
    assert "\x1b" not in result.safe_message
    assert len(result.safe_message) <= 256
