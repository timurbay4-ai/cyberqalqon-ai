from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from app.ai.ollama import OllamaProvider
from app.ai.provider import (
    AIInvalidResponse,
    AIModelUnavailable,
    AIProviderTimeout,
    AIProviderUnavailable,
    AIResponseTooLarge,
    ProviderRequest,
)
from app.schemas.ai import AIAvailability


def _result(**changes) -> dict:
    value = {
        "summary": "Suspicious authentication activity requires review.",
        "assessment": "Evidence is consistent with repeated failed authentication.",
        "key_evidence": ["Several failures were observed."],
        "mitre_context": [{"technique_id": "T1110", "explanation": "Brute force mapping was supplied.", "basis": "observed"}],
        "timeline_summary": None,
        "hypotheses": ["A user may have mistyped a password."],
        "investigation_steps": ["Review adjacent authentication events."],
        "possible_false_positive_reasons": ["An expired password can cause retries."],
        "recommended_actions": ["Ask a human analyst to validate the source."],
        "containment_considerations": [],
        "uncertainties": ["No successful login evidence was supplied."],
    }
    value.update(changes)
    return value


def _provider(handler, *, max_output_chars: int = 16_384, request_timeout: float = 1) -> OllamaProvider:
    return OllamaProvider(
        base_url="http://127.0.0.1:11434",
        model="test-model",
        connect_timeout_seconds=0.1,
        request_timeout_seconds=request_timeout,
        max_output_chars=max_output_chars,
        transport=httpx.MockTransport(handler),
    )


def _analyze(provider: OllamaProvider):
    async def run():
        try:
            return await provider.analyze(ProviderRequest("policy", "payload"))
        finally:
            await provider.close()
    return asyncio.run(run())


def test_ollama_health_finds_configured_model_and_digest() -> None:
    provider = _provider(lambda request: httpx.Response(200, json={"models": [{"name": "test-model:latest", "digest": "abc123"}]}))

    async def run():
        try:
            return await provider.health()
        finally:
            await provider.close()

    health = asyncio.run(run())
    assert health.state is AIAvailability.AVAILABLE
    assert health.model_digest == "abc123"


def test_ollama_health_classifies_missing_model_and_invalid_envelope() -> None:
    missing = _provider(lambda request: httpx.Response(200, json={"models": []}))
    invalid = _provider(lambda request: httpx.Response(200, json={"wrong": []}))

    async def run():
        try:
            return await missing.health(), await invalid.health()
        finally:
            await missing.close()
            await invalid.close()

    first, second = asyncio.run(run())
    assert (first.state, first.diagnostic) == (AIAvailability.UNAVAILABLE, "model_unavailable")
    assert (second.state, second.diagnostic) == (AIAvailability.UNAVAILABLE, "invalid_provider_response")


def test_ollama_request_uses_structured_nonstreaming_no_tools_contract() -> None:
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(200, json={"model": "test-model", "message": {"role": "assistant", "content": json.dumps(_result())}, "done": True})

    result = _analyze(_provider(handler))
    assert result.analysis.summary.startswith("Suspicious")
    assert captured["stream"] is False
    assert captured["options"] == {"temperature": 0}
    assert isinstance(captured["format"], dict)
    assert "tools" not in captured
    assert [message["role"] for message in captured["messages"]] == ["system", "user"]


@pytest.mark.parametrize(
    ("handler", "error"),
    [
        (lambda request: httpx.Response(404, json={"error": "model not found"}), AIModelUnavailable),
        (lambda request: httpx.Response(500, json={"error": "failed"}), AIProviderUnavailable),
        (lambda request: httpx.Response(200, content=b"not-json"), AIInvalidResponse),
        (lambda request: httpx.Response(200, json={"message": {"content": "not-json"}}), AIInvalidResponse),
        (lambda request: httpx.Response(200, json={"message": {"content": json.dumps(_result(summary=3))}}), AIInvalidResponse),
        (lambda request: httpx.Response(200, json={"message": {"content": json.dumps(_result(extra="forbidden"))}}), AIInvalidResponse),
        (lambda request: httpx.Response(200, json={"message": {"content": json.dumps(_result(key_evidence=["x"] * 13))}}), AIInvalidResponse),
        (lambda request: httpx.Response(200, json={"message": {"content": json.dumps(_result(summary="x" * 2001))}}), AIInvalidResponse),
    ],
)
def test_ollama_rejects_http_and_model_contract_failures(handler, error) -> None:
    with pytest.raises(error):
        _analyze(_provider(handler))


def test_ollama_rejects_oversized_model_content_and_envelope() -> None:
    content = json.dumps(_result(summary="x" * 100))
    with pytest.raises(AIResponseTooLarge):
        _analyze(_provider(lambda request: httpx.Response(200, json={"message": {"content": content}}), max_output_chars=20))

    with pytest.raises(AIResponseTooLarge):
        _analyze(_provider(lambda request: httpx.Response(200, content=b"x" * 70_000), max_output_chars=20))


def test_ollama_classifies_connection_close_and_timeout() -> None:
    def connection_error(request: httpx.Request):
        raise httpx.ConnectError("refused", request=request)

    def timeout(request: httpx.Request):
        raise httpx.ReadTimeout("slow", request=request)

    with pytest.raises(AIProviderUnavailable):
        _analyze(_provider(connection_error))
    with pytest.raises(AIProviderTimeout):
        _analyze(_provider(timeout))
