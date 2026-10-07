"""Minimal Ollama HTTP adapter with strict transport and response bounds."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
from pydantic import ValidationError

from app.ai.provider import (
    AIInvalidResponse,
    AIModelUnavailable,
    AIProviderTimeout,
    AIProviderUnavailable,
    AIResponseTooLarge,
    ProviderHealth,
    ProviderRequest,
    ProviderResult,
)
from app.schemas.ai import AIAnalysisResult, AIAvailability


class OllamaProvider:
    """Talk only to the configured Ollama HTTP API; no tools or remote fallback."""

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        connect_timeout_seconds: float,
        request_timeout_seconds: float,
        max_output_chars: int,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.model = model
        self.request_timeout_seconds = request_timeout_seconds
        self.max_output_chars = max_output_chars
        self.max_envelope_bytes = max(65_536, max_output_chars * 4 + 32_768)
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=httpx.Timeout(request_timeout_seconds, connect=connect_timeout_seconds),
            follow_redirects=False,
            trust_env=False,
            transport=transport,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def _bounded_request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        limit: int,
    ) -> tuple[int, bytes]:
        try:
            async with asyncio.timeout(self.request_timeout_seconds):
                async with self._client.stream(method, path, json=body) as response:
                    collected = bytearray()
                    async for chunk in response.aiter_bytes():
                        collected.extend(chunk)
                        if len(collected) > limit:
                            raise AIResponseTooLarge("Ollama response exceeded the configured limit")
                    return response.status_code, bytes(collected)
        except AIResponseTooLarge:
            raise
        except httpx.ConnectTimeout as exc:
            raise AIProviderUnavailable("Ollama is unavailable") from exc
        except (TimeoutError, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout) as exc:
            raise AIProviderTimeout("Ollama request timed out") from exc
        except (httpx.ConnectError, httpx.NetworkError, httpx.RemoteProtocolError) as exc:
            raise AIProviderUnavailable("Ollama is unavailable") from exc
        except httpx.HTTPError as exc:
            raise AIProviderUnavailable("Ollama request failed") from exc

    @staticmethod
    def _json_object(payload: bytes) -> dict[str, Any]:
        try:
            value = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AIInvalidResponse("Ollama returned malformed JSON") from exc
        if not isinstance(value, dict):
            raise AIInvalidResponse("Ollama returned an invalid response envelope")
        return value

    @staticmethod
    def _model_matches(configured: str, candidate: str) -> bool:
        return candidate == configured or candidate == f"{configured}:latest" or configured == f"{candidate}:latest"

    async def health(self) -> ProviderHealth:
        try:
            status_code, payload = await self._bounded_request(
                "GET", "/api/tags", limit=1_048_576
            )
            if status_code != 200:
                return ProviderHealth(AIAvailability.UNAVAILABLE, "provider_http_error")
            envelope = self._json_object(payload)
            models = envelope.get("models")
            if not isinstance(models, list):
                return ProviderHealth(AIAvailability.UNAVAILABLE, "invalid_provider_response")
            for item in models:
                if not isinstance(item, dict):
                    continue
                names = [item.get("name"), item.get("model")]
                if any(isinstance(name, str) and self._model_matches(self.model, name) for name in names):
                    digest = item.get("digest")
                    return ProviderHealth(
                        AIAvailability.AVAILABLE,
                        model_digest=digest if isinstance(digest, str) and len(digest) <= 256 else None,
                    )
            return ProviderHealth(AIAvailability.UNAVAILABLE, "model_unavailable")
        except (AIProviderUnavailable, AIProviderTimeout):
            return ProviderHealth(AIAvailability.UNAVAILABLE, "provider_unavailable")
        except (AIInvalidResponse, AIResponseTooLarge):
            return ProviderHealth(AIAvailability.UNAVAILABLE, "invalid_provider_response")

    async def analyze(self, request: ProviderRequest) -> ProviderResult:
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": request.system_policy},
                {"role": "user", "content": request.task_payload},
            ],
            "stream": False,
            "format": AIAnalysisResult.model_json_schema(),
            "options": {"temperature": 0},
        }
        status_code, payload = await self._bounded_request(
            "POST", "/api/chat", body=body, limit=self.max_envelope_bytes
        )
        if status_code == 404:
            raise AIModelUnavailable("The configured Ollama model is unavailable")
        if status_code != 200:
            raise AIProviderUnavailable("Ollama generation failed")
        envelope = self._json_object(payload)
        message = envelope.get("message")
        if not isinstance(message, dict) or not isinstance(message.get("content"), str):
            raise AIInvalidResponse("Ollama response did not contain assistant content")
        content = message["content"]
        if len(content) > self.max_output_chars:
            raise AIResponseTooLarge("Ollama model output exceeded the configured limit")
        try:
            analysis = AIAnalysisResult.model_validate_json(content)
        except ValidationError as exc:
            raise AIInvalidResponse("Ollama model output failed schema validation") from exc
        except (UnicodeDecodeError, ValueError) as exc:
            raise AIInvalidResponse("Ollama model output was not valid JSON") from exc
        returned_model = envelope.get("model")
        model = returned_model if isinstance(returned_model, str) and len(returned_model) <= 256 else self.model
        return ProviderResult(analysis=analysis, model=model)
