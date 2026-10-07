"""Provider-neutral contracts and safe failure categories."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from app.schemas.ai import AIAnalysisResult, AIAvailability


class AIProviderError(RuntimeError):
    code = "ai_unavailable"


class AIProviderUnavailable(AIProviderError):
    code = "ai_unavailable"


class AIProviderTimeout(AIProviderError):
    code = "ai_timeout"


class AIModelUnavailable(AIProviderError):
    code = "ai_model_unavailable"


class AIInvalidResponse(AIProviderError):
    code = "ai_invalid_response"


class AIResponseTooLarge(AIProviderError):
    code = "ai_response_too_large"


@dataclass(frozen=True, slots=True)
class ProviderHealth:
    state: AIAvailability
    diagnostic: str | None = None
    model_digest: str | None = None


@dataclass(frozen=True, slots=True)
class ProviderRequest:
    system_policy: str
    task_payload: str


@dataclass(frozen=True, slots=True)
class ProviderResult:
    analysis: AIAnalysisResult
    model: str
    model_digest: str | None = None


class AIProvider(Protocol):
    async def health(self) -> ProviderHealth: ...

    async def analyze(self, request: ProviderRequest) -> ProviderResult: ...

    async def close(self) -> None: ...
