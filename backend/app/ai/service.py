"""Advisory analysis orchestration, capacity control, provenance, and staleness."""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from app.ai.context import AIContextBuilder, AIContextTooLarge, AITargetNotFound
from app.ai.policy import build_provider_request
from app.ai.provider import AIProvider, AIProviderUnavailable, ProviderHealth
from app.core.config import Settings
from app.db.ai import AIRepository
from app.schemas.ai import (
    AIAnalysisHistory,
    AIAnalysisRecord,
    AIAnalysisType,
    AIAvailability,
    AIRequester,
    AIStatusResponse,
    AITargetType,
)
from app.schemas.auth import AnalystPrincipal


LOGGER = logging.getLogger("cyberqalqon.ai")


def _safe_log_field(value: str) -> str:
    """Encode untrusted text as one ASCII JSON string for line-oriented logs."""

    return json.dumps(value, ensure_ascii=True)


class AIDisabled(RuntimeError):
    pass


class AIMisconfigured(RuntimeError):
    pass


class AIBusy(RuntimeError):
    pass


class AIRateLimited(RuntimeError):
    pass


class _CapacityGate:
    def __init__(self, maximum: int) -> None:
        self.maximum = maximum
        self._active = 0
        self._lock = asyncio.Lock()

    @asynccontextmanager
    async def slot(self):
        async with self._lock:
            if self._active >= self.maximum:
                raise AIBusy("Local AI inference capacity is busy")
            self._active += 1
        try:
            yield
        finally:
            async with self._lock:
                self._active -= 1


class AIService:
    def __init__(
        self,
        *,
        settings: Settings,
        repository: AIRepository,
        provider: AIProvider | None,
    ) -> None:
        self.settings = settings
        self.repository = repository
        self.provider = provider
        self.contexts = AIContextBuilder(repository, settings)
        self._capacity = _CapacityGate(settings.ai_max_concurrent_requests)
        self._cooldown_lock = asyncio.Lock()
        self._last_request: dict[str, float] = {}
        self._health_lock = asyncio.Lock()
        self._health_cached: tuple[float, ProviderHealth] | None = None

    async def close(self) -> None:
        if self.provider is not None:
            await self.provider.close()

    async def status(self) -> AIStatusResponse:
        now = datetime.now(timezone.utc)
        if not self.settings.ai_enabled:
            return AIStatusResponse(
                state=AIAvailability.DISABLED,
                provider="ollama",
                diagnostic="ai_disabled",
                checked_at=now,
            )
        if self.settings.ai_configuration_error:
            return AIStatusResponse(
                state=AIAvailability.MISCONFIGURED,
                provider="ollama",
                model=self.settings.ollama_model or None,
                diagnostic="invalid_configuration",
                checked_at=now,
            )
        if self.provider is None:
            return AIStatusResponse(
                state=AIAvailability.UNAVAILABLE,
                provider="ollama",
                model=self.settings.ollama_model,
                diagnostic="provider_unavailable",
                checked_at=now,
            )
        monotonic_now = time.monotonic()
        async with self._health_lock:
            if self._health_cached and monotonic_now - self._health_cached[0] < self.settings.ai_health_cache_seconds:
                health = self._health_cached[1]
            else:
                health = await self.provider.health()
                self._health_cached = (time.monotonic(), health)
        return AIStatusResponse(
            state=health.state,
            provider="ollama",
            model=self.settings.ollama_model,
            diagnostic=health.diagnostic,
            checked_at=now,
        )

    async def _enforce_cooldown(self, analyst_id: str) -> None:
        if self.settings.ai_user_cooldown_seconds == 0:
            return
        now = time.monotonic()
        async with self._cooldown_lock:
            previous = self._last_request.get(analyst_id)
            if previous is not None and now - previous < self.settings.ai_user_cooldown_seconds:
                raise AIRateLimited("Wait briefly before requesting another analysis")
            self._last_request[analyst_id] = now

    def _require_provider(self) -> AIProvider:
        if not self.settings.ai_enabled:
            raise AIDisabled("AI analysis is disabled")
        if self.settings.ai_configuration_error:
            raise AIMisconfigured("AI analysis is misconfigured")
        if self.provider is None:
            raise AIProviderUnavailable("Ollama is unavailable")
        return self.provider

    async def analyze(
        self,
        *,
        target_type: AITargetType,
        target_id: str,
        question: str | None,
        principal: AnalystPrincipal,
    ) -> AIAnalysisRecord:
        provider = self._require_provider()
        context = self.contexts.build(target_type, target_id)
        analysis_type = (
            AIAnalysisType.ANALYST_QUESTION
            if question is not None
            else AIAnalysisType.ALERT_SUMMARY
            if target_type is AITargetType.ALERT
            else AIAnalysisType.INCIDENT_SUMMARY
        )
        request = build_provider_request(context, analysis_type, question)
        await self._enforce_cooldown(principal.analyst_id)
        requested_at = datetime.now(timezone.utc)
        started = time.monotonic()
        analysis_id = f"AIA-{uuid.uuid4().hex.upper()}"
        outcome = "failure"
        failure_category = "none"
        try:
            async with self._capacity.slot():
                generated = await provider.analyze(request)
            completed_at = datetime.now(timezone.utc)
            record = AIAnalysisRecord(
                analysis_id=analysis_id,
                analysis_type=analysis_type,
                target_type=target_type,
                target_id=target_id,
                requested_by=AIRequester(
                    analyst_id=principal.analyst_id,
                    display=principal.audit_display,
                ),
                requested_at=requested_at,
                completed_at=completed_at,
                provider="ollama",
                model=generated.model,
                model_digest=generated.model_digest,
                context_fingerprint=context.fingerprint,
                context=context.metadata,
                stale=False,
                result=generated.analysis,
            )
            self.repository.insert(record, target_updated_at=context.target_updated_at)
            outcome = "success"
            return record
        except Exception as exc:
            failure_category = getattr(exc, "code", None) or (
                "ai_busy" if isinstance(exc, AIBusy) else "internal_error"
            )
            raise
        finally:
            LOGGER.info(
                "ai_analysis analysis_id=%s target_type=%s target_id=%s analyst_id=%s provider=ollama model=%s duration_ms=%d outcome=%s failure_category=%s context_bytes=%d context_truncated=%s",
                analysis_id,
                target_type.value,
                _safe_log_field(target_id),
                principal.analyst_id,
                _safe_log_field(self.settings.ollama_model),
                int((time.monotonic() - started) * 1000),
                outcome,
                failure_category,
                context.metadata.context_bytes,
                context.metadata.truncated,
            )

    def _current_fingerprint(self, target_type: AITargetType, target_id: str) -> str | None:
        try:
            return self.contexts.build(target_type, target_id).fingerprint
        except (AITargetNotFound, AIContextTooLarge):
            return None

    def get(self, analysis_id: str) -> AIAnalysisRecord | None:
        record = self.repository.get(analysis_id)
        if record is None:
            return None
        current = self._current_fingerprint(record.target_type, record.target_id)
        return record.model_copy(update={"stale": current != record.context_fingerprint})

    def history(
        self,
        target_type: AITargetType,
        target_id: str,
        *,
        limit: int,
    ) -> AIAnalysisHistory:
        current = self.contexts.build(target_type, target_id).fingerprint
        records = self.repository.list_for_target(target_type.value, target_id, limit=limit)
        return AIAnalysisHistory(
            items=[
                record.model_copy(update={"stale": record.context_fingerprint != current})
                for record in records
            ],
            limit=limit,
        )
