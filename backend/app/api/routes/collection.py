"""Closed-by-default registered collection, existing machine and analyst auth."""
from __future__ import annotations

import hashlib
import hmac
import sqlite3
import time
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from app.api.dependencies.auth import require_soc_reader
from app.api.routes.alerts import _read_json_object, require_ingest_key
from app.db.events import EventIdConflictError, EventOutsideRetentionError, RetentionCapacityError
from app.schemas.collection import CollectionAcknowledgement, CollectionEnvelope
from app.services.event_normalizer import EventNormalizationError
from app.services.network_telemetry import normalize_network
from app.services.continuous_shadow import ContinuousShadowError
from app.db.shadow_history import ShadowStoreError

router = APIRouter(prefix='/api/v1/collection', tags=['Source collection'])


def error(status: int, code: str):
    return HTTPException(status, detail={'code': code, 'message': code},
                         headers={'Retry-After': '2'} if status == 503 else None)


@router.post('/events', response_model=CollectionAcknowledgement, status_code=201)
async def ingest(request: Request, response: Response, _: Annotated[None, Depends(require_ingest_key)]):
    registry = request.app.state.collection_registry
    if not registry.bindings:
        raise error(503, 'collection_gate_closed')
    began = time.monotonic()
    try:
        payload = await _read_json_object(request, request.app.state.settings.max_event_ingest_bytes)
    except (ValueError, UnicodeError, RecursionError):
        raise error(422, 'invalid_collection_encoding') from None
    try:
        envelope = CollectionEnvelope.model_validate(payload)
    except (ValidationError, ValueError, RecursionError):
        raise error(422, 'invalid_collection_envelope') from None
    binding = registry.bindings.get(envelope.source_id)
    key = request.headers.get('X-Source-Key', '')
    # No key or digest is logged/returned. This key scopes the existing machine key.
    candidate = hashlib.sha256(key.encode()).hexdigest() if 32 <= len(key) <= 512 else ''
    if binding is None or not hmac.compare_digest(candidate, binding.source_key_sha256):
        raise error(401, 'invalid_collection_source')
    metrics = request.app.state.ingestion_metrics
    try:
        normalized = normalize_network(envelope, binding)
        database_started = time.monotonic()
        stored = await run_in_threadpool(request.app.state.event_repository.ingest, normalized)
        database_ms = (time.monotonic() - database_started) * 1000
    except EventNormalizationError as exc:
        registry.record(binding.source_id, 'rejected')
        metrics.record_normalization(exc.code)
        raise error(422, exc.code) from None
    except EventIdConflictError:
        registry.record(binding.source_id, 'conflict')
        raise error(409, 'source_record_conflict') from None
    except EventOutsideRetentionError:
        registry.record(binding.source_id, 'rejected')
        raise error(422, 'outside_retention_window') from None
    except (RetentionCapacityError, sqlite3.Error):
        registry.record(binding.source_id, 'retryable_failure')
        raise error(503, 'collection_storage_unavailable') from None
    registry.record(binding.source_id, 'duplicate' if stored.duplicate else 'inserted')
    metrics.record_normalization('NORMALIZED', normalized.structured_payload['_cuse']['source_family'])
    metrics.record_success(mode='single', events=1, inserted=int(not stored.duplicate), duplicates=int(stored.duplicate),
                           request_ms=(time.monotonic()-began)*1000, database_ms=database_ms)
    response.status_code = 200 if stored.duplicate else 201
    return CollectionAcknowledgement(
        duplicate=stored.duplicate, event_id=stored.event.event_id,
        source_event_id=envelope.source_event_id, delivery_identity=envelope.delivery_identity,
        checkpoint_identity=envelope.checkpoint_identity, integrity_fingerprint=envelope.integrity_fingerprint)


@router.get('/sources', dependencies=[Depends(require_soc_reader)])
async def sources(request: Request):
    try:
        result = await run_in_threadpool(request.app.state.collection_registry.coverage, request.app.state.event_repository)
        workers = getattr(request.app.state, 'continuous_shadow_workers', ())
        result['detection_workers'] = [await run_in_threadpool(worker.status) for worker in workers[:8]]
        result['continuous_worker_state'] = 'OBSERVED_ISOLATED_WORKERS' if workers else 'UNKNOWN_NOT_ACTIVATED'
        return result
    except (sqlite3.Error, ValueError, KeyError, ContinuousShadowError, ShadowStoreError):
        raise error(503, 'source_coverage_unavailable') from None
