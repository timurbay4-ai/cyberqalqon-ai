"""Executable collection ACK reference; no file reader, spool, HTTP or activation.

A verified ACK permits the future collector's durable checkpoint transition. This
module alone persists nothing and cannot attest collector delivery or exactly-once.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.schemas.collection import CollectionEnvelope, CollectionAcknowledgement
from app.services.network_telemetry import digest


@dataclass(frozen=True, slots=True)
class DeliveryDecision:
    state: Literal['ACKNOWLEDGED','UNKNOWN_ACK','RETRYABLE_FAILURE','PERMANENT_REJECTION','BLOCKED']
    reason: str
    may_advance: bool = False
    retry: bool = False
    retry_after_seconds: int | None = None
    inserted: bool | None = None


def classify_response(envelope: CollectionEnvelope, status: int | None, body=None, *, retry_after=None):
    """No raw error/body/header values are included in diagnostics."""
    if status is None:
        return DeliveryDecision('UNKNOWN_ACK','RESPONSE_NOT_VERIFIED',retry=True,retry_after_seconds=2)
    if type(status) is not int:
        return DeliveryDecision('BLOCKED','INVALID_TRANSPORT_STATUS')
    if status in (429,503) or type(status) is int and 500 <= status <= 599:
        delay = int(retry_after) if isinstance(retry_after,str) and retry_after.isascii() and retry_after.isdigit() and len(retry_after)<=2 else 2
        return DeliveryDecision('RETRYABLE_FAILURE','BOUNDED_BACKOFF',retry=True,retry_after_seconds=max(1,min(delay,60)))
    if status in (400,413,415,422):
        return DeliveryDecision('PERMANENT_REJECTION','OPERATOR_DISPOSITION_REQUIRED')
    if status in (401,403):
        return DeliveryDecision('BLOCKED','AUTHENTICATION_REQUIRED')
    if status == 409:
        return DeliveryDecision('BLOCKED','SOURCE_RECORD_CONFLICT')
    if status not in (200,201):
        return DeliveryDecision('BLOCKED','UNEXPECTED_STATUS_NO_REDIRECT')
    try:
        if (not isinstance(body,dict) or len(body)!=8 or type(body.get('duplicate')) is not bool
                or body.get('committed') is not True
                or any(type(value) is not str or len(value)>128 for key,value in body.items()
                       if key not in {'committed','duplicate'})):
            raise ValueError('ACK shape')
        ack=CollectionAcknowledgement.model_validate(body)
        expected='EVT-'+digest(['cq-source-record-v1',envelope.source_id,envelope.collector_id,
                               envelope.source_generation,envelope.source_event_id])[:24].upper()
        if (ack.contract!='cq-collection-ack-v1' or ack.event_id!=expected
                or ack.source_event_id!=envelope.source_event_id or ack.delivery_identity!=envelope.delivery_identity
                or ack.checkpoint_identity!=envelope.checkpoint_identity or ack.integrity_fingerprint!=envelope.integrity_fingerprint
                or ack.duplicate!=(status==200)):
            raise ValueError('ACK binding')
    except (ValueError,TypeError):
        return DeliveryDecision('BLOCKED','INVALID_ACK_BINDING')
    return DeliveryDecision('ACKNOWLEDGED','VERIFIED_DUPLICATE' if ack.duplicate else 'VERIFIED_NEW_INSERT',
                            may_advance=True,inserted=not ack.duplicate)
