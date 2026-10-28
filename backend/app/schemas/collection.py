"""Versioned single-record collector boundary; no activation/configuration API."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import Field, field_validator

from app.schemas.alerts import StrictModel

IDENTIFIER = r'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
NetworkSource = Literal['ZEEK_JSON', 'SURICATA_EVE']


class CollectionEnvelope(StrictModel):
    contract: Literal['cq-collection-v1']
    source_id: str = Field(pattern=IDENTIFIER)
    source_type: NetworkSource
    collector_id: str = Field(pattern=IDENTIFIER)
    collector_version: str = Field(min_length=1, max_length=32, pattern=r'^[A-Za-z0-9_.-]+$')
    source_generation: str = Field(pattern=IDENTIFIER)
    source_event_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER)
    delivery_identity: str = Field(pattern=IDENTIFIER)
    checkpoint_identity: str = Field(pattern=IDENTIFIER)
    stream: Literal['conn', 'dns', 'http', 'ssl', 'alert', 'tls', 'flow']
    event_timestamp: datetime
    observed_timestamp: datetime
    payload_encoding: Literal['json'] = 'json'
    integrity_fingerprint: str = Field(pattern=r'^[a-f0-9]{64}$')
    normalization_version: Literal['cuse-v1'] = 'cuse-v1'
    payload: dict[str, Any]

    @field_validator('event_timestamp', 'observed_timestamp')
    @classmethod
    def aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError('UTC offset required')
        return value.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class SourceBinding:
    """Trusted server constructor input, never derived from event sensor labels."""

    source_id: str
    source_type: NetworkSource
    collector_id: str
    source_generation: str
    sensor_name: str
    source_key_sha256: str = field(repr=False)

    def __post_init__(self):
        import re
        for value in (self.source_id, self.collector_id, self.source_generation):
            if not isinstance(value, str) or re.fullmatch(IDENTIFIER, value) is None:
                raise ValueError('Invalid registered source identity')
        if self.source_type not in {'ZEEK_JSON', 'SURICATA_EVE'}:
            raise ValueError('Unsupported registered source')
        if not self.sensor_name or len(self.sensor_name) > 255 or any(ord(c) < 32 for c in self.sensor_name):
            raise ValueError('Invalid sensor name')
        if re.fullmatch(r'[a-f0-9]{64}', self.source_key_sha256) is None:
            raise ValueError('A source-specific key digest is required')


class CollectionAcknowledgement(StrictModel):
    contract: Literal['cq-collection-ack-v1'] = 'cq-collection-ack-v1'
    committed: Literal[True] = True
    duplicate: bool
    event_id: str
    source_event_id: str
    delivery_identity: str
    checkpoint_identity: str
    integrity_fingerprint: str
