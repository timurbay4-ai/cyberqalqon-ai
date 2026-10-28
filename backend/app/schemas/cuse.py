"""CUSE v1 metadata stored inside schema-17 structured evidence."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, field_validator, model_validator

from app.schemas.alerts import StrictModel


SourceFamily = Literal[
    "WINDOWS_EVENTCHANNEL", "SYSMON", "LINUX_AUTH", "SYSLOG", "JOURNALD", "WAZUH_GENERIC", "ZEEK", "SURICATA",
]
NormalizationStatus = Literal["NORMALIZED", "PARTIAL", "UNSUPPORTED_SOURCE"]
ProvenanceStatus = Literal["PARTIAL", "UNKNOWN", "UNPROVEN"]


class CUSEMetadata(StrictModel):
    version: Literal["cuse-v1"] = "cuse-v1"
    adapter_version: Literal["m28-v1", "m34-network-v1"] = "m28-v1"
    source_family: SourceFamily
    normalization_status: NormalizationStatus
    provenance_status: ProvenanceStatus
    historical_continuity: Literal["UNPROVEN"] = "UNPROVEN"
    transport_authenticated: bool = False
    endpoint_identity_verified: Literal[False] = False
    source_event_time: datetime | None = None
    collector_observation_time: datetime
    timestamp_basis: Literal["SOURCE_EVENT_TIME", "COLLECTOR_OBSERVATION_TIME"]
    original_event_identity: str | None = Field(default=None, max_length=255)
    source_identity_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    content_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    idempotency_contract: Literal["LEGACY_RAW_ENVELOPE_SHA256", "REGISTERED_SOURCE_RECORD_SHA256"] = "LEGACY_RAW_ENVELOPE_SHA256"
    delivery_identity: str | None = Field(default=None, max_length=128, pattern=r'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$')
    source_generation: str | None = Field(default=None, max_length=128, pattern=r'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$')
    warnings: list[Literal[
        "SOURCE_TIME_UNAVAILABLE", "SOURCE_CONTEXT_INCOMPLETE", "UNSUPPORTED_EVENT_CODE",
        "SOURCE_IDENTITY_CLAIMED", "YEARLESS_TIME_UNRESOLVED", "SOURCE_TIME_CONTEXT_INFERRED",
        "MULTIPLE_DNS_QUESTIONS",
    ]] = Field(default_factory=list, max_length=8)
    attributes: dict[str, str | int] = Field(default_factory=dict, max_length=32)

    @field_validator("source_event_time", "collector_observation_time")
    @classmethod
    def offset_aware_time(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("CUSE timestamps require a UTC offset")
        return value

    @model_validator(mode="after")
    def honest_timestamp_basis(self) -> "CUSEMetadata":
        if (self.source_event_time is not None) != (self.timestamp_basis == "SOURCE_EVENT_TIME"):
            raise ValueError("CUSE timestamp basis must match source time availability")
        registered = self.idempotency_contract == 'REGISTERED_SOURCE_RECORD_SHA256'
        if registered != (self.adapter_version == 'm34-network-v1'):
            raise ValueError('CUSE adapter and identity contract disagree')
        if registered:
            if self.source_family not in {'ZEEK', 'SURICATA'} or not self.delivery_identity or not self.source_generation:
                raise ValueError('Registered network provenance is incomplete')
        elif self.delivery_identity is not None or self.source_generation is not None or self.source_family in {'ZEEK', 'SURICATA'}:
            raise ValueError('Legacy CUSE cannot claim registered collection identity')
        return self
