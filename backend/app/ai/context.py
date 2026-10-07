"""Deterministic, allowlisted, size-bounded SOC context construction."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from app.core.config import Settings
from app.db.ai import AIRepository
from app.schemas.ai import AIContextMetadata, AITargetType
from app.services.wazuh_normalizer import canonical_json


class AITargetNotFound(LookupError):
    pass


class AIContextTooLarge(ValueError):
    pass


SENSITIVE_KEY_FRAGMENTS = (
    "api_key", "apikey", "authorization", "cookie", "csrf", "password",
    "secret", "session", "token", "credential",
)
RAW_EVENT_ALLOWLIST = ("full_log", "data", "predecoder", "decoder", "syscheck", "audit", "win")


@dataclass(frozen=True, slots=True)
class BuiltContext:
    target_type: AITargetType
    target_id: str
    evidence: dict[str, Any]
    serialized: str
    fingerprint: str
    metadata: AIContextMetadata
    target_updated_at: str | None


def _alert_fields(alert: dict[str, Any]) -> dict[str, Any]:
    return {
        "alert_id": alert.get("alert_id"),
        "timestamp": alert.get("timestamp"),
        "agent": alert.get("agent"),
        "rule": alert.get("rule"),
        "mitre": alert.get("mitre"),
        "source": alert.get("source"),
        "destination": alert.get("destination"),
        "user": alert.get("user"),
        "location": alert.get("location"),
        "decoder_name": alert.get("decoder_name"),
    }


class AIContextBuilder:
    def __init__(self, repository: AIRepository, settings: Settings) -> None:
        self.repository = repository
        self.settings = settings

    def _sanitize(self, value: Any, reasons: set[str], *, depth: int = 0) -> Any:
        if depth >= 8:
            reasons.add("nested_data_omitted")
            return "[nested data omitted]"
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            machine_key = self.settings.wazuh_ingest_api_key
            if machine_key and machine_key in value:
                value = value.replace(machine_key, "[REDACTED]")
                reasons.add("configured_secret_redacted")
            if len(value) > self.settings.ai_max_field_chars:
                reasons.add("field_text_truncated")
                return value[: self.settings.ai_max_field_chars] + "…[truncated]"
            return value
        if isinstance(value, list):
            if len(value) > 50:
                reasons.add("nested_list_truncated")
            return [self._sanitize(item, reasons, depth=depth + 1) for item in value[:50]]
        if isinstance(value, dict):
            sanitized: dict[str, Any] = {}
            for raw_key in sorted(value, key=lambda item: str(item)):
                key = str(raw_key)[:256]
                lowered = key.lower().replace("-", "_")
                if any(fragment in lowered for fragment in SENSITIVE_KEY_FRAGMENTS):
                    reasons.add("sensitive_named_field_excluded")
                    continue
                sanitized[key] = self._sanitize(value[raw_key], reasons, depth=depth + 1)
            return sanitized
        reasons.add("unsupported_value_omitted")
        return str(value)[: self.settings.ai_max_field_chars]

    def _finish(
        self,
        *,
        target_type: AITargetType,
        target_id: str,
        evidence: dict[str, Any],
        reasons: set[str],
        alerts_included: int,
        alerts_available: int,
        notes_included: int,
        notes_available: int,
        history_included: int,
        history_available: int,
        raw_event_included: bool,
        target_updated_at: str | None,
    ) -> BuiltContext:
        serialized = canonical_json(evidence)
        byte_count = len(serialized.encode("utf-8"))
        if byte_count > self.settings.ai_max_context_bytes:
            raise AIContextTooLarge("Selected AI context cannot fit the configured byte limit")
        fingerprint = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        metadata = AIContextMetadata(
            context_bytes=byte_count,
            truncated=bool(reasons),
            alerts_included=alerts_included,
            alerts_available=alerts_available,
            notes_included=notes_included,
            notes_available=notes_available,
            history_included=history_included,
            history_available=history_available,
            raw_event_included=raw_event_included,
            truncation_reasons=sorted(reasons),
        )
        return BuiltContext(
            target_type=target_type,
            target_id=target_id,
            evidence=evidence,
            serialized=serialized,
            fingerprint=fingerprint,
            metadata=metadata,
            target_updated_at=target_updated_at,
        )

    def alert(self, alert_id: str) -> BuiltContext:
        material = self.repository.alert_material(alert_id)
        if material is None:
            raise AITargetNotFound(alert_id)
        reasons: set[str] = set()
        selected_raw = {
            key: material["raw_event"][key]
            for key in RAW_EVENT_ALLOWLIST
            if key in material["raw_event"]
        }
        sanitized_raw = self._sanitize(selected_raw, reasons)
        if sanitized_raw:
            raw_serialized = canonical_json(sanitized_raw)
            if len(raw_serialized) > self.settings.ai_max_raw_event_chars:
                sanitized_raw = {
                    "serialized_excerpt": raw_serialized[: self.settings.ai_max_raw_event_chars]
                    + "…[truncated]"
                }
                reasons.add("raw_event_truncated")
        normalized = self._sanitize(_alert_fields(material["normalized"]), reasons)
        evidence: dict[str, Any] = {
            "target_type": "alert",
            "alert": normalized,
            "selected_raw_event": sanitized_raw,
        }
        if len(canonical_json(evidence).encode("utf-8")) > self.settings.ai_max_context_bytes:
            evidence["selected_raw_event"] = {}
            sanitized_raw = {}
            reasons.add("raw_event_omitted_for_context_budget")
        return self._finish(
            target_type=AITargetType.ALERT,
            target_id=alert_id,
            evidence=evidence,
            reasons=reasons,
            alerts_included=1,
            alerts_available=1,
            notes_included=0,
            notes_available=0,
            history_included=0,
            history_available=0,
            raw_event_included=bool(sanitized_raw),
            target_updated_at=material["target_updated_at"],
        )

    def incident(self, incident_id: str) -> BuiltContext:
        material = self.repository.incident_material(
            incident_id,
            alert_limit=self.settings.ai_max_alerts_per_request,
            note_limit=self.settings.ai_max_notes_per_request,
            history_limit=self.settings.ai_max_history_per_request,
        )
        if material is None:
            raise AITargetNotFound(incident_id)
        reasons: set[str] = set()
        counts = material["counts"]
        if counts["alerts"] > len(material["alerts"]):
            reasons.add("linked_alert_limit")
        if counts["notes"] > len(material["notes"]):
            reasons.add("note_limit")
        if counts["history"] > len(material["history"]):
            reasons.add("history_limit")
        incident = material["incident"]
        evidence: dict[str, Any] = {
            "target_type": "incident",
            "incident": self._sanitize(
                {
                    "incident_id": incident["incident_id"],
                    "title": incident["title"],
                    "description": incident["description"],
                    "severity": incident["severity"],
                    "status": incident["status"],
                    "assigned_to": incident["assigned_to"],
                    "created_at": incident["created_at"],
                    "updated_at": incident["updated_at"],
                },
                reasons,
            ),
            "linked_alerts": self._sanitize(
                [_alert_fields(alert) for alert in material["alerts"]], reasons
            ),
            "analyst_notes": self._sanitize(
                [
                    {
                        "note_id": note["note_id"],
                        "body": note["body"],
                        "author": note["author"],
                        "author_id": note["author_id"],
                        "created_at": note["created_at"],
                    }
                    for note in material["notes"]
                ],
                reasons,
            ),
            "audit_history": self._sanitize(material["history"], reasons),
        }
        for section, reason in (
            ("audit_history", "history_omitted_for_context_budget"),
            ("analyst_notes", "notes_omitted_for_context_budget"),
            ("linked_alerts", "alerts_omitted_for_context_budget"),
        ):
            while evidence[section] and len(canonical_json(evidence).encode("utf-8")) > self.settings.ai_max_context_bytes:
                evidence[section].pop()
                reasons.add(reason)
        return self._finish(
            target_type=AITargetType.INCIDENT,
            target_id=incident_id,
            evidence=evidence,
            reasons=reasons,
            alerts_included=len(evidence["linked_alerts"]),
            alerts_available=counts["alerts"],
            notes_included=len(evidence["analyst_notes"]),
            notes_available=counts["notes"],
            history_included=len(evidence["audit_history"]),
            history_available=counts["history"],
            raw_event_included=False,
            target_updated_at=material["target_updated_at"],
        )

    def build(self, target_type: AITargetType, target_id: str) -> BuiltContext:
        return self.alert(target_id) if target_type is AITargetType.ALERT else self.incident(target_id)
