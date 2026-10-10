"""Normalize bounded Wazuh archive records without inventing absent metadata."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from pydantic import ValidationError

from app.schemas.events import EventSourceType, NormalizedSecurityEvent
from app.services.wazuh_normalizer import canonical_json


SENSITIVE_KEY_FRAGMENTS = (
    "authorization",
    "api_key",
    "apikey",
    "cookie",
    "credential",
    "passwd",
    "password",
    "secret",
    "session",
    "token",
)
SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|token|secret|api[_-]?key|authorization|cookie)\s*([=:])\s*([^\s&;,]+)"
)


class EventNormalizationError(ValueError):
    def __init__(self, message: str, *, field: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.field = field


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _nested(value: Mapping[str, Any], path: str) -> Any:
    current: Any = value
    for part in path.split("."):
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
    return current


def _first(value: Mapping[str, Any], *paths: str) -> Any:
    for path in paths:
        candidate = _nested(value, path)
        if candidate not in (None, "", "-"):
            return candidate
    return None


def _text(value: Any, *, maximum: int, field: str) -> str | None:
    if value in (None, "", "-"):
        return None
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        raise EventNormalizationError("must be text", field=field)
    result = str(value).strip()
    if not result:
        return None
    return result[:maximum]


def _port(value: Any, field: str) -> int | None:
    if value in (None, "", "-", "0", 0):
        return None
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise EventNormalizationError("must be an integer port", field=field) from exc
    if not 1 <= result <= 65_535:
        raise EventNormalizationError("must be between 1 and 65535", field=field)
    return result


def _redact_string(value: str) -> str:
    return SENSITIVE_ASSIGNMENT.sub(lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", value)


def redact_sensitive_payload(value: Any, *, depth: int = 0) -> Any:
    if depth > 24:
        return "[MAX_DEPTH]"
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            normalized = key.casefold().replace("-", "_")
            if any(fragment in normalized for fragment in SENSITIVE_KEY_FRAGMENTS):
                result[key] = "[REDACTED]"
            else:
                result[key] = redact_sensitive_payload(item, depth=depth + 1)
        return result
    if isinstance(value, list):
        return [redact_sensitive_payload(item, depth=depth + 1) for item in value[:1000]]
    if isinstance(value, str):
        return _redact_string(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


def _source_type(raw: Mapping[str, Any]) -> EventSourceType:
    location = str(raw.get("location", "")).casefold()
    decoder = str(_first(raw, "decoder.name") or "").casefold()
    rule_id = str(_first(raw, "rule.id") or "")
    full_log = str(raw.get("full_log", ""))
    if _nested(raw, "data.win.system") is not None or decoder == "windows_eventchannel":
        return "windows_event"
    if "syscheck" in decoder or rule_id in {"100130", "100131"}:
        return "file_integrity"
    if "nginx" in location or rule_id in {"100101", "100120"}:
        return "web"
    if "CQ-NETSCAN" in full_log or rule_id in {"100110", "100111"}:
        return "network"
    if decoder in {"pam", "sshd"} or "authentication" in " ".join(
        str(item).casefold() for item in (_nested(raw, "rule.groups") or [])
    ):
        return "authentication"
    if raw.get("rule"):
        return "wazuh_alert"
    return "wazuh_archive"


def _message(raw: Mapping[str, Any], redacted: Mapping[str, Any]) -> str:
    candidate = _first(
        redacted,
        "rule.description",
        "data.win.system.message",
        "full_log",
        "predecoder.program_name",
    )
    if candidate is None:
        return "Wazuh archive event"
    result = str(candidate).strip()
    return (result or "Wazuh archive event")[:4096]


def normalize_wazuh_event(
    raw_event: dict[str, Any],
    *,
    ingestion_source: str = "wazuh_archives",
) -> NormalizedSecurityEvent:
    if not isinstance(raw_event, dict):
        raise EventNormalizationError("payload must be a JSON object")

    raw_json = canonical_json(raw_event)
    fingerprint = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()
    timestamp_raw = raw_event.get("timestamp")
    if not isinstance(timestamp_raw, str):
        raise EventNormalizationError("is required", field="timestamp")
    try:
        timestamp = datetime.fromisoformat(timestamp_raw)
    except ValueError as exc:
        raise EventNormalizationError("must be an ISO-8601 timestamp", field="timestamp") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise EventNormalizationError("must include a UTC offset", field="timestamp")

    redacted = redact_sensitive_payload(raw_event)
    if not isinstance(redacted, dict):
        raise EventNormalizationError("payload must be a JSON object")
    rule = _mapping(raw_event.get("rule"))
    groups = rule.get("groups") if isinstance(rule.get("groups"), list) else []
    event_category = _text(groups[0], maximum=255, field="rule.groups") if groups else None
    severity_raw = rule.get("level")
    severity: int | None = None
    if severity_raw not in (None, ""):
        try:
            severity = int(severity_raw)
        except (TypeError, ValueError) as exc:
            raise EventNormalizationError("must be an integer", field="rule.level") from exc

    structured_keys = ("agent", "data", "decoder", "location", "manager", "predecoder", "rule")
    structured = {key: redacted[key] for key in structured_keys if key in redacted}
    source_type = _source_type(raw_event)
    hostname = _first(raw_event, "data.win.system.computer", "agent.name")
    agent_id = _first(raw_event, "agent.id")
    agent_name = _first(raw_event, "agent.name")

    try:
        return NormalizedSecurityEvent(
            event_id=f"EVT-{fingerprint[:24].upper()}",
            deduplication_id=fingerprint,
            source_event_id=_text(raw_event.get("id"), maximum=255, field="id"),
            event_code=_text(
                _first(raw_event, "data.win.system.eventID", "data.event_id", "data.eventID"),
                maximum=128,
                field="event_code",
            ),
            timestamp=timestamp,
            source_type=source_type,
            hostname=_text(hostname, maximum=255, field="hostname"),
            agent_id=_text(agent_id, maximum=128, field="agent.id"),
            agent_name=_text(agent_name, maximum=255, field="agent.name"),
            source_ip=_first(
                raw_event,
                "data.srcip",
                "data.src_ip",
                "data.source.ip",
                "data.win.eventdata.ipAddress",
            ),
            destination_ip=_first(
                raw_event,
                "data.dstip",
                "data.dst_ip",
                "data.destination.ip",
            ),
            source_port=_port(
                _first(raw_event, "data.srcport", "data.src_port", "data.win.eventdata.ipPort"),
                "source_port",
            ),
            destination_port=_port(
                _first(raw_event, "data.dstport", "data.dst_port"),
                "destination_port",
            ),
            username=_text(
                _first(
                    raw_event,
                    "data.dstuser",
                    "data.srcuser",
                    "data.user",
                    "data.win.eventdata.targetUserName",
                    "data.win.eventdata.subjectUserName",
                ),
                maximum=512,
                field="username",
            ),
            event_category=event_category,
            event_action=_text(
                _first(raw_event, "data.action", "data.event_action"),
                maximum=255,
                field="event_action",
            ),
            outcome=_text(
                _first(raw_event, "data.outcome", "data.result"),
                maximum=128,
                field="outcome",
            ),
            rule_id=_text(rule.get("id"), maximum=128, field="rule.id"),
            severity=severity,
            message=_message(raw_event, redacted),
            ingestion_source=ingestion_source,
            structured_payload=structured,
            raw_payload=redacted,
            raw_size_bytes=len(raw_json.encode("utf-8")),
        )
    except ValidationError as exc:
        first = exc.errors(include_url=False)[0]
        field = ".".join(str(part) for part in first.get("loc", ())) or None
        raise EventNormalizationError(str(first.get("msg", "invalid event")), field=field) from exc


def encoded_event_size(raw_event: dict[str, Any]) -> int:
    return len(json.dumps(raw_event, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
