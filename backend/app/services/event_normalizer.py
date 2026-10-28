"""Normalize bounded Wazuh archive records without inventing absent metadata."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from pydantic import ValidationError

from app.schemas.alerts import MitreContext
from app.schemas.events import EventSourceType, NormalizedSecurityEvent
from app.services.wazuh_normalizer import MITRE_ID_PATTERN, canonical_json


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
    r"(?i)\b(password|passwd|token|secret|api[_-]?key|authorization|cookie)\s*([=:])\s*"
    r"(\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s&;,]+)"
)
BEARER_CREDENTIAL = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+={0,2}")


class EventNormalizationError(ValueError):
    def __init__(self, message: str, *, field: str | None = None, code: str = "MALFORMED") -> None:
        super().__init__(message)
        self.message = message
        self.field = field
        self.code = code


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
    value = BEARER_CREDENTIAL.sub("Bearer [REDACTED]", value)
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


def _windows_category(raw: Mapping[str, Any]) -> str | None:
    channel = str(_first(raw, "data.win.system.channel") or "").casefold()
    provider = str(_first(raw, "data.win.system.providerName") or "").casefold()
    if not channel and not provider:
        return None
    if "powershell" in channel or "powershell" in provider:
        return "windows_powershell"
    if "defender" in channel or "defender" in provider:
        return "windows_defender"
    if "sysmon" in channel or "sysmon" in provider:
        return "windows_sysmon"
    if channel == "security":
        return "windows_security"
    if channel == "system":
        return "windows_system"
    return "windows_event"


def _linux_category(raw: Mapping[str, Any]) -> str | None:
    decoder = str(_first(raw, "decoder.name") or "").casefold()
    location = str(raw.get("location", "")).casefold()
    groups = {
        str(item).casefold()
        for item in (_nested(raw, "rule.groups") or [])
        if isinstance(item, (str, int)) and not isinstance(item, bool)
    }
    evidence = " ".join((decoder, location, " ".join(sorted(groups)), str(raw.get("full_log", "")).casefold()))
    if decoder == "sshd" or "sshd" in groups:
        return "linux_ssh"
    if decoder == "pam" or "pam" in groups:
        return "linux_pam"
    if "sudo" in evidence:
        return "linux_sudo"
    if "auditd" in evidence or decoder == "auditd":
        return "linux_audit"
    if any(marker in evidence for marker in ("useradd", "userdel", "groupadd", "groupdel", "usermod")):
        return "linux_account_management"
    if any(marker in evidence for marker in ("cron", "crond", "systemd-timer")):
        return "linux_scheduled_task"
    if any(marker in evidence for marker in ("systemd", "service")):
        return "linux_service"
    return None


def _operating_system(raw: Mapping[str, Any], source_type: EventSourceType) -> str | None:
    explicit = _first(
        raw,
        "agent.os.name",
        "agent.os.platform",
        "data.os.name",
        "data.host.os.name",
    )
    if explicit not in (None, "", "-"):
        return _text(explicit, maximum=255, field="operating_system")
    if source_type == "windows_event":
        return "windows"
    if _linux_category(raw) is not None:
        return "linux"
    return None


def _text_list(value: Any, *, field: str, maximum_items: int = 32) -> list[str]:
    if value in (None, "", "-"):
        return []
    items = value if isinstance(value, list) else [value]
    result: list[str] = []
    for item in items[:maximum_items]:
        text = _text(item, maximum=255, field=field)
        if text and text not in result:
            result.append(text)
    return result


def _mitre_context(raw: Mapping[str, Any]) -> MitreContext:
    mitre = _mapping(_first(raw, "rule.mitre", "mitre"))
    ids = _text_list(mitre.get("id", mitre.get("ids")), field="rule.mitre.id")
    invalid = next((item for item in ids if not MITRE_ID_PATTERN.fullmatch(item)), None)
    if invalid is not None:
        raise EventNormalizationError(
            "contains invalid MITRE ATT&CK technique ID",
            field="rule.mitre.id",
        )
    return MitreContext(
        ids=ids,
        tactics=_text_list(mitre.get("tactic", mitre.get("tactics")), field="rule.mitre.tactic"),
        techniques=_text_list(
            mitre.get("technique", mitre.get("techniques")),
            field="rule.mitre.technique",
        ),
    )


WINDOWS_EVENT_SEMANTICS: dict[str, tuple[str, str]] = {
    "4624": ("logon", "success"),
    "4625": ("logon", "failure"),
    "4634": ("logoff", "success"),
    "4648": ("explicit_credentials", "observed"),
    "4672": ("privileged_logon", "success"),
    "4688": ("process_start", "success"),
    "4720": ("account_create", "success"),
    "4726": ("account_delete", "success"),
    "4732": ("group_member_add", "success"),
    "7045": ("service_install", "success"),
    "4103": ("powershell_module", "observed"),
    "4104": ("powershell_script_block", "observed"),
    "1116": ("malware_detect", "detected"),
    "1117": ("malware_remediate", "remediated"),
    "1118": ("malware_remediate", "failure"),
    "1119": ("malware_remediate", "failure"),
    "5000": ("endpoint_protection_enable", "success"),
    "5001": ("endpoint_protection_disable", "observed"),
    "5004": ("endpoint_protection_change", "observed"),
    "5007": ("endpoint_protection_change", "observed"),
}


def _event_semantics(raw: Mapping[str, Any], source_type: EventSourceType) -> tuple[str | None, str | None]:
    explicit_action = _text(
        _first(raw, "data.action", "data.event_action"),
        maximum=255,
        field="event_action",
    )
    explicit_outcome = _text(
        _first(raw, "data.outcome", "data.result"),
        maximum=128,
        field="outcome",
    )
    if explicit_action is not None or explicit_outcome is not None:
        return explicit_action, explicit_outcome
    if source_type == "windows_event":
        code = str(_first(raw, "data.win.system.eventID", "data.win.system.eventId") or "")
        return WINDOWS_EVENT_SEMANTICS.get(code, (None, None))

    category = _linux_category(raw)
    groups = " ".join(
        str(item).casefold() for item in (_nested(raw, "rule.groups") or [])
    )
    full_log = str(raw.get("full_log", "")).casefold()
    failure = any(marker in groups or marker in full_log for marker in (
        "authentication_failed", "authentication failure", "failed password", "not in the sudoers", "incorrect password",
    ))
    success = any(marker in groups or marker in full_log for marker in (
        "authentication_success", "accepted password", "accepted publickey", "session opened", "command=",
    ))
    if category in {"linux_ssh", "linux_pam"}:
        return "authenticate", "failure" if failure else "success" if success else "observed"
    if category == "linux_sudo":
        return "privilege_escalation", "failure" if failure else "success" if success else "observed"
    if category == "linux_account_management":
        return "account_or_group_change", "success" if not failure else "failure"
    if category == "linux_scheduled_task":
        return "scheduled_task_change", "observed"
    if category == "linux_service":
        return "service_change", "observed"
    if category == "linux_audit":
        return "audit_event", "observed"
    return None, None


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


def _normalize_legacy_wazuh_event(
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
    if source_type == "windows_event":
        event_category = _windows_category(raw_event) or event_category
    else:
        event_category = _linux_category(raw_event) or event_category
    hostname = _first(raw_event, "data.win.system.computer", "agent.name")
    agent_id = _first(raw_event, "agent.id")
    agent_name = _first(raw_event, "agent.name")
    event_action, outcome = _event_semantics(raw_event, source_type)

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
            operating_system=_operating_system(raw_event, source_type),
            manager_identity=_text(
                _first(raw_event, "manager.name"), maximum=255, field="manager.name"
            ),
            event_provider=_text(
                _first(raw_event, "data.win.system.providerName"),
                maximum=255,
                field="event_provider",
            ),
            event_channel=_text(
                _first(raw_event, "data.win.system.channel"),
                maximum=255,
                field="event_channel",
            ),
            process_name=_text(
                _first(
                    raw_event,
                    "data.win.eventdata.image",
                    "data.win.eventdata.newProcessName",
                    "data.win.eventdata.processName",
                    "data.process.name",
                ),
                maximum=1024,
                field="process_name",
            ),
            process_path=_text(
                _first(
                    raw_event,
                    "data.win.eventdata.image",
                    "data.win.eventdata.newProcessName",
                    "data.win.eventdata.processName",
                    "data.process.executable",
                    "data.process.path",
                ),
                maximum=2048,
                field="process_path",
            ),
            command_line=_text(
                _first(
                    redacted,
                    "data.win.eventdata.commandLine",
                    "data.win.eventdata.processCommandLine",
                    "data.win.eventdata.imagePath",
                    "data.process.command_line",
                    "data.command",
                ),
                maximum=8192,
                field="command_line",
            ),
            process_id=_text(
                _first(
                    raw_event,
                    "data.win.eventdata.processId",
                    "data.win.eventdata.newProcessId",
                    "data.process.id",
                ),
                maximum=128,
                field="process_id",
            ),
            parent_process_name=_text(
                _first(
                    raw_event,
                    "data.win.eventdata.parentImage",
                    "data.win.eventdata.parentProcessName",
                    "data.win.eventdata.creatorProcessName",
                ),
                maximum=1024,
                field="parent_process_name",
            ),
            parent_process_path=_text(
                _first(
                    raw_event,
                    "data.win.eventdata.parentImage",
                    "data.win.eventdata.parentProcessName",
                    "data.win.eventdata.creatorProcessName",
                    "data.process.parent.executable",
                ),
                maximum=2048,
                field="parent_process_path",
            ),
            parent_process_id=_text(
                _first(
                    raw_event,
                    "data.win.eventdata.parentProcessId",
                    "data.win.eventdata.creatorProcessId",
                ),
                maximum=128,
                field="parent_process_id",
            ),
            source_ip=_first(
                raw_event,
                "data.srcip",
                "data.src_ip",
                "data.source.ip",
                "data.win.eventdata.ipAddress",
                "data.win.eventdata.sourceNetworkAddress",
            ),
            destination_ip=_first(
                raw_event,
                "data.dstip",
                "data.dst_ip",
                "data.destination.ip",
                "data.win.eventdata.destinationIp",
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
                    "data.user.name",
                    "data.audit.user.name",
                ),
                maximum=512,
                field="username",
            ),
            event_category=event_category,
            event_action=event_action,
            outcome=outcome,
            rule_id=_text(rule.get("id"), maximum=128, field="rule.id"),
            severity=severity,
            mitre=_mitre_context(raw_event),
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


def normalize_wazuh_event(
    raw_event: dict[str, Any],
    *,
    ingestion_source: str = "wazuh_archives",
    context=None,
) -> NormalizedSecurityEvent:
    """Normalize through explicit M28 adapters while preserving legacy identity."""

    from app.services.source_adapters import normalize_source_event

    return normalize_source_event(raw_event, ingestion_source=ingestion_source, context=context)
