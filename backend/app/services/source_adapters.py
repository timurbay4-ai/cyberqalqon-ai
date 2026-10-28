"""Bounded Wazuh source adapters. No collectors, checkpoint writes, or schema DDL."""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone, tzinfo
from typing import Any, Protocol

from pydantic import ValidationError

from app.schemas.cuse import CUSEMetadata, SourceFamily
from app.schemas.events import NormalizedSecurityEvent
from app.services.event_normalizer import (
    EventNormalizationError, WINDOWS_EVENT_SEMANTICS, _first, _mapping, _port,
    _normalize_legacy_wazuh_event, redact_sensitive_payload,
)
from app.services.wazuh_normalizer import canonical_json


MAX_SOURCE_BYTES = 1_048_576
MAX_NODES = 10_000
MAX_DEPTH = 24
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
WINDOWS_CODE = re.compile(r"^[0-9]{1,5}$")
RFC3164 = re.compile(
    r"^(?:<(?P<pri>[0-9]{1,3})>)?(?P<date>[A-Z][a-z]{2} +[0-9]{1,2} "
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}) (?P<host>[^ ]+) (?P<program>[^ :\[]+)"
    r"(?:\[(?P<pid>[0-9]+)\])?: ?(?P<message>.*)$", re.DOTALL,
)
PROGRAM = re.compile(r"\b(sshd|sudo|su|login)(?:\[([0-9]+)\])?:", re.IGNORECASE)
SSH = re.compile(
    r"\b(Accepted|Failed) (?:password|publickey|keyboard-interactive(?:/pam)?) for "
    r"(?:invalid user )?([^ ]+) from ([^ ]+)(?: port ([0-9]+))?", re.IGNORECASE,
)
INVALID_SSH = re.compile(r"\bInvalid user ([^ ]+) from ([^ ]+)(?: port ([0-9]+))?", re.IGNORECASE)
SYSMON_ACTIONS = {
    "1": "process_start", "3": "network_connection", "7": "image_load",
    "8": "remote_thread_create", "10": "process_access", "11": "file_create",
    "12": "registry_object_change", "13": "registry_value_set",
    "14": "registry_rename", "22": "dns_query",
}
SYSMON_CONTEXT_FIELDS = {
    "1": ("image", "processId"), "3": ("sourceIp", "destinationIp", "destinationPort"),
    "7": ("imageLoaded",), "8": ("sourceImage", "targetImage"),
    "10": ("sourceImage", "targetImage"), "11": ("targetFilename",),
    "12": ("targetObject",), "13": ("targetObject",), "14": ("targetObject",),
    "22": ("queryName",),
}


@dataclass(frozen=True, slots=True)
class SourceContext:
    """Server-created context; never constructed from untrusted payload labels."""

    transport_authenticated: bool = False
    expected_agent_id: str | None = None
    expected_manager: str | None = None
    syslog_year: int | None = None
    syslog_timezone: tzinfo | None = None


@dataclass(slots=True)
class AdapterResult:
    patch: dict[str, Any]
    attributes: dict[str, str | int]
    source_time: datetime | None = None
    warnings: tuple[str, ...] = ()
    supported: bool = True


class SourceAdapter(Protocol):
    source_family: SourceFamily
    adapter_version: str

    def normalize(self, raw: dict[str, Any], context: SourceContext) -> AdapterResult: ...


def validate_bounds(raw: Any) -> None:
    if not isinstance(raw, dict):
        raise EventNormalizationError("payload must be a JSON object")
    for field in ("agent", "manager", "rule", "decoder", "data", "predecoder"):
        if raw.get(field) is not None and not isinstance(raw[field], dict):
            raise EventNormalizationError("source section must be a JSON object", field=field)
    groups = _first(raw, "rule.groups")
    if groups is not None and not isinstance(groups, list):
        raise EventNormalizationError("rule groups must be an array", field="rule.groups")
    for field in ("data.journal", "data.journald"):
        value = _first(raw, field)
        if value is not None and not isinstance(value, dict):
            raise EventNormalizationError("journal metadata must be an object", field=field)
    stack = [(raw, 0)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise EventNormalizationError("source structure exceeds limits", code="OVERSIZED")
        if isinstance(value, dict):
            if len(value) > MAX_NODES:
                raise EventNormalizationError("source object exceeds limits", code="OVERSIZED")
            if any(not isinstance(key, str) for key in value):
                raise EventNormalizationError("JSON keys must be text")
            for key in value:
                try:
                    key.encode("utf-8", errors="strict")
                except UnicodeEncodeError as exc:
                    raise EventNormalizationError("source contains invalid Unicode") from exc
                if len(key) > 1024:
                    raise EventNormalizationError("source key exceeds limits", code="OVERSIZED")
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            if len(value) > MAX_NODES:
                raise EventNormalizationError("source array exceeds limits", code="OVERSIZED")
            stack.extend((item, depth + 1) for item in value)
        elif isinstance(value, str):
            try:
                value.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise EventNormalizationError("source contains invalid Unicode") from exc
            if len(value) > 262_144:
                raise EventNormalizationError("source field exceeds limits", code="OVERSIZED")
        elif isinstance(value, float) and not math.isfinite(value):
            raise EventNormalizationError("source numbers must be finite")
        elif value is not None and not isinstance(value, (int, float, bool)):
            raise EventNormalizationError("source must contain JSON values")
    try:
        size = len(canonical_json(raw).encode("utf-8"))
    except (ValueError, TypeError, OverflowError) as exc:
        raise EventNormalizationError("source cannot be encoded as JSON") from exc
    if size > MAX_SOURCE_BYTES:
        raise EventNormalizationError("source exceeds maximum bytes", code="OVERSIZED")


def text(value: Any, field: str, maximum: int = 1024) -> str | None:
    if value in (None, "", "-"):
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise EventNormalizationError("source field must be text", field=field)
    return CONTROL.sub("", str(value)).strip()[:maximum] or None


def timestamp(value: Any, field: str) -> datetime | None:
    if value in (None, "", "-"):
        return None
    if not isinstance(value, str):
        raise EventNormalizationError("source timestamp must be ISO-8601 text", field=field, code="INVALID_TIMESTAMP")
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("timezone missing")
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise EventNormalizationError("source timestamp must include a valid UTC offset", field=field, code="INVALID_TIMESTAMP") from exc


def validate_source_identity(raw: dict[str, Any], context: SourceContext) -> None:
    for expected, path in ((context.expected_agent_id, "agent.id"), (context.expected_manager, "manager.name")):
        if expected is not None and str(_first(raw, path) or "") != expected:
            raise EventNormalizationError("source identity does not match trusted context", field=path, code="INVALID_SOURCE_IDENTITY")


class WindowsAdapter:
    source_family: SourceFamily = "WINDOWS_EVENTCHANNEL"
    adapter_version = "m28-v1"

    def normalize(self, raw: dict[str, Any], context: SourceContext) -> AdapterResult:
        system = _mapping(_first(raw, "data.win.system"))
        data = _mapping(_first(raw, "data.win.eventdata"))
        code = text(system.get("eventID", system.get("eventId")), "event_code", 128)
        if code is None or WINDOWS_CODE.fullmatch(code) is None or int(code) > 65535:
            raise EventNormalizationError("Windows event ID must be an integer from 0 to 65535", field="event_code")
        source_time = timestamp(system.get("systemTime"), "data.win.system.systemTime")
        attrs = {}
        for source, target in (
            ("eventRecordID", "event_record_id"), ("version", "event_version"),
        ):
            value = text(system.get(source), source, 255)
            if value is not None:
                attrs[target] = value
        for source, target in (("targetUserSid", "target_user_sid"), ("subjectUserSid", "subject_user_sid")):
            value = text(data.get(source), source, 255)
            if value is not None:
                attrs[target] = value
        patch: dict[str, Any] = {"event_code": code}
        if code == "4740":
            patch.update(event_action="account_lockout", outcome="observed")
        warnings = () if system.get("providerName") and system.get("channel") else ("SOURCE_CONTEXT_INCOMPLETE",)
        return AdapterResult(patch, attrs, source_time, warnings, code in WINDOWS_EVENT_SEMANTICS or code == "4740")


class SysmonAdapter(WindowsAdapter):
    source_family: SourceFamily = "SYSMON"

    def normalize(self, raw: dict[str, Any], context: SourceContext) -> AdapterResult:
        result = super().normalize(raw, context)
        data = _mapping(_first(raw, "data.win.eventdata"))
        code = result.patch["event_code"]
        action = SYSMON_ACTIONS.get(code)
        result.patch.update(event_category="windows_sysmon", event_action=action, outcome="observed")
        result.supported = action is not None
        if action is not None and any(data.get(field) in (None, "", "-") for field in SYSMON_CONTEXT_FIELDS[code]):
            result.warnings = (*result.warnings, "SOURCE_CONTEXT_INCOMPLETE")
        for source, target in (
            ("processGuid", "process_guid"), ("parentProcessGuid", "parent_process_guid"),
            ("sourceProcessGUID", "source_process_guid"), ("targetProcessGUID", "target_process_guid"),
            ("hashes", "hashes"), ("queryName", "dns_query_name"),
            ("queryResults", "dns_query_results"), ("targetObject", "registry_object"),
            ("eventType", "registry_operation"), ("targetFilename", "file_path"),
            ("imageLoaded", "image_loaded"), ("targetImage", "target_image"),
        ):
            value = text(data.get(source), source, 2048)
            if value is not None:
                result.attributes[target] = value
        for source, target in (
            ("sourceIp", "source_ip"), ("destinationIp", "destination_ip"),
            ("sourcePort", "source_port"), ("destinationPort", "destination_port"),
            ("user", "username"), ("sourceImage", "process_name"),
            ("sourceProcessId", "process_id"),
        ):
            value = text(data.get(source), source)
            if value is not None:
                if target.endswith("_port"):
                    try:
                        value = int(value)
                    except ValueError as exc:
                        raise EventNormalizationError("source port must be an integer", field=target) from exc
                result.patch[target] = value
        return result


def journal_fields(raw: dict[str, Any]) -> dict[str, Any]:
    return dict(_mapping(_first(raw, "data.journald", "data.journal")))


def syslog_fields(raw: dict[str, Any], context: SourceContext) -> AdapterResult:
    line = text(raw.get("full_log"), "full_log", 65_536) or ""
    attrs: dict[str, str | int] = {}
    patch: dict[str, Any] = {}
    source_time = None
    warnings: tuple[str, ...] = ()
    if line.startswith("<"):
        priority = re.match(r"^<([0-9]{1,3})>", line)
        if priority is None or int(priority.group(1)) > 191:
            raise EventNormalizationError("invalid syslog priority", field="full_log")
        pri = int(priority.group(1))
        attrs.update(syslog_priority=pri, syslog_facility=pri // 8, syslog_severity=pri % 8)
        after_priority = line[priority.end():]
        if re.match(r"^[1-9][0-9]{0,2} ", after_priority):
            parts = after_priority.split(" ", 6)
            if len(parts) != 7:
                raise EventNormalizationError("truncated RFC5424 header", field="full_log")
            version, stamp, host, app, pid, message_id, rest = parts
            source_time = timestamp(stamp, "syslog.timestamp")
            if not app:
                raise EventNormalizationError("empty syslog program", field="program")
            patch.update(hostname=text(host, "hostname", 255), process_name=text(app, "program"), process_id=text(pid, "pid", 128))
            attrs.update(syslog_version=version)
            if message_id != "-":
                attrs["message_id"] = message_id[:255]
            # Parse bounded RFC5424 structured-data with quoted escapes. Reject
            # malformed framing rather than treating it as a valid header.
            if rest.startswith("-") and (len(rest) == 1 or rest[1] == " "):
                message = rest[2:] if len(rest) > 1 else ""
            elif rest.startswith("["):
                in_quote = escaped = False
                end = 0
                while end < len(rest):
                    char = rest[end]
                    if escaped:
                        escaped = False
                    elif char == "\\" and in_quote:
                        escaped = True
                    elif char == '"':
                        in_quote = not in_quote
                    elif char == "]" and not in_quote:
                        if end + 1 >= len(rest) or rest[end + 1] != "[":
                            break
                    end += 1
                if end >= len(rest) or in_quote:
                    raise EventNormalizationError("invalid syslog structured data", field="full_log")
                if end + 1 < len(rest) and rest[end + 1] != " ":
                    raise EventNormalizationError("invalid syslog message separator", field="full_log")
                attrs["structured_data"] = rest[:end + 1][:4096]
                message = rest[end + 2:] if len(rest) > end + 1 and rest[end + 1] == " " else ""
            else:
                raise EventNormalizationError("invalid RFC5424 structured data", field="full_log")
            patch["message"] = message[:4096] or "Syslog event"
            return AdapterResult(patch, attrs, source_time)
    match = RFC3164.fullmatch(line)
    if match:
        patch.update(hostname=match["host"][:255], process_name=match["program"][:1024], process_id=match["pid"])
        patch["message"] = match["message"][:4096] or "Syslog event"
        # Validate day/time even when the year and timezone are unavailable.
        try:
            parsed = datetime.strptime("2000 " + match["date"], "%Y %b %d %H:%M:%S")
            if context.syslog_year is not None and context.syslog_timezone is not None:
                source_time = parsed.replace(year=context.syslog_year, tzinfo=context.syslog_timezone)
                warnings = ("SOURCE_TIME_CONTEXT_INFERRED",)
            else:
                warnings = ("YEARLESS_TIME_UNRESOLVED",)
        except ValueError as exc:
            raise EventNormalizationError("invalid RFC3164 date", field="full_log", code="INVALID_TIMESTAMP") from exc
    else:
        predecoder = _mapping(raw.get("predecoder"))
        program = text(predecoder.get("program_name"), "predecoder.program_name")
        if program:
            patch["process_name"] = program
        warnings = ("SOURCE_CONTEXT_INCOMPLETE",)
    return AdapterResult(patch, attrs, source_time, warnings)


class SyslogAdapter:
    source_family: SourceFamily = "SYSLOG"
    adapter_version = "m28-v1"

    def normalize(self, raw: dict[str, Any], context: SourceContext) -> AdapterResult:
        return syslog_fields(raw, context)


class JournalAdapter:
    source_family: SourceFamily = "JOURNALD"
    adapter_version = "m28-v1"

    def normalize(self, raw: dict[str, Any], context: SourceContext) -> AdapterResult:
        journal = journal_fields(raw)
        if not journal:
            # Wazuh's documented journald collection also emits decoded
            # RFC3164-style full_log/predecoder envelopes with location=journald.
            result = syslog_fields(raw, context)
            result.attributes["collection_format"] = "wazuh_journald_syslog"
            return result
        patch = {}
        attrs = {}
        for source, target in (("_HOSTNAME", "hostname"), ("_COMM", "process_name"), ("SYSLOG_IDENTIFIER", "process_name"), ("_PID", "process_id"), ("MESSAGE", "message")):
            value = text(journal.get(source), source, 4096 if target == "message" else 255)
            if value is not None:
                patch.setdefault(target, value)
        source_time = None
        microseconds = journal.get("__REALTIME_TIMESTAMP")
        if microseconds is not None:
            try:
                if isinstance(microseconds, bool) or not str(microseconds).isdigit():
                    raise ValueError("invalid realtime timestamp")
                source_time = datetime.fromtimestamp(int(microseconds) / 1_000_000, tz=timezone.utc)
            except (ValueError, OverflowError, OSError) as exc:
                raise EventNormalizationError("invalid journal realtime timestamp", field="__REALTIME_TIMESTAMP", code="INVALID_TIMESTAMP") from exc
        for source, target in (("_BOOT_ID", "boot_id"), ("_MACHINE_ID", "machine_id"), ("__CURSOR", "journal_record_cursor"), ("_SYSTEMD_UNIT", "systemd_unit")):
            value = text(journal.get(source), source, 255)
            if value is not None:
                attrs[target] = value
        for source, maximum in (("PRIORITY", 7), ("SYSLOG_FACILITY", 23)):
            if journal.get(source) is not None:
                value = str(journal[source])
                if not value.isdigit() or not 0 <= int(value) <= maximum:
                    raise EventNormalizationError("invalid journal priority or facility", field=source)
                attrs[source.lower()] = int(value)
        return AdapterResult(patch, attrs, source_time)


class LinuxAuthAdapter:
    source_family: SourceFamily = "LINUX_AUTH"
    adapter_version = "m28-v1"

    def normalize(self, raw: dict[str, Any], context: SourceContext) -> AdapterResult:
        journal = journal_fields(raw)
        result = JournalAdapter().normalize(raw, context) if journal else syslog_fields(raw, context)
        message = str(journal.get("MESSAGE", raw.get("full_log", "")))
        lower = message.casefold()
        program = text(_first(raw, "predecoder.program_name", "decoder.name"), "program")
        match = PROGRAM.search(message)
        if match:
            program = match[1].casefold()
            if match[2]:
                result.patch["process_id"] = match[2]
        program = str(result.patch.get("process_name") or program or "").casefold()
        if program in {"sshd", "sudo", "su", "login"}:
            result.patch["process_name"] = program
        result.patch["operating_system"] = text(_first(raw, "agent.os.name"), "operating_system", 255) or "linux"
        ssh = SSH.search(message)
        invalid = INVALID_SSH.search(message)
        if ssh or invalid:
            if ssh:
                user, address, port = ssh[2], ssh[3], ssh[4]
                outcome = "success" if ssh[1].casefold() == "accepted" else "failure"
            else:
                user, address, port = invalid[1], invalid[2], invalid[3]
                outcome = "failure"
            try:
                ipaddress.ip_address(address)
            except ValueError as exc:
                raise EventNormalizationError("invalid SSH source address", field="source_ip") from exc
            result.patch.update(username=user, source_ip=address, event_category="linux_ssh", event_action="authenticate", outcome=outcome)
            if port:
                result.patch["source_port"] = _port(port, "source_port")
        elif "session opened" in lower or "session closed" in lower:
            opened = "session opened" in lower
            result.patch.update(event_action="session_open" if opened else "session_close", outcome="observed", event_category="linux_pam")
            user_match = re.search(r"session (?:opened|closed) for user ([^ (]+)", message, re.IGNORECASE)
            if user_match:
                result.patch["username"] = user_match[1]
        elif "sudo" in program or "sudo:" in lower or "sudo(" in lower:
            failure = any(marker in lower for marker in ("authentication failure", "incorrect password", "not in the sudoers", "not allowed"))
            result.patch.update(event_category="linux_sudo", event_action="privilege_escalation", outcome="failure" if failure else "success" if "command=" in lower else "observed")
            command = re.search(r"\bCOMMAND=(.*)$", message)
            if command:
                result.patch["command_line"] = command[1][:8192]
        elif "authentication failure" in lower:
            result.patch.update(event_category="linux_pam", event_action="authenticate", outcome="failure")
        # Preserve already decoded user/address fields; parse only an explicit
        # PAM assignment and never infer an IP from a hostname/account name.
        if not _first(raw, "data.dstuser", "data.srcuser", "data.user"):
            user_match = re.search(r"\buser=([^ ;]+)", message)
            if user_match:
                result.patch.setdefault("username", user_match[1])
        return result


class GenericAdapter:
    source_family: SourceFamily = "WAZUH_GENERIC"
    adapter_version = "m28-v1"

    def normalize(self, raw: dict[str, Any], context: SourceContext) -> AdapterResult:
        return AdapterResult({}, {}, supported=False)


def select_adapter(raw: dict[str, Any]) -> SourceAdapter:
    windows = _first(raw, "data.win") is not None
    windows_label = _first(raw, "decoder.name") == "windows_eventchannel"
    journal = journal_fields(raw)
    if (windows or windows_label) and journal:
        raise EventNormalizationError("source identification is ambiguous", code="AMBIGUOUS_SOURCE")
    if windows:
        provider = str(_first(raw, "data.win.system.providerName") or "").casefold()
        channel = str(_first(raw, "data.win.system.channel") or "").casefold()
        sysmon_provider = provider == "microsoft-windows-sysmon"
        sysmon_channel = channel == "microsoft-windows-sysmon/operational"
        if (sysmon_provider and channel and not sysmon_channel) or (sysmon_channel and provider and not sysmon_provider):
            raise EventNormalizationError("conflicting Sysmon provider and channel", code="INVALID_SOURCE_IDENTITY")
        return SysmonAdapter() if sysmon_provider or sysmon_channel else WindowsAdapter()
    if windows_label:
        # Older accepted envelopes may carry only a decoder label, without
        # EventChannel metadata. Preserve them without inventing a Windows ID
        # or claiming that the source-specific contract has been validated.
        return GenericAdapter()
    decoder = str(_first(raw, "decoder.name") or "").casefold()
    program = str(_first(raw, "predecoder.program_name") or journal.get("SYSLOG_IDENTIFIER") or journal.get("_COMM") or "").casefold()
    header = RFC3164.fullmatch(str(raw.get("full_log", "")))
    if not program and header:
        program = header["program"].casefold()
    groups = _first(raw, "rule.groups")
    groups = {str(item).casefold() for item in groups} if isinstance(groups, list) else set()
    if decoder in {"sshd", "sudo", "pam", "pam_unix"} or program in {"sshd", "sudo", "su", "login"} or groups.intersection({"sshd", "pam", "sudo"}):
        return LinuxAuthAdapter()
    if journal:
        return JournalAdapter()
    if raw.get("location") == "journald":
        return JournalAdapter()
    if decoder == "syslog" or header or _first(raw, "predecoder.program_name") or str(raw.get("full_log", "")).startswith("<"):
        return SyslogAdapter()
    return GenericAdapter()


def normalize_source_event(
    raw: dict[str, Any], *, ingestion_source: str, context: SourceContext | None = None,
) -> NormalizedSecurityEvent:
    validate_bounds(raw)
    context = context or SourceContext()
    validate_source_identity(raw, context)
    if timestamp(raw.get("timestamp"), "timestamp") is None:
        raise EventNormalizationError("collector timestamp is required", field="timestamp", code="INVALID_TIMESTAMP")
    adapter = select_adapter(raw)
    result = adapter.normalize(raw, context)
    # Legacy hash always uses the original envelope. Adapters never mutate it.
    event = _normalize_legacy_wazuh_event(raw, ingestion_source=ingestion_source)
    for field in ("source_ip", "destination_ip"):
        original = getattr(event, field)
        replacement = result.patch.get(field)
        if original is not None and replacement is not None:
            try:
                if original != ipaddress.ip_address(replacement):
                    raise EventNormalizationError("conflicting decoded source fields", field=field)
            except ValueError as exc:
                if isinstance(exc, EventNormalizationError):
                    raise
                raise EventNormalizationError("invalid source address", field=field) from exc
    source_time = result.source_time
    warnings = list(result.warnings)
    if source_time is None:
        warnings.append("SOURCE_TIME_UNAVAILABLE")
    if not result.supported:
        warnings.append("UNSUPPORTED_EVENT_CODE" if adapter.source_family == "SYSMON" else "SOURCE_CONTEXT_INCOMPLETE")
    warnings.append("SOURCE_IDENTITY_CLAIMED")
    identity = {key: _first(raw, path) for key, path in (
        ("manager", "manager.name"), ("agent", "agent.id"),
        ("host", "data.win.system.computer"), ("provider", "data.win.system.providerName"),
        ("channel", "data.win.system.channel"),
    )}
    identity["family"] = adapter.source_family
    metadata = CUSEMetadata(
        source_family=adapter.source_family,
        normalization_status="UNSUPPORTED_SOURCE" if not result.supported else "PARTIAL" if source_time is None or result.warnings else "NORMALIZED",
        provenance_status="PARTIAL" if context.transport_authenticated else "UNKNOWN",
        transport_authenticated=context.transport_authenticated,
        source_event_time=source_time,
        collector_observation_time=event.timestamp,
        timestamp_basis="SOURCE_EVENT_TIME" if source_time else "COLLECTOR_OBSERVATION_TIME",
        original_event_identity=redact_sensitive_payload(
            str(result.attributes.get("event_record_id") or event.source_event_id or "")[:255]
        ) or None,
        source_identity_sha256=hashlib.sha256(canonical_json(identity).encode()).hexdigest(),
        content_fingerprint=event.deduplication_id,
        warnings=list(dict.fromkeys(warnings)),
        attributes=redact_sensitive_payload(result.attributes),
    )
    values = event.model_dump()
    values.update(result.patch)
    if source_time is not None:
        values["timestamp"] = source_time
    # Canonical string fields have the same redaction policy as raw evidence.
    for key, value in values.items():
        if isinstance(value, str) and key not in {"event_id", "deduplication_id"}:
            values[key] = CONTROL.sub("", redact_sensitive_payload(value))
    structured = dict(event.structured_payload)
    structured["_cuse"] = metadata.model_dump(mode="json")
    values["structured_payload"] = structured
    try:
        return NormalizedSecurityEvent.model_validate(values)
    except ValidationError as exc:
        field = ".".join(str(part) for part in exc.errors(include_url=False)[0]["loc"])
        raise EventNormalizationError("source field validation failed", field=field) from exc
