"""Deterministic M11 detection semantics over normalized security events.

The engine is intentionally not connected to live ingestion.  The catalog is
disabled by policy and this module is currently invoked only by the bounded
historical dry-run API.  A future live evaluator must call :meth:`evaluate`
instead of reimplementing these semantics.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from collections import defaultdict, deque
from contextlib import closing
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from app.schemas.detection_engineering import (
    AdvancedDetectionAvailability,
    AdvancedDetectionEvidence,
    AdvancedDetectionFinding,
    AdvancedDetectionPrerequisite,
    AdvancedDetectionRule,
    AdvancedMitreMapping,
    AdvancedRuleDryRunRequest,
    AdvancedRuleDryRunResult,
)


@dataclass(frozen=True, slots=True)
class RuleSpec:
    rule_id: str
    name: str
    description: str
    severity: int
    source_types: tuple[str, ...]
    event_codes: tuple[str, ...]
    event_categories: tuple[str, ...]
    required_fields: tuple[str, ...]
    conditions: tuple[str, ...]
    grouping_fields: tuple[str, ...]
    window_seconds: int
    threshold: int
    deduplication: str
    mitre_ids: tuple[str, ...]
    false_positive_notes: tuple[str, ...]
    evidence_fields: tuple[str, ...]
    analyst_guidance: tuple[str, ...]
    validation_notes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DetectionEvent:
    event_id: str
    timestamp: datetime
    source_type: str
    hostname: str | None
    username: str | None
    source_ip: str | None
    event_code: str | None
    category: str | None
    action: str | None
    outcome: str | None
    process_name: str | None
    process_path: str | None
    command_line: str | None
    parent_process_name: str | None
    message: str
    raw: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class FindingSeed:
    events: tuple[DetectionEvent, ...]
    group: Mapping[str, str]
    explanation: str
    reason: str
    threshold: int | None = None
    mitre_ids: tuple[str, ...] | None = None


RULES: tuple[RuleSpec, ...] = (
    RuleSpec(
        "DET-001", "Windows brute-force candidate",
        "Detect repeated Windows failed logons with conservative identity, source, and logon-type grouping.",
        10, ("windows_event",), ("4625",), ("windows_security",),
        ("hostname", "username", "logon_type"),
        (
            "Event ID 4625 and outcome=failure.",
            "Five failures for the same host, account, source identity and logon type within five minutes.",
            "Missing source IP is accepted only for local/interactive logon types; machine and built-in service accounts are excluded.",
        ),
        ("hostname", "username", "source_ip_or_local", "logon_type"), 300, 5,
        "One finding per grouping key per ten-minute cooldown; upstream event IDs are unique evidence.",
        ("T1110.001",),
        ("Shared jump hosts and stale credentials can create bursts.", "Service accounts are excluded by default and need a separately tuned rule."),
        ("event_id", "timestamp", "hostname", "username", "source_ip", "logon_type", "status", "sub_status"),
        ("Confirm the source and logon type.", "Check for a later successful logon and reset exposed credentials if compromise is confirmed."),
        ("Boundary: four failures do not match; five in 300 seconds match.", "Out-of-order input is sorted by event time and event ID."),
    ),
    RuleSpec(
        "DET-002", "Windows failures followed by success",
        "Correlate repeated Windows logon failures followed by a successful logon for the same identity and source context.",
        12, ("windows_event",), ("4625", "4624"), ("windows_security",),
        ("hostname", "username", "logon_type"),
        (
            "At least three Event ID 4625 failures precede Event ID 4624 within ten minutes.",
            "Host, account, source identity and logon type must agree.",
            "Network logons require source IP; missing IP is accepted only for local/interactive logon types.",
        ),
        ("hostname", "username", "source_ip_or_local", "logon_type"), 600, 3,
        "A successful event closes the failure sequence and prevents overlapping duplicate findings.",
        ("T1110.001", "T1078"),
        ("Users correcting a mistyped password can satisfy low thresholds.", "Password synchronization delays may cause benign failure-success sequences."),
        ("failure_event_ids", "success_event_id", "hostname", "username", "source_ip", "logon_type"),
        ("Validate that the success came from the same expected source.", "Review process and session activity immediately after the success."),
        ("Success before failures does not match.", "Three failures followed by success at the window boundary match."),
    ),
    RuleSpec(
        "DET-003", "Remote privileged Windows logon",
        "Correlate a remote/network successful logon with assignment of special privileges without treating every administrator session as malicious.",
        9, ("windows_event",), ("4624", "4672"), ("windows_security",),
        ("hostname", "username", "logon_id", "source_ip", "logon_type"),
        (
            "Event IDs 4624 and 4672 share host, account and logon ID within two minutes.",
            "Only network or remote-interactive logon types 3 and 10 with a source IP are considered.",
            "SYSTEM, LOCAL SERVICE, NETWORK SERVICE, anonymous and machine accounts are excluded.",
        ),
        ("hostname", "username", "logon_id"), 120, 2,
        "One finding per host/account/logon ID; identical evidence cannot produce another finding.",
        ("T1078",),
        ("Expected remote administration remains a review candidate.", "Approved management subnets should be tuned in a deployment-specific allowlist."),
        ("logon_event_id", "privilege_event_id", "hostname", "username", "logon_id", "source_ip", "logon_type"),
        ("Confirm the account and source are approved for remote administration.", "Review child processes and lateral movement from the session."),
        ("A standalone 4672 does not match.", "Local interactive and service logons do not match."),
    ),
    RuleSpec(
        "DET-004", "Windows account or privileged group change",
        "Detect account creation/deletion and membership additions to explicitly privileged Windows groups.",
        8, ("windows_event",), ("4720", "4726", "4732"), ("windows_security",),
        ("hostname", "account_or_group_context"),
        (
            "Event IDs 4720 and 4726 identify account lifecycle changes.",
            "Event ID 4732 matches only privileged local/domain group names or well-known privileged group SIDs.",
            "Actor and target context are preserved when present; absence is shown as unknown, never fabricated.",
        ),
        ("hostname", "event_code", "target_account_or_group"), 300, 1,
        "Duplicate account/group action keys within five minutes collapse into one finding.",
        ("T1136", "T1098.007"),
        ("Approved onboarding and offboarding generates account events.", "Privileged group maintenance may be legitimate under a change ticket."),
        ("event_id", "actor", "target_account", "target_sid", "group_name", "group_sid", "hostname"),
        ("Confirm an approved identity-management change exists.", "Review the new or changed account's subsequent logons and privileges."),
        ("A 4732 event for an ordinary local group does not match.", "Privileged group names and SIDs are compared case-insensitively."),
    ),
    RuleSpec(
        "DET-005", "Suspicious PowerShell execution",
        "Detect high-risk PowerShell indicator combinations while ignoring ordinary administrative PowerShell use.",
        11, ("windows_event",), ("4103", "4104", "4688"), ("windows_powershell", "windows_security"),
        ("hostname", "command_or_script"),
        (
            "PowerShell telemetry contains a strong encoded/download/Invoke-Expression indicator, or at least two medium-risk indicators.",
            "A process-creation event must identify PowerShell in the process, parent, or command context.",
            "Plain Get-Process, signed-module loading, and PowerShell presence alone do not match.",
        ),
        ("hostname", "username", "process_context"), 300, 1,
        "Equivalent indicator categories for the same host/user/process context deduplicate for five minutes.",
        ("T1059.001", "T1027.010"),
        ("Software deployment and encoded enterprise scripts may be legitimate.", "Security tooling can use download or in-memory execution primitives."),
        ("event_id", "timestamp", "hostname", "username", "process_path", "parent_process", "matched_indicator_categories"),
        ("Retrieve the redacted command/script evidence from the protected event record.", "Check script provenance, signing, parent process, and network activity."),
        ("Ordinary PowerShell commands are explicit negative fixtures.", "Evidence summaries never echo complete command lines."),
    ),
    RuleSpec(
        "DET-006", "High-risk Windows service installation",
        "Detect service installation events with command-shell, user-writable, network-path, or privileged auto-start risk combinations.",
        10, ("windows_event",), ("7045",), ("windows_system",),
        ("hostname", "service_metadata"),
        (
            "Event ID 7045 is required.",
            "A command interpreter, script host, network/user-writable image path, or privileged auto-start combination must be present.",
            "A normal signed service path alone does not match.",
        ),
        ("hostname", "service_name"), 600, 1,
        "The same service name and image-risk signature deduplicates for ten minutes.",
        ("T1543.003",),
        ("Legitimate endpoint-management agents may install LocalSystem services.", "Installers can transiently stage binaries under user-writable paths."),
        ("event_id", "hostname", "service_name", "image_path", "start_type", "service_account", "risk_categories"),
        ("Validate the service binary signature and change authorization.", "Inspect service start, child processes, persistence, and outbound activity."),
        ("A normal demand-start service under Program Files does not match.", "Command-shell service images are high-risk without a second signal."),
    ),
    RuleSpec(
        "DET-007", "Linux SSH brute-force or failure-success",
        "Detect repeated SSH authentication failures and an optional failure-then-success sequence with complete host/user/source grouping.",
        10, ("authentication", "wazuh_alert", "wazuh_archive"), (), ("linux_ssh", "linux_pam"),
        ("hostname", "username", "source_ip"),
        (
            "Five failures for the same host, account and source IP within five minutes match brute force.",
            "Three failures followed by success for the same key within ten minutes match a compromise candidate.",
            "Events missing user or source IP do not enter correlation state.",
        ),
        ("hostname", "username", "source_ip"), 600, 3,
        "Failure bursts and failure-success sequences have distinct deduplication reasons per grouping key.",
        ("T1110.001", "T1078"),
        ("Users can mistype passwords before a legitimate login.", "NAT and bastion hosts can aggregate independent users behind one source."),
        ("event_ids", "hostname", "username", "source_ip", "outcomes"),
        ("Check source reputation and expected user location.", "Review the successful session and rotate credentials when unauthorized."),
        ("Missing source/user events are negative fixtures.", "Both threshold and ordered sequence paths are tested."),
    ),
    RuleSpec(
        "DET-008", "Unusual sudo activity",
        "Detect failed or materially high-risk sudo activity without flagging every successful sudo command.",
        8, ("authentication", "wazuh_alert", "wazuh_archive"), (), ("linux_sudo",),
        ("hostname", "username", "command_or_failure"),
        (
            "Failed authorization/not-in-sudoers evidence matches.",
            "Successful sudo requires account modification, shell spawn, persistence, security-control impairment, or sensitive permission changes.",
            "Routine package, status, log-reading and service-restart commands alone do not match.",
        ),
        ("hostname", "username", "risk_category"), 300, 1,
        "Same user/risk category on a host deduplicates for five minutes.",
        ("T1548.003",),
        ("Authorized emergency administration can use shell or account-management commands.", "Configuration management may legitimately change permissions."),
        ("event_id", "hostname", "username", "target_user", "risk_category", "outcome"),
        ("Validate the command against an approved administrative task.", "Review shell history and adjacent authentication events."),
        ("Routine sudo systemctl status is an explicit negative fixture.", "Failure and high-risk command branches are independently tested."),
    ),
    RuleSpec(
        "DET-009", "Microsoft Defender detection lifecycle",
        "Correlate Defender detections, remediation, repeated detections, unresolved detections, and protection impairment.",
        12, ("windows_event",), ("1116", "1117", "1118", "1119", "5001", "5007"), ("windows_defender",),
        ("hostname", "defender_threat_context"),
        (
            "Remediation failures 1118/1119 match and correlate to the preceding detection when available.",
            "Repeated 1116 detections for the same host/threat/path within one hour match.",
            "A 1116 detection without 1117 remediation after fifteen minutes is unresolved.",
            "5001 and explicitly disabling/exclusion-related 5007 changes match defense impairment; generic 5007 changes do not.",
        ),
        ("hostname", "threat_name_or_id", "path"), 3600, 1,
        "One finding per host/threat/path/reason/window; remediation success closes unresolved state.",
        (),
        ("Repeated scans can rediscover quarantined artifacts.", "Administrators can make approved Defender policy changes."),
        ("event_ids", "hostname", "threat_name", "threat_id", "path", "remediation_outcome", "reason"),
        ("Confirm remediation state in Defender and isolate the host when unresolved.", "Review policy-change authorization before treating defense impairment as malicious."),
        ("A remediated single detection does not match unresolved logic.", "Generic Defender configuration changes without impairment terms do not match."),
    ),
)

RULE_BY_ID = {item.rule_id: item for item in RULES}

MITRE_TECHNIQUES: Mapping[str, tuple[str, str]] = {
    "T1110.001": ("Password Guessing", "Credential Access"),
    "T1078": ("Valid Accounts", "Defense Evasion / Persistence / Privilege Escalation / Initial Access"),
    "T1136": ("Create Account", "Persistence"),
    "T1098.007": ("Additional Local or Domain Groups", "Persistence / Privilege Escalation"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1027.010": ("Command Obfuscation", "Stealth"),
    "T1543.003": ("Windows Service", "Persistence / Privilege Escalation"),
    "T1548.003": ("Sudo and Sudo Caching", "Privilege Escalation"),
}

MITRE_RELATIONSHIPS: Mapping[str, Mapping[str, str]] = {
    "DET-001": {"T1110.001": "Repeated failed logons are evidence of password-guessing behavior, not proof of compromise."},
    "DET-002": {
        "T1110.001": "The ordered failure burst represents password guessing.",
        "T1078": "The subsequent success may represent use of a valid account and requires analyst validation.",
    },
    "DET-003": {"T1078": "A remote session receiving special privileges may represent use of a privileged valid account."},
    "DET-004": {
        "T1136": "Event 4720 is account-creation evidence; the rule does not assume local versus domain scope when context is absent.",
        "T1098.007": "A scoped privileged local/domain group membership addition modifies account permissions."},
    "DET-005": {
        "T1059.001": "The event records PowerShell execution with additional high-risk indicators.",
        "T1027.010": "Encoded or decoding command indicators are explicit command-obfuscation evidence."},
    "DET-006": {"T1543.003": "A high-risk service installation is a Windows service persistence/privilege mechanism."},
    "DET-007": {
        "T1110.001": "Repeated SSH authentication failures represent password guessing.",
        "T1078": "A success after failures may represent use of a valid account."},
    "DET-008": {"T1548.003": "Scoped sudo evidence records use or attempted use of the sudo privilege mechanism."},
}


class AdvancedDetectionEvaluationLimitError(RuntimeError):
    """Raised when a bounded dry-run exceeds its explicit wall-clock budget."""


def _nested(value: Mapping[str, Any], path: str) -> Any:
    current: Any = value
    for part in path.split("."):
        if not isinstance(current, Mapping):
            return None
        match = next((key for key in current if str(key).casefold() == part.casefold()), None)
        if match is None:
            return None
        current = current[match]
    return current


def _first(event: DetectionEvent, *paths: str) -> str | None:
    for path in paths:
        value = _nested(event.raw, path)
        if value not in (None, "", "-"):
            return str(value).strip()[:2048]
    return None


def _clean(value: str | None, fallback: str = "unknown") -> str:
    if value is None or not value.strip() or value.strip() in {"-", "::", "0.0.0.0"}:
        return fallback
    return value.strip()[:256]


def _account(event: DetectionEvent) -> str | None:
    value = event.username or _first(
        event, "data.win.eventdata.targetUserName", "data.win.eventdata.subjectUserName",
        "data.user", "data.dstuser", "data.srcuser",
    )
    if value is None:
        text = event.message + " " + str(_nested(event.raw, "full_log") or "")
        match = re.search(r"(?:for|user[= ])\s*(?:invalid user\s+)?([\w.@\\-]+)", text, re.I)
        value = match.group(1) if match else None
    return value.casefold() if value else None


def _source_ip(event: DetectionEvent) -> str | None:
    value = event.source_ip or _first(
        event, "data.win.eventdata.ipAddress", "data.win.eventdata.sourceNetworkAddress",
        "data.srcip", "data.src_ip",
    )
    if value is None:
        text = event.message + " " + str(_nested(event.raw, "full_log") or "")
        match = re.search(r"\bfrom\s+([0-9a-f:.]+)\b", text, re.I)
        value = match.group(1) if match else None
    return None if value in (None, "", "-", "::", "0.0.0.0") else value.casefold()


def _host(event: DetectionEvent) -> str | None:
    return event.hostname.casefold() if event.hostname else None


def _logon_type(event: DetectionEvent) -> str | None:
    return _first(event, "data.win.eventdata.logonType")


def _logon_id(event: DetectionEvent) -> str | None:
    return _first(
        event, "data.win.eventdata.targetLogonId", "data.win.eventdata.subjectLogonId",
        "data.win.eventdata.logonId",
    )


def _is_human_account(value: str | None) -> bool:
    if value is None or value.endswith("$"):
        return False
    leaf = value.rsplit("\\", 1)[-1]
    return leaf not in {
        "system", "local service", "network service", "anonymous logon", "dwm-1", "umfd-0",
    }


def _text(event: DetectionEvent) -> str:
    values = (
        event.command_line, event.process_name, event.process_path, event.parent_process_name,
        event.message, _first(event, "data.win.eventdata.scriptBlockText"),
        _first(event, "data.win.eventdata.payload"), _first(event, "data.command"),
        str(_nested(event.raw, "full_log") or ""),
    )
    return " ".join(value for value in values if value).casefold()


def _eligible_source(event: DetectionEvent, spec: RuleSpec) -> bool:
    source_matches = not spec.source_types or event.source_type in spec.source_types
    category_matches = not spec.event_categories or event.category in spec.event_categories
    code_matches = not spec.event_codes or event.event_code in spec.event_codes
    return source_matches and category_matches and code_matches


def _event_group(event: DetectionEvent) -> tuple[str, str, str, str] | None:
    host, user, logon_type = _host(event), _account(event), _logon_type(event)
    if not host or not user or not logon_type or not _is_human_account(user):
        return None
    source = _source_ip(event)
    if logon_type in {"3", "10"} and source is None:
        return None
    if source is None and logon_type not in {"2", "7", "11"}:
        return None
    return host, user, source or "local-no-ip", logon_type


def _cluster_threshold(
    events: Sequence[DetectionEvent], key: Callable[[DetectionEvent], tuple[str, ...] | None],
    *, threshold: int, window_seconds: int, reason: str,
    explanation: str, cooldown_seconds: int | None = None,
) -> list[FindingSeed]:
    queues: dict[tuple[str, ...], deque[DetectionEvent]] = defaultdict(deque)
    last_fired: dict[tuple[str, ...], datetime] = {}
    result: list[FindingSeed] = []
    for event in events:
        group_key = key(event)
        if group_key is None:
            continue
        queue = queues[group_key]
        cutoff = event.timestamp - timedelta(seconds=window_seconds)
        while queue and queue[0].timestamp < cutoff:
            queue.popleft()
        queue.append(event)
        if len(queue) < threshold:
            continue
        cooldown = cooldown_seconds or window_seconds
        if group_key in last_fired and event.timestamp < last_fired[group_key] + timedelta(seconds=cooldown):
            continue
        evidence = tuple(list(queue)[-threshold:])
        result.append(FindingSeed(
            events=evidence,
            group={f"key_{index + 1}": value for index, value in enumerate(group_key)},
            explanation=explanation, reason=reason, threshold=threshold,
        ))
        last_fired[group_key] = event.timestamp
    return result


def _det001(events: Sequence[DetectionEvent], spec: RuleSpec) -> list[FindingSeed]:
    failures = [event for event in events if event.event_code == "4625" and event.outcome == "failure"]
    seeds = _cluster_threshold(
        failures, _event_group, threshold=spec.threshold,
        window_seconds=spec.window_seconds, cooldown_seconds=spec.window_seconds * 2,
        reason="failed-logon-threshold",
        explanation=(
            f"{spec.threshold} Windows logon failures occurred for the same host, "
            f"account, source context and logon type within {spec.window_seconds} seconds."
        ),
    )
    return [FindingSeed(item.events, {
        "hostname": item.group["key_1"], "username": item.group["key_2"],
        "source_ip_or_local": item.group["key_3"], "logon_type": item.group["key_4"],
    }, item.explanation, item.reason, item.threshold) for item in seeds]


def _failure_success(
    events: Sequence[DetectionEvent], *, windows: bool,
    threshold: int = 3, window_seconds: int = 600,
) -> list[FindingSeed]:
    queues: dict[tuple[str, ...], deque[DetectionEvent]] = defaultdict(deque)
    result: list[FindingSeed] = []
    for event in events:
        if windows:
            if event.event_code not in {"4624", "4625"}:
                continue
            key = _event_group(event)
            failure = event.event_code == "4625" and event.outcome == "failure"
            success = event.event_code == "4624" and event.outcome == "success"
            window = window_seconds
        else:
            if event.category not in {"linux_ssh", "linux_pam"}:
                continue
            host, user, source = _host(event), _account(event), _source_ip(event)
            key = (host, user, source) if host and user and source else None
            failure, success = event.outcome == "failure", event.outcome == "success"
            window = window_seconds
        if key is None:
            continue
        queue = queues[key]
        cutoff = event.timestamp - timedelta(seconds=window)
        while queue and queue[0].timestamp < cutoff:
            queue.popleft()
        if failure:
            queue.append(event)
        elif success and len(queue) >= threshold:
            evidence = tuple(list(queue)[-threshold:] + [event])
            names = ("hostname", "username", "source_ip_or_local", "logon_type") if windows else ("hostname", "username", "source_ip")
            threshold_label = "three" if threshold == 3 else str(threshold)
            result.append(FindingSeed(
                events=evidence, group={name: str(value) for name, value in zip(names, key)},
                explanation=(
                    f"A Windows successful logon followed {threshold_label} failures for the same identity and source context within {window} seconds."
                    if windows else
                    f"An SSH authentication success followed {threshold_label} failures for the same host, account and source IP within {window} seconds."
                ),
                reason="failure-then-success", threshold=threshold,
                mitre_ids=("T1110.001", "T1078"),
            ))
            queue.clear()
    return result


def _det002(events: Sequence[DetectionEvent], spec: RuleSpec) -> list[FindingSeed]:
    return _failure_success(
        events, windows=True, threshold=spec.threshold,
        window_seconds=spec.window_seconds,
    )


def _det003(events: Sequence[DetectionEvent], spec: RuleSpec) -> list[FindingSeed]:
    logons: dict[tuple[str, str, str], DetectionEvent] = {}
    result: list[FindingSeed] = []
    for event in events:
        host, user, logon_id = _host(event), _account(event), _logon_id(event)
        if not host or not user or not logon_id or not _is_human_account(user):
            continue
        key = (host, user, logon_id.casefold())
        if event.event_code == "4624" and event.outcome == "success":
            if _logon_type(event) in {"3", "10"} and _source_ip(event):
                logons[key] = event
        elif event.event_code == "4672" and key in logons:
            logon = logons[key]
            if abs((event.timestamp - logon.timestamp).total_seconds()) <= spec.window_seconds:
                result.append(FindingSeed(
                    events=(logon, event),
                    group={"hostname": host, "username": user, "logon_id": logon_id.casefold()},
                    explanation="A remote/network logon was followed by special-privilege assignment for the same logon session.",
                    reason="remote-privileged-session", threshold=2,
                ))
                logons.pop(key, None)
    return result


_PRIVILEGED_GROUP_NAMES = {
    "administrators", "domain admins", "enterprise admins", "schema admins",
    "account operators", "server operators", "backup operators", "remote desktop users",
}
_PRIVILEGED_GROUP_SIDS = {"s-1-5-32-544", "s-1-5-32-548", "s-1-5-32-549", "s-1-5-32-551"}


def _det004(events: Sequence[DetectionEvent], spec: RuleSpec) -> list[FindingSeed]:
    result: list[FindingSeed] = []
    seen: set[tuple[str, str, str, int]] = set()
    for event in events:
        if event.event_code not in {"4720", "4726", "4732"}:
            continue
        target = _first(event, "data.win.eventdata.targetUserName", "data.win.eventdata.memberName")
        group_name = _first(event, "data.win.eventdata.targetGroupName", "data.win.eventdata.groupName")
        group_sid = _first(event, "data.win.eventdata.targetSid", "data.win.eventdata.groupSid")
        if event.event_code == "4732" and (
            (group_name or "").casefold() not in _PRIVILEGED_GROUP_NAMES
            and (group_sid or "").casefold() not in _PRIVILEGED_GROUP_SIDS
        ):
            continue
        host = _host(event) or "unknown"
        context = (target or group_name or group_sid or "unknown").casefold()
        bucket = int(event.timestamp.timestamp()) // spec.window_seconds
        key = host, event.event_code, context, bucket
        if key in seen:
            continue
        seen.add(key)
        action = {"4720": "account creation", "4726": "account deletion", "4732": "privileged group membership addition"}[event.event_code]
        result.append(FindingSeed(
            events=(event,), group={"hostname": host, "event_code": event.event_code, "target_account_or_group": context},
            explanation=f"Windows {action} evidence met the rule's scoped account-change criteria.",
            reason=action.replace(" ", "-"), threshold=1,
            mitre_ids=(
                ("T1136",) if event.event_code == "4720"
                else ("T1098.007",) if event.event_code == "4732"
                else ()
            ),
        ))
    return result


def _powershell_indicators(text: str) -> tuple[set[str], set[str]]:
    strong: set[str] = set()
    medium: set[str] = set()
    checks = {
        "encoded-command": r"(?:^|\s)-(?:enc|encodedcommand)\b",
        "base64-decode": r"frombase64string|convert::frombase64",
        "download-cradle": r"downloadstring|downloadfile|invoke-webrequest|start-bitstransfer|\biwr\b",
        "dynamic-execution": r"invoke-expression|\biex\s*\(",
    }
    for label, pattern in checks.items():
        if re.search(pattern, text, re.I):
            strong.add(label)
    medium_checks = {
        "execution-policy-bypass": r"executionpolicy\s+bypass|-ep\s+bypass",
        "hidden-window": r"windowstyle\s+hidden|-w\s+hidden",
        "noninteractive": r"-noninteractive|-nop\b",
        "reflection": r"reflection\.assembly|add-type",
    }
    for label, pattern in medium_checks.items():
        if re.search(pattern, text, re.I):
            medium.add(label)
    return strong, medium


def _det005(events: Sequence[DetectionEvent], spec: RuleSpec) -> list[FindingSeed]:
    result: list[FindingSeed] = []
    seen: set[tuple[str, str, tuple[str, ...], int]] = set()
    for event in events:
        if event.event_code not in {"4103", "4104", "4688"}:
            continue
        text = _text(event)
        if event.event_code == "4688" and "powershell" not in text and "pwsh" not in text:
            continue
        strong, medium = _powershell_indicators(text)
        if not strong and len(medium) < 2:
            continue
        indicators = tuple(sorted(strong | medium))
        host, user = _host(event) or "unknown", _account(event) or "unknown"
        bucket = int(event.timestamp.timestamp()) // spec.window_seconds
        key = host, user, indicators, bucket
        if key in seen:
            continue
        seen.add(key)
        result.append(FindingSeed(
            events=(event,),
            group={"hostname": host, "username": user, "process_context": _clean(event.process_path or event.process_name, "powershell")},
            explanation=f"PowerShell evidence contained high-risk indicator categories: {', '.join(indicators)}. Full command text is not repeated in the finding.",
            reason="powershell:" + "+".join(indicators), threshold=1,
            mitre_ids=(
                ("T1059.001", "T1027.010")
                if strong & {"encoded-command", "base64-decode"}
                else ("T1059.001",)
            ),
        ))
    return result


def _det006(events: Sequence[DetectionEvent], spec: RuleSpec) -> list[FindingSeed]:
    result: list[FindingSeed] = []
    seen: set[tuple[str, str, tuple[str, ...], int]] = set()
    for event in events:
        if event.event_code != "7045":
            continue
        image = _first(event, "data.win.eventdata.imagePath") or event.command_line or ""
        service = _first(event, "data.win.eventdata.serviceName") or "unknown"
        start_type = _first(event, "data.win.eventdata.startType") or "unknown"
        account = _first(event, "data.win.eventdata.accountName", "data.win.eventdata.serviceAccount") or "unknown"
        lowered = image.casefold()
        risks: set[str] = set()
        if re.search(r"(?:^|[\\/\s])(cmd|powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32)(?:\.exe)?\b", lowered):
            risks.add("command-or-script-host")
        if any(marker in lowered for marker in ("\\users\\", "\\appdata\\", "\\temp\\", "\\public\\", "/tmp/", "/var/tmp/")):
            risks.add("user-writable-path")
        if lowered.startswith("\\\\") or lowered.startswith("//"):
            risks.add("network-path")
        if "auto" in start_type.casefold() and account.casefold() in {"localsystem", "local system", "system"}:
            risks.add("privileged-auto-start")
        if not risks:
            continue
        host = _host(event) or "unknown"
        signature = tuple(sorted(risks))
        bucket = int(event.timestamp.timestamp()) // spec.window_seconds
        key = host, service.casefold(), signature, bucket
        if key in seen:
            continue
        seen.add(key)
        result.append(FindingSeed(
            events=(event,), group={"hostname": host, "service_name": service[:256]},
            explanation=f"Service installation contained high-risk categories: {', '.join(signature)}.",
            reason="service:" + "+".join(signature), threshold=1,
        ))
    return result


def _det007(events: Sequence[DetectionEvent], spec: RuleSpec) -> list[FindingSeed]:
    ssh = [event for event in events if event.category in {"linux_ssh", "linux_pam"}]
    failures = [event for event in ssh if event.outcome == "failure"]
    burst = _cluster_threshold(
        failures,
        lambda event: tuple(value for value in (_host(event), _account(event), _source_ip(event)) if value is not None)
        if all((_host(event), _account(event), _source_ip(event))) else None,
        threshold=5, window_seconds=300, cooldown_seconds=600,
        reason="ssh-failure-threshold",
        explanation=(
            "Five SSH authentication failures occurred for the same host, account "
            "and source IP within five minutes."
        ),
    )
    normalized = [FindingSeed(item.events, {
        "hostname": item.group["key_1"], "username": item.group["key_2"], "source_ip": item.group["key_3"],
    }, item.explanation, item.reason, item.threshold, ("T1110.001",)) for item in burst]
    return normalized + _failure_success(ssh, windows=False)


def _sudo_risk(text: str, outcome: str | None) -> str | None:
    if outcome == "failure" or any(marker in text for marker in ("not in the sudoers", "incorrect password", "authentication failure")):
        return "authorization-failure"
    patterns = (
        ("account-change", r"\b(useradd|userdel|usermod|groupadd|groupdel|passwd)\b"),
        ("root-shell", r"\b(bash|sh|zsh|dash|fish)\b(?:\s+-[cil]|\s*$)"),
        ("persistence", r"\b(crontab|systemctl\s+(?:enable|mask)|update-rc\.d)\b"),
        ("defense-impairment", r"\b(systemctl\s+(?:stop|disable)\s+(?:auditd|wazuh|falco)|setenforce\s+0|ufw\s+disable|iptables\s+-f)\b"),
        ("sensitive-permission-change", r"\b(chmod\s+(?:777|[ugo]*\+s)|chown\s+root|visudo)\b"),
    )
    return next((label for label, pattern in patterns if re.search(pattern, text, re.I)), None)


def _det008(events: Sequence[DetectionEvent], spec: RuleSpec) -> list[FindingSeed]:
    result: list[FindingSeed] = []
    seen: set[tuple[str, str, str, int]] = set()
    for event in events:
        if event.category != "linux_sudo":
            continue
        risk = _sudo_risk(_text(event), event.outcome)
        if risk is None:
            continue
        host, user = _host(event) or "unknown", _account(event) or "unknown"
        bucket = int(event.timestamp.timestamp()) // spec.window_seconds
        key = host, user, risk, bucket
        if key in seen:
            continue
        seen.add(key)
        result.append(FindingSeed(
            events=(event,), group={"hostname": host, "username": user, "risk_category": risk},
            explanation=f"Sudo activity met the scoped '{risk}' condition; routine sudo activity is excluded.",
            reason="sudo:" + risk, threshold=1,
        ))
    return result


def _defender_key(event: DetectionEvent) -> tuple[str, str, str]:
    return (
        _host(event) or "unknown",
        (_first(event, "data.win.eventdata.threatName", "data.win.eventdata.threatID") or "unknown-threat").casefold(),
        (_first(event, "data.win.eventdata.path") or "unknown-path").casefold(),
    )


def _det009(
    events: Sequence[DetectionEvent], *, evaluation_end: datetime, spec: RuleSpec,
) -> list[FindingSeed]:
    defender = [event for event in events if event.event_code in {"1116", "1117", "1118", "1119", "5001", "5007"}]
    detections: dict[tuple[str, str, str], list[DetectionEvent]] = defaultdict(list)
    remediated: dict[tuple[str, str, str], list[DetectionEvent]] = defaultdict(list)
    result: list[FindingSeed] = []
    seen: set[tuple[tuple[str, str, str], str, int]] = set()
    for event in defender:
        key = _defender_key(event)
        if event.event_code == "1116":
            detections[key].append(event)
            recent = [
                item for item in detections[key]
                if event.timestamp - item.timestamp <= timedelta(seconds=spec.window_seconds)
            ]
            if len(recent) >= 2:
                marker = key, "repeated-detection", int(event.timestamp.timestamp()) // spec.window_seconds
                if marker not in seen:
                    seen.add(marker)
                    result.append(FindingSeed(
                        events=tuple(recent), group={"hostname": key[0], "threat": key[1], "path": key[2]},
                        explanation="Microsoft Defender reported the same threat/path more than once within one hour.",
                        reason="repeated-detection", threshold=2,
                    ))
        elif event.event_code == "1117":
            remediated[key].append(event)
        elif event.event_code in {"1118", "1119"}:
            prior = [item for item in detections.get(key, []) if item.timestamp <= event.timestamp]
            evidence = tuple((prior[-1:] + [event]) if prior else [event])
            result.append(FindingSeed(
                events=evidence, group={"hostname": key[0], "threat": key[1], "path": key[2]},
                explanation="Microsoft Defender reported a remediation failure.",
                reason="remediation-failure", threshold=1,
            ))
        elif event.event_code == "5001" or (
            event.event_code == "5007"
            and any(term in _text(event) for term in ("disable", "exclusion", "realtime", "real-time", "tamper"))
        ):
            result.append(FindingSeed(
                events=(event,), group={"hostname": key[0], "threat": key[1], "path": key[2]},
                explanation="Microsoft Defender protection was disabled or a configuration change explicitly referenced an impairment/exclusion condition.",
                reason="defense-impairment", threshold=1,
            ))
    for key, detected in detections.items():
        for event in detected:
            deadline = event.timestamp + timedelta(minutes=15)
            successful = any(event.timestamp <= item.timestamp <= deadline for item in remediated.get(key, []))
            if evaluation_end >= deadline and not successful:
                marker = key, "unresolved-detection", int(event.timestamp.timestamp()) // spec.window_seconds
                if marker in seen:
                    continue
                seen.add(marker)
                result.append(FindingSeed(
                    events=(event,), group={"hostname": key[0], "threat": key[1], "path": key[2]},
                    explanation="A Defender detection remained without successful remediation for at least fifteen minutes in the evaluated evidence.",
                    reason="unresolved-detection", threshold=1,
                ))
    return result


EVALUATORS: Mapping[str, Callable[[Sequence[DetectionEvent], RuleSpec], list[FindingSeed]]] = {
    "DET-001": _det001, "DET-002": _det002, "DET-003": _det003,
    "DET-004": _det004, "DET-005": _det005, "DET-006": _det006,
    "DET-007": _det007, "DET-008": _det008,
}


def configured_rule_spec(
    spec: RuleSpec, profile: Mapping[str, Any] | None = None,
) -> RuleSpec:
    """Apply a validated declarative profile without changing rule semantics."""

    if not profile:
        return spec
    threshold = int(profile.get("threshold_count", spec.threshold))
    window = int(profile.get("time_window_seconds", spec.window_seconds))
    severity = int(profile.get("severity", spec.severity))
    if not 1 <= threshold <= 100 or not 30 <= window <= 86_400 or not 0 <= severity <= 16:
        raise ValueError("Advanced detection profile is outside supported safety bounds")
    return replace(spec, threshold=threshold, window_seconds=window, severity=severity)


def _required_value(event: DetectionEvent, field: str) -> bool:
    values: Mapping[str, Any] = {
        "hostname": _host(event), "username": _account(event), "source_ip": _source_ip(event),
        "logon_type": _logon_type(event), "logon_id": _logon_id(event), "event_code": event.event_code,
        "command_or_script": _text(event).strip(),
        "command_or_failure": _text(event).strip() or event.outcome == "failure",
        "account_or_group_context": _first(event, "data.win.eventdata.targetUserName", "data.win.eventdata.targetGroupName", "data.win.eventdata.targetSid"),
        "service_metadata": _first(event, "data.win.eventdata.serviceName", "data.win.eventdata.imagePath"),
        "defender_threat_context": _first(event, "data.win.eventdata.threatName", "data.win.eventdata.threatID", "data.win.eventdata.path") or event.event_code in {"5001", "5007"},
    }
    return bool(values.get(field))


def _availability(spec: RuleSpec, events: Sequence[DetectionEvent], *, end: datetime) -> AdvancedDetectionAvailability:
    observed = [event for event in events if _eligible_source(event, spec)]
    missing = [field for field in spec.required_fields if not any(_required_value(event, field) for event in observed)]
    complete_record = any(
        all(_required_value(event, field) for field in spec.required_fields)
        for event in observed
    )
    if observed and spec.required_fields and not complete_record and not missing:
        missing.append("co-located_required_fields")
    latest = max((event.timestamp for event in observed), default=None)
    recent = latest is not None and latest >= end - timedelta(hours=24)
    if not observed:
        status, explanation = "NO_DATA", "No events satisfying the rule's source/event prerequisite were observed in the selected range."
    elif missing:
        status, explanation = "PREREQUISITE_MISSING", "Telemetry was observed, but required correlation fields are absent from all eligible events."
    elif recent:
        status, explanation = "RECENTLY_OBSERVED", "Eligible telemetry and required fields were observed in the most recent 24 hours of the selected range."
    else:
        status, explanation = "OBSERVED_STALE", "Eligible telemetry was observed, but not in the most recent 24 hours of the selected range."
    return AdvancedDetectionAvailability(
        parser_supported=True, data_observed=bool(observed), recently_observed=recent,
        configuration_status="UNKNOWN", status=status, observed_event_count=len(observed),
        latest_event_at=latest, missing_required_fields=missing,
        explanation=explanation + " Live collector configuration is not inferred from stored data.",
    )


def _public_rule(spec: RuleSpec, availability: AdvancedDetectionAvailability | None = None) -> AdvancedDetectionRule:
    mappings = [
        AdvancedMitreMapping(
            technique_id=technique_id,
            technique_name=MITRE_TECHNIQUES[technique_id][0],
            tactic=MITRE_TECHNIQUES[technique_id][1],
            relationship=MITRE_RELATIONSHIPS[spec.rule_id][technique_id],
        )
        for technique_id in spec.mitre_ids
    ]
    return AdvancedDetectionRule(
        rule_id=spec.rule_id, name=spec.name, description=spec.description,
        severity=spec.severity,
        prerequisites=AdvancedDetectionPrerequisite(
            source_types=list(spec.source_types), event_codes=list(spec.event_codes),
            event_categories=list(spec.event_categories), required_fields=list(spec.required_fields),
            parser_supported=True, configuration_status="UNKNOWN",
            configuration_evidence="No authoritative live collector/configuration API is queried by M11 dry-run.",
        ),
        conditions=list(spec.conditions), grouping_fields=list(spec.grouping_fields),
        window_seconds=spec.window_seconds, threshold=spec.threshold,
        deduplication=spec.deduplication, mitre_ids=list(spec.mitre_ids),
        mitre_mappings=mappings,
        false_positive_notes=list(spec.false_positive_notes), evidence_fields=list(spec.evidence_fields),
        analyst_guidance=list(spec.analyst_guidance), version="1.0.0-m11",
        validation_status="VALIDATED_FOR_DRY_RUN",
        validation_notes=list(spec.validation_notes), availability=availability,
    )


def _finding(spec: RuleSpec, seed: FindingSeed) -> AdvancedDetectionFinding:
    unique: dict[str, DetectionEvent] = {event.event_id: event for event in seed.events}
    events = sorted(unique.values(), key=lambda item: (item.timestamp, item.event_id))
    bucket = int(events[0].timestamp.timestamp()) // spec.window_seconds
    material = json.dumps(
        {"rule": spec.rule_id, "group": dict(sorted(seed.group.items())), "reason": seed.reason, "bucket": bucket},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest().upper()
    evidence = [AdvancedDetectionEvidence(
        event_id=event.event_id, timestamp=event.timestamp,
        summary=(
            f"{event.event_code or event.category or event.source_type} on "
            f"{event.hostname or 'unknown host'}; outcome={event.outcome or 'unknown'}"
        ),
    ) for event in events[:25]]
    return AdvancedDetectionFinding(
        finding_id=f"FND-{digest[:24]}", rule_id=spec.rule_id, severity=spec.severity,
        first_event_at=events[0].timestamp, last_event_at=events[-1].timestamp,
        group={key: _clean(value) for key, value in seed.group.items()},
        matched_event_count=len(events), threshold=seed.threshold or spec.threshold,
        event_ids=[event.event_id for event in events], explanation=seed.explanation,
        evidence=evidence, deduplication_key=digest,
        mitre_ids=list(spec.mitre_ids if seed.mitre_ids is None else seed.mitre_ids),
    )


class AdvancedDetectionEngine:
    """Read-only catalog and bounded deterministic evaluation facade."""

    def __init__(self, database_path: Path) -> None:
        self.path = database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def _event(row: sqlite3.Row) -> DetectionEvent:
        try:
            raw = json.loads(row["raw_event_json"])
        except (TypeError, json.JSONDecodeError):
            raw = {}
        if not isinstance(raw, Mapping):
            raw = {}
        timestamp = datetime.fromisoformat(row["occurred_at"])
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return DetectionEvent(
            event_id=str(row["event_id"]), timestamp=timestamp.astimezone(timezone.utc),
            source_type=str(row["source_type"]), hostname=row["hostname"], username=row["username"],
            source_ip=row["source_ip"], event_code=row["event_code"], category=row["event_category"],
            action=row["event_action"], outcome=row["outcome"], process_name=row["process_name"],
            process_path=row["process_path"], command_line=row["command_line"],
            parent_process_name=row["parent_process_name"], message=str(row["message"]), raw=raw,
        )

    def _events(
        self, start: datetime, end: datetime, limit: int, *, deadline: float | None = None
    ) -> list[DetectionEvent]:
        with closing(self._connect()) as connection:
            if deadline is not None:
                connection.set_progress_handler(
                    lambda: 1 if time.perf_counter() >= deadline else 0, 1000
                )
            try:
                rows = connection.execute(
                    """
                    WITH bounded AS (
                        SELECT event_id, occurred_at, source_type, hostname, username, source_ip,
                               event_code, event_category, event_action, outcome, process_name,
                               process_path, command_line, parent_process_name, message, raw_event_json
                        FROM security_events
                        WHERE occurred_at BETWEEN ? AND ?
                        ORDER BY occurred_at DESC, event_id DESC
                        LIMIT ?
                    )
                    SELECT * FROM bounded ORDER BY occurred_at ASC, event_id ASC
                    """,
                    (start.isoformat(), end.isoformat(), limit),
                ).fetchall()
            except sqlite3.OperationalError as exc:
                if "interrupted" in str(exc).casefold():
                    raise AdvancedDetectionEvaluationLimitError(
                        "Advanced detection evaluation exceeded its time budget"
                    ) from exc
                raise
            finally:
                connection.set_progress_handler(None, 0)
        return [self._event(row) for row in rows]

    def load_events(
        self, start: datetime, end: datetime, limit: int, *, deadline: float | None = None
    ) -> list[DetectionEvent]:
        """Load a bounded, event-time ordered input set for isolated evaluators."""

        if not 1 <= limit <= 5_000:
            raise ValueError("event limit must be between 1 and 5000")
        if start > end or end - start > timedelta(days=31):
            raise ValueError("evaluation window is invalid or exceeds 31 days")
        return self._events(start, end, limit, deadline=deadline)

    def load_rule_events(
        self,
        rule_id: str,
        start: datetime,
        end: datetime,
        limit: int,
        *,
        deadline: float | None = None,
    ) -> list[DetectionEvent]:
        """Load a bounded rule-prerequisite slice without a global newest-event bias."""

        spec = RULE_BY_ID.get(rule_id.upper())
        if spec is None:
            raise KeyError(rule_id)
        if not 1 <= limit <= 5_000:
            raise ValueError("event limit must be between 1 and 5000")
        if start > end or end - start > timedelta(days=31):
            raise ValueError("evaluation window is invalid or exceeds 31 days")
        source_marks = ",".join("?" for _ in spec.source_types)
        prerequisites: list[str] = []
        parameters: list[object] = [start.isoformat(), end.isoformat(), *spec.source_types]
        if spec.event_codes:
            prerequisites.append(
                "event_code IN (" + ",".join("?" for _ in spec.event_codes) + ")"
            )
            parameters.extend(spec.event_codes)
        elif spec.event_categories:
            prerequisites.append(
                "event_category IN ("
                + ",".join("?" for _ in spec.event_categories)
                + ")"
            )
            parameters.extend(spec.event_categories)
        predicate = " AND (" + " OR ".join(prerequisites) + ")" if prerequisites else ""
        parameters.append(limit)
        with closing(self._connect()) as connection:
            if deadline is not None:
                connection.set_progress_handler(
                    lambda: 1 if time.perf_counter() >= deadline else 0, 1000
                )
            try:
                rows = connection.execute(
                    f"""
                    WITH bounded AS (
                        SELECT event_id, occurred_at, source_type, hostname, username, source_ip,
                               event_code, event_category, event_action, outcome, process_name,
                               process_path, command_line, parent_process_name, message, raw_event_json
                        FROM security_events
                        WHERE occurred_at BETWEEN ? AND ?
                          AND source_type IN ({source_marks}){predicate}
                        ORDER BY occurred_at DESC, event_id DESC
                        LIMIT ?
                    )
                    SELECT * FROM bounded ORDER BY occurred_at ASC, event_id ASC
                    """,
                    parameters,
                ).fetchall()
            except sqlite3.OperationalError as exc:
                if "interrupted" in str(exc).casefold():
                    raise AdvancedDetectionEvaluationLimitError(
                        "Telemetry evidence query exceeded its time budget"
                    ) from exc
                raise
            finally:
                connection.set_progress_handler(None, 0)
        return [self._event(row) for row in rows]

    @staticmethod
    def evaluate_events(
        rule_id: str,
        events: Sequence[DetectionEvent],
        *,
        evaluation_end: datetime,
        max_findings: int,
        profile: Mapping[str, Any] | None = None,
    ) -> tuple[RuleSpec, AdvancedDetectionAvailability, list[AdvancedDetectionFinding], int]:
        """Run the shared M11 evaluator over caller-supplied isolated state."""

        base_spec = RULE_BY_ID.get(rule_id.upper())
        if base_spec is None:
            raise KeyError(rule_id)
        if not 1 <= max_findings <= 500:
            raise ValueError("finding limit must be between 1 and 500")
        spec = configured_rule_spec(base_spec, profile)
        ordered_by_id: dict[str, DetectionEvent] = {}
        duplicate_count = 0
        for event in sorted(events, key=lambda item: (item.timestamp, item.event_id)):
            if event.event_id in ordered_by_id:
                duplicate_count += 1
                continue
            ordered_by_id[event.event_id] = event
        ordered = list(ordered_by_id.values())
        eligible = [event for event in ordered if _eligible_source(event, spec)]
        if spec.rule_id == "DET-009":
            seeds = _det009(eligible, evaluation_end=evaluation_end, spec=spec)
        else:
            seeds = EVALUATORS[spec.rule_id](eligible, spec)
        findings_by_key: dict[str, AdvancedDetectionFinding] = {}
        for seed in seeds:
            item = _finding(spec, seed)
            if item.deduplication_key in findings_by_key:
                duplicate_count += 1
            findings_by_key.setdefault(item.deduplication_key, item)
        findings = sorted(
            findings_by_key.values(), key=lambda item: (item.first_event_at, item.finding_id)
        )
        return spec, _availability(spec, ordered, end=evaluation_end), findings[:max_findings], duplicate_count

    def catalog(self, *, days: int = 30) -> list[AdvancedDetectionRule]:
        if not 1 <= days <= 31:
            raise ValueError("days must be between 1 and 31")
        end = datetime.now(timezone.utc)
        events = self._events(end - timedelta(days=days), end, 1000, deadline=time.perf_counter() + 2.0)
        return [_public_rule(spec, _availability(spec, events, end=end)) for spec in RULES]

    def rule(self, rule_id: str) -> AdvancedDetectionRule:
        spec = RULE_BY_ID.get(rule_id.upper())
        if spec is None:
            raise KeyError(rule_id)
        end = datetime.now(timezone.utc)
        events = self._events(end - timedelta(days=30), end, 1000, deadline=time.perf_counter() + 2.0)
        return _public_rule(spec, _availability(spec, events, end=end))

    def evaluate(
        self,
        rule_id: str,
        payload: AdvancedRuleDryRunRequest,
        *,
        profile: Mapping[str, Any] | None = None,
    ) -> AdvancedRuleDryRunResult:
        """Evaluate the shared M11 semantics without creating alerts or incidents."""
        base_spec = RULE_BY_ID.get(rule_id.upper())
        if base_spec is None:
            raise KeyError(rule_id)
        spec = configured_rule_spec(base_spec, profile)
        start, end = payload.resolved()
        started = time.perf_counter()
        deadline = started + payload.max_execution_ms / 1000
        events = self._events(start, end, payload.max_events, deadline=deadline)
        _, availability, all_findings, _ = self.evaluate_events(
            rule_id,
            events,
            evaluation_end=end,
            max_findings=500,
            profile=profile,
        )
        if time.perf_counter() >= deadline:
            raise AdvancedDetectionEvaluationLimitError(
                "Advanced detection evaluation exceeded its time budget"
            )
        findings = all_findings[:payload.max_findings]
        execution_ms = max(0.0, (time.perf_counter() - started) * 1000)
        return AdvancedRuleDryRunResult(
            rule=_public_rule(spec, availability), availability=availability,
            start_time=start, end_time=end, evaluated_event_count=len(events),
            finding_count=len(all_findings), findings=findings, execution_ms=execution_ms,
            execution_budget_ms=payload.max_execution_ms,
            result_truncated=len(all_findings) > len(findings),
        )
