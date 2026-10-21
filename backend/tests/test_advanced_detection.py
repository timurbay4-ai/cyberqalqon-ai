from __future__ import annotations

from datetime import datetime, timedelta, timezone
import sqlite3

from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from app.schemas.auth import AnalystCreate, AnalystRole
from app.schemas.detection_engineering import AdvancedDetectionRule
from tests.conftest import TEST_ORIGIN, TEST_PASSWORD


def _windows(
    code: str,
    timestamp: datetime,
    suffix: str,
    eventdata: dict[str, str],
    *,
    provider: str = "Microsoft-Windows-Security-Auditing",
    channel: str = "Security",
) -> dict:
    return {
        "timestamp": timestamp.isoformat(),
        "id": f"m11-win-{code}-{suffix}",
        "agent": {"id": "002", "name": "WIN-M11-LAB"},
        "manager": {"name": "lab-manager"},
        "decoder": {"name": "windows_eventchannel"},
        "rule": {"id": f"60{code}", "level": 5, "description": f"Synthetic {code}"},
        "data": {
            "win": {
                "system": {
                    "providerName": provider,
                    "eventID": code,
                    "channel": channel,
                    "computer": "WIN-M11-LAB",
                    "message": f"Synthetic M11 event {code}",
                },
                "eventdata": eventdata,
            }
        },
    }


def _linux(
    timestamp: datetime,
    suffix: str,
    *,
    decoder: str,
    full_log: str,
    username: str,
    source_ip: str | None,
    outcome: str,
) -> dict:
    data: dict[str, str] = {"user": username, "outcome": outcome}
    if source_ip is not None:
        data["srcip"] = source_ip
    return {
        "timestamp": timestamp.isoformat(),
        "id": f"m11-linux-{suffix}",
        "agent": {"id": "001", "name": "linux-m11-lab"},
        "decoder": {"name": decoder},
        "rule": {"id": "5700", "level": 5, "description": "Synthetic Linux auth", "groups": [decoder]},
        "data": data,
        "location": f"/var/log/{'auth.log' if decoder == 'sshd' else 'secure'}",
        "full_log": full_log,
    }


def _ingest(client: TestClient, *events: dict) -> None:
    for event in events:
        response = client.post(
            "/api/v1/events/ingest",
            headers={"X-API-Key": "test-ingest-key"},
            json=event,
        )
        assert response.status_code in {200, 201}, response.text


def _run(client: TestClient, rule_id: str, *, minutes: int = 1440) -> dict:
    response = client.post(
        f"/api/v1/detection-engineering/advanced-rules/{rule_id}/dry-run",
        json={"relative_minutes": minutes, "max_events": 1000, "max_findings": 100},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _logon(user: str, source: str, logon_type: str = "3", logon_id: str = "0x123") -> dict[str, str]:
    return {
        "targetUserName": user,
        "targetDomainName": "LAB",
        "ipAddress": source,
        "logonType": logon_type,
        "targetLogonId": logon_id,
        "status": "0xc000006d",
        "subStatus": "0xc000006a",
    }


def test_advanced_catalog_is_complete_disabled_and_coverage_gated(client: TestClient) -> None:
    response = client.get("/api/v1/detection-engineering/advanced-rules")
    assert response.status_code == 200
    rules = response.json()
    assert [item["rule_id"] for item in rules] == [f"DET-{index:03d}" for index in range(1, 10)]
    assert all(item["enabled"] is False for item in rules)
    assert all(item["activation_state"] == "DISABLED_BY_POLICY" for item in rules)
    assert all(item["validation_status"] == "VALIDATED_FOR_DRY_RUN" for item in rules)
    assert all(item["prerequisites"]["configuration_status"] == "UNKNOWN" for item in rules)
    assert all(item["availability"]["status"] == "NO_DATA" for item in rules)
    assert all(item["conditions"] and item["false_positive_notes"] for item in rules)
    assert all(len(item["mitre_ids"]) == len(item["mitre_mappings"]) for item in rules)
    with pytest.raises(ValidationError):
        AdvancedDetectionRule.model_validate({**rules[0], "threshold": 0})
    over_budget = client.post(
        "/api/v1/detection-engineering/advanced-rules/DET-001/dry-run",
        json={"relative_minutes": 1440, "max_events": 1000, "max_findings": 100,
              "max_execution_ms": 5001},
    )
    assert over_budget.status_code == 422


def test_det001_threshold_boundary_missing_source_and_deduplication(
    client: TestClient, database_path
) -> None:
    base = datetime.now(timezone.utc) - timedelta(minutes=20)
    events = [
        _windows("4625", base + timedelta(seconds=index * 60), str(index), _logon("alice", "192.0.2.10"))
        for index in range(4)
    ]
    events.extend(
        _windows("4625", base + timedelta(seconds=index), f"missing-{index}", _logon("bob", "-"))
        for index in range(5)
    )
    missing_user = _logon("", "192.0.2.10")
    events.extend(
        _windows("4625", base + timedelta(seconds=index), f"missing-user-{index}", missing_user)
        for index in range(5)
    )
    cross_host = _windows("4625", base + timedelta(seconds=200), "cross-host", _logon("alice", "192.0.2.10"))
    cross_host["data"]["win"]["system"]["computer"] = "WIN-OTHER-HOST"
    cross_account = _windows("4625", base + timedelta(seconds=210), "cross-account", _logon("eve", "192.0.2.10"))
    events.extend([cross_host, cross_account])
    _ingest(client, *events)
    assert _run(client, "DET-001")["finding_count"] == 0
    fifth = _windows("4625", base + timedelta(seconds=240), "4", _logon("alice", "192.0.2.10"))
    _ingest(client, fifth, fifth)
    with sqlite3.connect(database_path) as connection:
        before = tuple(connection.execute(
            "SELECT (SELECT COUNT(*) FROM alerts), (SELECT COUNT(*) FROM incidents), "
            "(SELECT COUNT(*) FROM soc_cases), (SELECT COUNT(*) FROM analyst_notifications)"
        ).fetchone())
    result = _run(client, "DET-001")
    repeated = _run(client, "DET-001")
    assert result["finding_count"] == 1
    assert result["findings"][0]["matched_event_count"] == 5
    assert result["findings"][0]["group"]["source_ip_or_local"] == "192.0.2.10"
    assert result["side_effects"] is False
    assert result["findings"] == repeated["findings"]
    assert result["execution_budget_ms"] == 1000
    with sqlite3.connect(database_path) as connection:
        after = tuple(connection.execute(
            "SELECT (SELECT COUNT(*) FROM alerts), (SELECT COUNT(*) FROM incidents), "
            "(SELECT COUNT(*) FROM soc_cases), (SELECT COUNT(*) FROM analyst_notifications)"
        ).fetchone())
        audit_count = connection.execute(
            "SELECT COUNT(*) FROM security_audit_events WHERE action = 'ADVANCED_DETECTION_DRY_RUN'"
        ).fetchone()[0]
    assert after == before
    assert audit_count >= 2


def test_det002_is_ordered_event_time_correlation_and_not_ingest_order(client: TestClient) -> None:
    base = datetime.now(timezone.utc) - timedelta(minutes=15)
    success = _windows("4624", base + timedelta(minutes=3), "success", _logon("carol", "198.51.100.8"))
    failures = [
        _windows("4625", base + timedelta(minutes=index), f"failure-{index}", _logon("carol", "198.51.100.8"))
        for index in range(3)
    ]
    expired = [
        _windows("4625", base + timedelta(seconds=index), f"expired-{index}", _logon("dave", "203.0.113.40"))
        for index in range(3)
    ]
    expired_success = _windows(
        "4624", base + timedelta(seconds=601), "expired-success", _logon("dave", "203.0.113.40")
    )
    _ingest(client, success, *reversed(failures), *expired, expired_success)
    result = _run(client, "DET-002")
    assert result["finding_count"] == 1
    finding = result["findings"][0]
    assert finding["matched_event_count"] == 4
    assert finding["group"]["username"] == "carol"
    assert finding["event_ids"][-1] != finding["event_ids"][0]
    assert "successful logon followed three failures" in finding["explanation"]


def test_det003_requires_correlated_remote_human_privileged_session(client: TestClient) -> None:
    base = datetime.now(timezone.utc) - timedelta(minutes=10)
    logon = _windows("4624", base, "remote", _logon("admin-user", "203.0.113.9", "10", "0x777"))
    privileged = _windows("4672", base + timedelta(seconds=30), "priv", {
        "subjectUserName": "admin-user", "subjectLogonId": "0x777",
    })
    local_system = _windows("4672", base + timedelta(seconds=40), "system", {
        "subjectUserName": "SYSTEM", "subjectLogonId": "0x888",
    })
    _ingest(client, privileged, local_system, logon)
    result = _run(client, "DET-003")
    assert result["finding_count"] == 1
    assert result["findings"][0]["group"]["logon_id"] == "0x777"


def test_det004_scopes_group_membership_to_privileged_groups(client: TestClient) -> None:
    base = datetime.now(timezone.utc) - timedelta(minutes=10)
    created = _windows("4720", base, "create", {
        "subjectUserName": "operator", "targetUserName": "new-user",
    })
    ordinary = _windows("4732", base + timedelta(seconds=20), "ordinary", {
        "subjectUserName": "operator", "memberName": "new-user", "targetGroupName": "Print Operators",
    })
    privileged = _windows("4732", base + timedelta(seconds=40), "admin", {
        "subjectUserName": "operator", "memberName": "new-user", "targetGroupName": "Administrators",
        "targetSid": "S-1-5-32-544",
    })
    _ingest(client, created, ordinary, privileged)
    result = _run(client, "DET-004")
    assert result["finding_count"] == 2
    assert {item["group"]["event_code"] for item in result["findings"]} == {"4720", "4732"}


def test_det005_ignores_ordinary_powershell_and_redacts_finding_summary(client: TestClient) -> None:
    base = datetime.now(timezone.utc) - timedelta(minutes=10)
    ordinary = _windows("4104", base, "ordinary", {"scriptBlockText": "Get-Process"},
                        provider="Microsoft-Windows-PowerShell", channel="Microsoft-Windows-PowerShell/Operational")
    suspicious = _windows("4104", base + timedelta(seconds=10), "encoded", {
        "scriptBlockText": "powershell.exe -EncodedCommand U1lOVEhFVElDLU5PVC1TRUNSRVQ=",
    }, provider="Microsoft-Windows-PowerShell", channel="Microsoft-Windows-PowerShell/Operational")
    _ingest(client, ordinary, suspicious)
    result = _run(client, "DET-005")
    assert result["finding_count"] == 1
    serialized = str(result["findings"][0])
    assert "U1lOVEhFVElDLU5PVC1TRUNSRVQ=" not in serialized
    assert "encoded-command" in result["findings"][0]["explanation"]


def test_det006_requires_high_risk_service_metadata(client: TestClient) -> None:
    base = datetime.now(timezone.utc) - timedelta(minutes=10)
    benign = _windows("7045", base, "benign", {
        "serviceName": "ApprovedAgent", "imagePath": "C:\\Program Files\\Approved\\agent.exe",
        "startType": "demand start", "accountName": "LocalSystem",
    }, provider="Service Control Manager", channel="System")
    suspicious = _windows("7045", base + timedelta(seconds=30), "suspicious", {
        "serviceName": "Updater", "imagePath": "C:\\Windows\\System32\\cmd.exe /c C:\\Users\\Public\\update.cmd",
        "startType": "auto start", "accountName": "LocalSystem",
    }, provider="Service Control Manager", channel="System")
    _ingest(client, benign, suspicious)
    result = _run(client, "DET-006")
    assert result["finding_count"] == 1
    assert result["findings"][0]["group"]["service_name"] == "Updater"


def test_det007_handles_ssh_threshold_and_failure_success_separately(client: TestClient) -> None:
    base = datetime.now(timezone.utc) - timedelta(minutes=20)
    burst = [
        _linux(base + timedelta(seconds=index * 30), f"burst-{index}", decoder="sshd",
               full_log=f"Failed password for alice from 192.0.2.70 port {2200 + index}",
               username="alice", source_ip="192.0.2.70", outcome="failure")
        for index in range(5)
    ]
    sequence = [
        _linux(base + timedelta(minutes=10, seconds=index * 30), f"seq-{index}", decoder="sshd",
               full_log=f"Failed password for bob from 198.51.100.70 port {2300 + index}",
               username="bob", source_ip="198.51.100.70", outcome="failure")
        for index in range(3)
    ]
    sequence.append(_linux(base + timedelta(minutes=12), "seq-success", decoder="sshd",
                           full_log="Accepted password for bob from 198.51.100.70 port 2400",
                           username="bob", source_ip="198.51.100.70", outcome="success"))
    _ingest(client, *(burst + sequence))
    result = _run(client, "DET-007")
    assert result["finding_count"] == 2
    explanations = " ".join(item["explanation"] for item in result["findings"])
    assert "Five SSH" in explanations
    assert "success followed three failures" in explanations


def test_det008_ignores_routine_sudo_and_matches_scoped_risk(client: TestClient) -> None:
    base = datetime.now(timezone.utc) - timedelta(minutes=10)
    routine = _linux(base, "sudo-routine", decoder="sudo",
                     full_log="alice : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/systemctl status nginx",
                     username="alice", source_ip=None, outcome="success")
    shell = _linux(base + timedelta(seconds=10), "sudo-shell", decoder="sudo",
                   full_log="alice : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash -i",
                   username="alice", source_ip=None, outcome="success")
    denied = _linux(base + timedelta(seconds=20), "sudo-denied", decoder="sudo",
                    full_log="mallory is not in the sudoers file",
                    username="mallory", source_ip=None, outcome="failure")
    _ingest(client, routine, shell, denied)
    result = _run(client, "DET-008")
    assert result["finding_count"] == 2
    assert {item["group"]["risk_category"] for item in result["findings"]} == {
        "root-shell", "authorization-failure",
    }


def test_det009_correlates_remediation_and_protection_state_without_broad_5007(client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    detection = _windows("1116", now - timedelta(minutes=30), "remediated-detect", {
        "threatName": "Synthetic:Remediated", "path": "file:_C:\\remediated.txt",
    }, provider="Microsoft-Windows-Windows Defender", channel="Microsoft-Windows-Windows Defender/Operational")
    remediated = _windows("1117", now - timedelta(minutes=28), "remediated", {
        "threatName": "Synthetic:Remediated", "path": "file:_C:\\remediated.txt",
    }, provider="Microsoft-Windows-Windows Defender", channel="Microsoft-Windows-Windows Defender/Operational")
    unresolved = _windows("1116", now - timedelta(minutes=25), "unresolved", {
        "threatName": "Synthetic:Unresolved", "path": "file:_C:\\unresolved.txt",
    }, provider="Microsoft-Windows-Windows Defender", channel="Microsoft-Windows-Windows Defender/Operational")
    generic_change = _windows("5007", now - timedelta(minutes=5), "generic", {"configuration": "EngineVersion=1"},
                              provider="Microsoft-Windows-Windows Defender", channel="Microsoft-Windows-Windows Defender/Operational")
    disabled = _windows("5001", now - timedelta(minutes=4), "disabled", {},
                        provider="Microsoft-Windows-Windows Defender", channel="Microsoft-Windows-Windows Defender/Operational")
    _ingest(client, detection, remediated, unresolved, generic_change, disabled)
    result = _run(client, "DET-009")
    assert result["finding_count"] == 2
    explanations = " ".join(item["explanation"] for item in result["findings"])
    assert "without successful remediation" in explanations
    assert "protection was disabled" in explanations
    assert "Synthetic:Remediated" not in explanations
    assert result["rule"]["mitre_ids"] == []


def test_advanced_dry_run_is_rbac_protected_and_has_no_detection_side_effects(
    client: TestClient, database_path
) -> None:
    before = client.get("/api/v1/detection-engineering/advanced-rules/DET-001")
    assert before.status_code == 200
    client.app.state.auth_repository.create_analyst(AnalystCreate(
        username="m11-viewer", display_name="M11 Viewer", password=TEST_PASSWORD, role=AnalystRole.VIEWER,
    ))
    client.cookies.clear()
    login = client.post(
        "/api/v1/auth/login", headers={"Origin": TEST_ORIGIN},
        json={"username": "m11-viewer", "password": TEST_PASSWORD},
    )
    client.headers.update({"Origin": TEST_ORIGIN, "X-CSRF-Token": login.json()["csrf_token"]})
    assert client.get("/api/v1/detection-engineering/advanced-rules").status_code == 200
    denied = client.post(
        "/api/v1/detection-engineering/advanced-rules/DET-001/dry-run",
        json={"relative_minutes": 1440, "max_events": 1000, "max_findings": 100},
    )
    assert denied.status_code == 403
