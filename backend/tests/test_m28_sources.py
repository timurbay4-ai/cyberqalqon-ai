from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from app.core.config import Settings
from app.main import create_app
from app.schemas.auth import AnalystCreate, AnalystRole

from app.services.event_normalizer import EventNormalizationError, normalize_wazuh_event
from app.services.source_adapters import SourceContext
from app.services.wazuh_normalizer import canonical_json


spec = importlib.util.spec_from_file_location("m28_synthetic", Path(__file__).parents[2] / "scripts/m28_synthetic.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


@pytest.fixture
def client(database_path):
    settings = Settings(database_url=f"sqlite:///{database_path.as_posix()}",
                        wazuh_ingest_api_key="test-ingest-key", allow_m14_schema_migration=False)
    with TestClient(create_app(settings)) as test_client:
        test_client.app.state.auth_repository.bootstrap_first_admin(AnalystCreate(
            username="m28-synthetic-admin", display_name="M28 Synthetic Admin",
            password="Synthetic-M28-Only-928!", role=AnalystRole.ADMIN))
        login = test_client.post("/api/v1/auth/login", headers={"Origin": "http://localhost:5173"},
            json={"username": "m28-synthetic-admin", "password": "Synthetic-M28-Only-928!"})
        assert login.status_code == 200
        test_client.headers.update({"Origin": "http://localhost:5173", "X-CSRF-Token": login.json()["csrf_token"]})
        yield test_client


@pytest.mark.parametrize("name,raw,expected", fixtures.cases(), ids=lambda value: value if isinstance(value, str) else None)
def test_golden_source_normalization(name, raw, expected):
    original = copy.deepcopy(raw)
    normalized = normalize_wazuh_event(raw)
    for field, value in expected.items():
        actual = getattr(normalized, field)
        assert (str(actual) if field.endswith("_ip") else actual) == value
    cuse = normalized.structured_payload["_cuse"]
    assert cuse["version"] == "cuse-v1"
    assert cuse["endpoint_identity_verified"] is False
    assert cuse["historical_continuity"] == "UNPROVEN"
    assert cuse["provenance_status"] == "UNKNOWN"
    assert normalized.deduplication_id == hashlib.sha256(canonical_json(raw).encode()).hexdigest()
    assert raw == original


def test_sysmon_attributes_no_automatic_mitre_and_retry_identity():
    raw = fixtures.windows(1, datetime.now(timezone.utc), "22", sysmon=True)
    normalized = normalize_wazuh_event(raw)
    cuse = normalized.structured_payload["_cuse"]
    assert cuse["source_family"] == "SYSMON"
    assert cuse["attributes"]["dns_query_name"] == "synthetic.example.invalid"
    assert cuse["attributes"]["process_guid"].endswith("928}")
    assert normalized.mitre.ids == []
    assert normalize_wazuh_event(copy.deepcopy(raw)).event_id == normalized.event_id
    other_host = copy.deepcopy(raw)
    other_host["agent"]["id"] = "929"
    assert normalize_wazuh_event(other_host).event_id != normalized.event_id
    other_delivery = copy.deepcopy(raw)
    other_delivery["id"] += "-repeat-line"
    assert normalize_wazuh_event(other_delivery).event_id != normalized.event_id


@pytest.mark.parametrize("mutation,code", [
    ("fake_identity", "INVALID_SOURCE_IDENTITY"), ("wrong_sysmon_channel", "INVALID_SOURCE_IDENTITY"),
    ("ambiguous", "AMBIGUOUS_SOURCE"), ("bad_code", "MALFORMED"),
    ("bad_timestamp", "INVALID_TIMESTAMP"), ("naive_timestamp", "INVALID_TIMESTAMP"),
    ("huge", "OVERSIZED"), ("deep", "OVERSIZED"), ("unicode", "MALFORMED"),
])
def test_source_failures_are_bounded_and_do_not_echo_payload(mutation, code):
    raw = fixtures.windows(1, datetime.now(timezone.utc), "3", sysmon=True)
    context = SourceContext()
    if mutation == "fake_identity":
        context = SourceContext(expected_agent_id="some-other-agent")
    elif mutation == "wrong_sysmon_channel":
        raw["data"]["win"]["system"]["channel"] = "Security"
    elif mutation == "ambiguous":
        raw["data"]["journald"] = {"MESSAGE": "sensitive-fixture"}
    elif mutation == "bad_code":
        raw["data"]["win"]["system"]["eventID"] = "sensitive-fixture"
    elif mutation in {"bad_timestamp", "naive_timestamp"}:
        raw["timestamp"] = "sensitive-fixture" if mutation == "bad_timestamp" else "2026-10-22T08:00:00"
    elif mutation == "huge":
        raw["full_log"] = "x" * 262_145
    elif mutation == "deep":
        branch = raw
        for _ in range(30):
            branch["nested"] = {}
            branch = branch["nested"]
    elif mutation == "unicode":
        raw["full_log"] = "\ud800"
    with pytest.raises(EventNormalizationError) as error:
        normalize_wazuh_event(raw, context=context)
    assert error.value.code == code
    assert "sensitive-fixture" not in str(error.value)


def test_missing_provider_unsupported_code_and_untrusted_claims():
    raw = fixtures.windows(1, datetime.now(timezone.utc), "255", sysmon=True)
    raw["data"]["win"]["system"].pop("providerName")
    raw["_cuse"] = {"provenance_status": "VERIFIED", "source_generation": "fake"}
    event = normalize_wazuh_event(raw, context=SourceContext(transport_authenticated=True))
    cuse = event.structured_payload["_cuse"]
    assert cuse["normalization_status"] == "UNSUPPORTED_SOURCE"
    assert cuse["provenance_status"] == "PARTIAL"
    assert cuse["source_generation"] is None
    assert event.event_action is None


def test_sysmon_missing_family_context_is_partial():
    raw = fixtures.windows(1, datetime.now(timezone.utc), "22", sysmon=True)
    raw["data"]["win"]["eventdata"] = {"processId": "1"}
    event = normalize_wazuh_event(raw)
    assert event.structured_payload["_cuse"]["normalization_status"] == "PARTIAL"
    assert "SOURCE_CONTEXT_INCOMPLETE" in event.structured_payload["_cuse"]["warnings"]


def test_decoder_only_legacy_windows_envelope_remains_accepted_without_source_claim():
    raw = fixtures.envelope(1, datetime.now(timezone.utc))
    raw.update(decoder={"name": "windows_eventchannel"}, data={"srcip": "192.0.2.10"})
    event = normalize_wazuh_event(raw)
    cuse = event.structured_payload["_cuse"]
    assert cuse["source_family"] == "WAZUH_GENERIC"
    assert cuse["normalization_status"] == "UNSUPPORTED_SOURCE"
    assert cuse["source_event_time"] is None
    assert event.event_code is None
    assert event.deduplication_id == hashlib.sha256(canonical_json(raw).encode()).hexdigest()


def test_windows_structure_without_event_id_is_still_rejected():
    raw = fixtures.windows(1, datetime.now(timezone.utc), "4625")
    raw["data"]["win"]["system"].pop("eventID")
    with pytest.raises(EventNormalizationError, match="Windows event ID"):
        normalize_wazuh_event(raw)


def test_yearless_syslog_requires_explicit_year_and_timezone():
    raw = next(raw for name, raw, _ in fixtures.cases() if name == "rfc3164")
    event = normalize_wazuh_event(raw)
    assert event.structured_payload["_cuse"]["source_event_time"] is None
    assert "YEARLESS_TIME_UNRESOLVED" in event.structured_payload["_cuse"]["warnings"]
    inferred = normalize_wazuh_event(raw, context=SourceContext(syslog_year=2025, syslog_timezone=timezone.utc))
    assert inferred.timestamp.year == 2025
    assert "SOURCE_TIME_CONTEXT_INFERRED" in inferred.structured_payload["_cuse"]["warnings"]


@pytest.mark.parametrize("line", ["<999>bad", "<x>bad", "<34>1 broken", "<34>1 2026-10-22T08:00:00Z host app 1 ID [unclosed", "<34>Feb 31 08:00:00 host app: invalid"])
def test_malformed_syslog_fails_without_guessing(line):
    raw = fixtures.envelope(1, datetime.now(timezone.utc))
    raw.update(decoder={"name": "syslog"}, full_log=line)
    with pytest.raises(EventNormalizationError):
        normalize_wazuh_event(raw)


def test_credentials_and_control_characters_redacted_from_normalized_fields():
    raw = fixtures.windows(1, datetime.now(timezone.utc), "1", sysmon=True)
    raw["data"]["win"]["eventdata"]["commandLine"] = "synthetic password=do-not-store\x00"
    raw["data"]["win"]["eventdata"]["queryName"] = "token=do-not-store"
    event = normalize_wazuh_event(raw)
    assert "do-not-store" not in json.dumps(event.model_dump(mode="json"))
    assert "\x00" not in event.command_line


@pytest.mark.parametrize("secret", ['password="synthetic secret phrase"', "Authorization: Bearer synthetic.token.value", "cookie='synthetic cookie phrase'"])
def test_quoted_and_bearer_credentials_do_not_escape_redaction(secret):
    raw = fixtures.windows(1, datetime.now(timezone.utc), "1", sysmon=True)
    raw["data"]["win"]["eventdata"]["commandLine"] = "example.exe " + secret
    event = normalize_wazuh_event(raw)
    assert "synthetic secret phrase" not in event.model_dump_json()
    assert "synthetic.token.value" not in event.model_dump_json()
    assert "synthetic cookie phrase" not in event.model_dump_json()


def test_original_source_identity_extension_uses_same_redaction_policy():
    raw = fixtures.envelope(1, datetime.now(timezone.utc))
    raw["id"] = "source token=synthetic-do-not-store"
    event = normalize_wazuh_event(raw)
    assert "synthetic-do-not-store" not in event.model_dump_json()


def test_multisource_authenticated_ingestion_search_export_and_workbench(client, auth_headers, database_path):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    dataset = fixtures.cases(now)
    ids = []
    for name, raw, _ in dataset:
        response = client.post("/api/v1/events/ingest", headers=auth_headers, json=raw)
        assert response.status_code == 201, (name, response.text)
        event_id = response.json()["event"]["event_id"]
        ids.append(event_id)
        # Lost acknowledgement retry uses precisely the existing 200 contract.
        duplicate = client.post("/api/v1/events/ingest", headers=auth_headers, json=raw)
        assert duplicate.status_code == 200
        assert duplicate.json()["duplicate"] is True
    query = {"query": 'event.provider = "Microsoft-Windows-Sysmon"',
             "start_time": (now - timedelta(minutes=1)).isoformat(),
             "end_time": (now + timedelta(minutes=1)).isoformat(), "limit": 3}
    found = []
    while True:
        response = client.post("/api/v1/siem/search", json=query)
        assert response.status_code == 200, response.text
        found.extend(item["event_id"] for item in response.json()["items"])
        cursor = response.json()["page"].get("next_cursor")
        if not cursor:
            break
        query["cursor"] = cursor
    assert len(found) == len(set(found)) == 10
    detail = client.get(f"/api/v1/events/{found[0]}")
    assert detail.status_code == 200
    assert detail.json()["cuse"]["source_family"] == "SYSMON"
    assert detail.json()["cuse"]["provenance_status"] == "PARTIAL"
    workbench = client.post("/api/v1/investigations/workbench", json={
        "target_type": "EVENT", "target_id": found[0], "relative_minutes": 15,
    })
    assert workbench.status_code == 200, workbench.text
    assert workbench.json()["primary_event"]["cuse"]["source_family"] == "SYSMON"
    cuse = workbench.json()["primary_event"]["cuse"]
    file_hash_values = {entity["value"] for entity in workbench.json()["entities"] if entity["entity_type"] == "FILE_HASH"}
    assert cuse["content_fingerprint"] not in file_hash_values
    assert cuse["source_identity_sha256"] not in file_hash_values
    query.pop("cursor", None)
    query.pop("limit")
    analytics = client.post("/api/v1/siem/search/analytics", json={**query, "group_by": ["host.name"]})
    assert analytics.status_code == 200, analytics.text
    assert analytics.json()["matching_events"] == 10
    exported = client.post("/api/v1/siem/search/export.csv", json={**query, "fields": ["event_id", "event_code"], "limit": 100})
    assert exported.status_code == 200
    assert exported.headers["x-cqql-export-rows"] == "10"
    hunt = client.get("/api/v1/threat-hunts", params={"relative_minutes": 15, "cqql": query["query"]})
    assert hunt.status_code == 200
    assert hunt.json()["total"] == 10
    metrics = client.app.state.ingestion_metrics.snapshot()
    assert metrics["inserted"] == len(dataset)
    assert metrics["duplicates"] == len(dataset)
    assert metrics["normalization_counts"]["received"] == len(dataset) * 2
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 17
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_normalization_rejection_never_counts_as_delivery(client, auth_headers):
    raw = fixtures.windows(1, datetime.now(timezone.utc))
    raw["timestamp"] = "incorrect"
    response = client.post("/api/v1/events/ingest", headers=auth_headers, json=raw)
    assert response.status_code == 422
    metrics = client.app.state.ingestion_metrics.snapshot()
    assert metrics["inserted"] == metrics["duplicates"] == 0
    assert metrics["normalization_counts"]["invalid_timestamp"] == 1


def test_transport_authentication_does_not_accept_analyst_session_as_machine_auth(client):
    raw = fixtures.windows(1, datetime.now(timezone.utc))
    response = client.post("/api/v1/events/ingest", json=raw)
    assert response.status_code == 401
    assert client.app.state.ingestion_metrics.snapshot()["inserted"] == 0


def test_sqlite_failure_has_no_acknowledgement_and_retry_is_safe(client, auth_headers, monkeypatch):
    raw = fixtures.windows(1, datetime.now(timezone.utc))
    repository = client.app.state.event_repository
    def unavailable(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked sensitive-fixture")
    monkeypatch.setattr(repository, "ingest", unavailable)
    response = client.post("/api/v1/events/ingest", headers=auth_headers, json=raw)
    assert response.status_code == 503
    assert "sensitive-fixture" not in response.text
    assert client.app.state.ingestion_metrics.snapshot()["inserted"] == 0
    monkeypatch.undo()
    assert client.post("/api/v1/events/ingest", headers=auth_headers, json=raw).status_code == 201
    assert client.post("/api/v1/events/ingest", headers=auth_headers, json=raw).status_code == 200


def test_multisource_protected_evidence_survives_retention(client, database_path):
    from app.db.events import EventRepository
    now = datetime.now(timezone.utc)
    repository = EventRepository(database_path, retention_days=30, max_records=2)
    raw = fixtures.windows(1, now-timedelta(seconds=3), "3", sysmon=True)
    protected = repository.ingest(normalize_wazuh_event(raw), now=now).event.event_id
    case = client.post("/api/v1/cases", json={"title": "SYNTHETIC M28 retention", "description": "Synthetic source evidence", "severity": "HIGH", "priority": "HIGH"})
    assert case.status_code == 201
    linked = client.post(f"/api/v1/cases/{case.json()['case_id']}/related/event", json={"reference_id": protected, "expected_version": 1})
    assert linked.status_code == 201
    before = repository.get(protected).raw_payload
    for index in range(2, 5):
        other = fixtures.windows(index, now-timedelta(seconds=4-index), "1", sysmon=True)
        repository.ingest(normalize_wazuh_event(other), now=now)
    assert repository.get(protected).raw_payload == before
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 2
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_unknown_source_and_missing_timestamp_are_explicit():
    raw = fixtures.envelope(0, datetime.now(timezone.utc))
    raw["decoder"] = {"name": "unknown-distro-parser"}
    event = normalize_wazuh_event(raw)
    assert event.structured_payload["_cuse"]["normalization_status"] == "UNSUPPORTED_SOURCE"
    assert event.operating_system is None
    raw.pop("timestamp")
    with pytest.raises(EventNormalizationError) as error:
        normalize_wazuh_event(raw)
    assert error.value.code == "INVALID_TIMESTAMP"


def test_unsupported_source_is_preserved_and_accounted_after_commit(client, auth_headers):
    raw = fixtures.envelope(1, datetime.now(timezone.utc))
    raw["decoder"] = {"name": "synthetic-unsupported-source"}
    response = client.post("/api/v1/events/ingest", headers=auth_headers, json=raw)
    assert response.status_code == 201
    detail = client.get(f"/api/v1/events/{response.json()['event']['event_id']}").json()
    assert detail["cuse"]["normalization_status"] == "UNSUPPORTED_SOURCE"
    assert detail["raw_payload"] == raw
    metrics = client.app.state.ingestion_metrics.snapshot()
    assert metrics["normalization_counts"]["unsupported"] == metrics["inserted"] == 1
    assert metrics["normalization_counts"]["rejected"] == 0


def test_wazuh_documented_journald_syslog_envelope_and_field_conflict():
    raw = fixtures.envelope(1, datetime.now(timezone.utc))
    raw.update(location="journald", decoder={"name": "cron-service"},
               predecoder={"program_name": "CRON"},
               full_log="Oct 22 08:00:00 SYNTH-HOST CRON[123]: SYNTHETIC routine command")
    event = normalize_wazuh_event(raw)
    assert event.structured_payload["_cuse"]["source_family"] == "JOURNALD"
    assert event.process_name == "CRON"
    assert event.structured_payload["_cuse"]["source_event_time"] is None
    conflict = fixtures.windows(2, datetime.now(timezone.utc), "3", sysmon=True)
    conflict["data"]["srcip"] = "192.0.2.99"
    with pytest.raises(EventNormalizationError, match="conflicting"):
        normalize_wazuh_event(conflict)


@pytest.mark.parametrize("code,data,expected_field,expected", [
    ("1", {"image": "C:\\Synthetic\\one.exe", "processId": "10", "commandLine": "one.exe"}, "process_id", "10"),
    ("3", {"image": "C:\\Synthetic\\one.exe", "destinationIp": "198.51.100.3", "destinationPort": "53"}, "destination_port", 53),
    ("7", {"imageLoaded": "C:\\Synthetic\\module.dll", "processId": "12"}, "process_id", "12"),
    ("8", {"sourceImage": "C:\\Synthetic\\source.exe", "sourceProcessId": "13", "targetImage": "C:\\Synthetic\\target.exe"}, "process_id", "13"),
    ("10", {"sourceImage": "C:\\Synthetic\\source.exe", "sourceProcessId": "14"}, "process_name", "C:\\Synthetic\\source.exe"),
    ("11", {"image": "C:\\Synthetic\\one.exe", "targetFilename": "C:\\Synthetic\\new.txt"}, "process_name", "C:\\Synthetic\\one.exe"),
    ("13", {"image": "C:\\Synthetic\\one.exe", "targetObject": "HKCU\\Synthetic", "eventType": "SetValue"}, "event_action", "registry_value_set"),
    ("22", {"processId": "15", "queryName": "synthetic.example.invalid"}, "process_id", "15"),
])
def test_minimal_sysmon_family_contracts(code, data, expected_field, expected):
    raw = fixtures.windows(1, datetime.now(timezone.utc), code, sysmon=True)
    raw["data"]["win"]["eventdata"] = data
    event = normalize_wazuh_event(raw)
    assert getattr(event, expected_field) == expected
    assert event.mitre.ids == []


def test_source_time_and_collector_time_remain_distinct_and_range_uses_source(client, auth_headers):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    raw = fixtures.windows(1, now, "4625")
    source_time = now - timedelta(minutes=30)
    raw["data"]["win"]["system"]["systemTime"] = source_time.isoformat()
    response = client.post("/api/v1/events/ingest", headers=auth_headers, json=raw)
    assert response.status_code == 201
    detail = client.get(f"/api/v1/events/{response.json()['event']['event_id']}").json()
    assert datetime.fromisoformat(detail["cuse"]["source_event_time"]) == source_time
    assert datetime.fromisoformat(detail["cuse"]["collector_observation_time"]) == now
    recent = client.post("/api/v1/siem/search", json={"query": 'event.code = "4625"',
        "start_time": (now-timedelta(minutes=10)).isoformat(), "end_time": now.isoformat()})
    assert recent.status_code == 200
    assert recent.json()["items"] == []


def test_authentication_source_detected_from_valid_syslog_header():
    raw = fixtures.envelope(1, datetime.now(timezone.utc))
    raw.update(decoder={"name": "syslog"}, full_log="Oct 22 08:00:00 SYNTH-HOST sshd[123]: Accepted publickey for synthetic-user from 192.0.2.10 port 50500 ssh2")
    event = normalize_wazuh_event(raw)
    assert event.structured_payload["_cuse"]["source_family"] == "LINUX_AUTH"
    assert event.outcome == "success"
    assert event.username == "synthetic-user"
    assert event.process_id == "123"


@pytest.mark.parametrize("port", ["9" * 5000, "65536"], ids=["integer-conversion-limit", "out-of-range"])
def test_invalid_ssh_port_is_sanitized_api_rejection_not_unhandled_failure(client, auth_headers, port):
    raw = fixtures.envelope(1, datetime.now(timezone.utc))
    raw.update(decoder={"name": "sshd"},
               full_log=f"Accepted password for synthetic-user from 192.0.2.20 port {port} ssh2")
    response = client.post("/api/v1/events/ingest", headers=auth_headers, json=raw)
    assert response.status_code == 422
    assert response.json()["detail"]["field"] == "source_port"
    assert port not in response.text
    metrics = client.app.state.ingestion_metrics.snapshot()
    assert metrics["inserted"] == metrics["duplicates"] == 0
    assert metrics["normalization_counts"]["malformed"] == 1


@pytest.mark.parametrize("body", [
    '{"n":' + '9' * 5000 + '}',
    '{"nested":' + '[' * 1100 + '0' + ']' * 1100 + '}',
], ids=["numeric-literal-limit", "decoder-recursion-limit"])
def test_json_decoder_resource_limits_return_sanitized_400(client, auth_headers, body):
    response = client.post("/api/v1/events/ingest", content=body.encode(),
                           headers={**auth_headers, "Content-Type": "application/json"})
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_json"
    assert body not in response.text
    metrics = client.app.state.ingestion_metrics.snapshot()
    assert metrics["inserted"] == metrics["duplicates"] == 0


@pytest.mark.parametrize("field,value", [("agent", []), ("data", "sensitive-fixture"), ("rule", []), ("decoder", 12)])
def test_present_source_sections_must_have_valid_shapes(field, value):
    raw = fixtures.envelope(1, datetime.now(timezone.utc))
    raw[field] = value
    with pytest.raises(EventNormalizationError) as error:
        normalize_wazuh_event(raw)
    assert "sensitive-fixture" not in str(error.value)


@pytest.mark.parametrize("extra,expected_code", [(list(range(10_001)), "OVERSIZED"), (float("nan"), "MALFORMED")])
def test_wide_arrays_and_nonfinite_numbers_fail_bounded_validation(extra, expected_code):
    raw = fixtures.envelope(1, datetime.now(timezone.utc))
    raw["extra"] = extra
    with pytest.raises(EventNormalizationError) as error:
        normalize_wazuh_event(raw)
    assert error.value.code == expected_code


@pytest.mark.parametrize("key,expected_code", [("\ud800", "MALFORMED"), ("x" * 1025, "OVERSIZED")])
def test_source_keys_are_bounded_and_valid_unicode(key, expected_code):
    raw = fixtures.envelope(1, datetime.now(timezone.utc))
    raw["data"] = {key: "SYNTHETIC"}
    with pytest.raises(EventNormalizationError) as error:
        normalize_wazuh_event(raw)
    assert error.value.code == expected_code


@pytest.mark.parametrize("source_offset", [-31, 2])
def test_source_time_must_obey_existing_retention_bounds(client, auth_headers, source_offset):
    now = datetime.now(timezone.utc)
    raw = fixtures.windows(1, now)
    raw["data"]["win"]["system"]["systemTime"] = (now+timedelta(days=source_offset)).isoformat()
    response = client.post("/api/v1/events/ingest", headers=auth_headers, json=raw)
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "outside_retention_window"
    assert client.app.state.ingestion_metrics.snapshot()["inserted"] == 0
