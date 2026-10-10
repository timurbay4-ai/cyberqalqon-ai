from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.services.wazuh_normalizer import AlertNormalizationError, normalize_wazuh_alert


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = ROOT / "wazuh" / "samples" / "windows-security-failure.json"


@pytest.fixture
def windows_alert() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_windows_event_context_username_and_source_are_normalized(windows_alert: dict) -> None:
    alert = normalize_wazuh_alert(windows_alert)
    assert alert.agent.id == "002"
    assert alert.agent.name == "WIN-392LNNLLAT3"
    assert alert.windows is not None
    assert alert.windows.event_id == "4625"
    assert alert.windows.channel == "Security"
    assert alert.windows.provider == "Microsoft-Windows-Security-Auditing"
    assert alert.windows.computer == "WIN-392LNNLLAT3"
    assert alert.user == "cq-m10-synthetic"
    assert alert.source is not None
    assert str(alert.source.ip) == "192.0.2.44"
    assert alert.source.port == 49800


def test_partial_windows_identity_fails_closed(windows_alert: dict) -> None:
    del windows_alert["data"]["win"]["system"]["eventID"]
    with pytest.raises(AlertNormalizationError) as error:
        normalize_wazuh_alert(windows_alert)
    assert error.value.field == "data.win.system.eventID"


def test_windows_missing_network_sentinels_are_not_treated_as_addresses(windows_alert: dict) -> None:
    windows_alert["data"]["win"]["eventdata"]["ipAddress"] = "-"
    windows_alert["data"]["win"]["eventdata"]["ipPort"] = "-"
    alert = normalize_wazuh_alert(windows_alert)
    assert alert.source is None


def test_windows_alert_round_trips_through_authenticated_api(
    client: TestClient,
    auth_headers: dict[str, str],
    windows_alert: dict,
) -> None:
    created = client.post("/api/v1/alerts/ingest", headers=auth_headers, json=windows_alert)
    assert created.status_code == 201, created.text
    body = created.json()["alert"]
    assert body["windows"] == {
        "event_id": "4625",
        "channel": "Security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "computer": "WIN-392LNNLLAT3",
    }
    assert body["user"] == "cq-m10-synthetic"
    assert body["source"] == {"ip": "192.0.2.44", "port": 49800}

    detail = client.get("/api/v1/alerts/m10-synthetic-4625-001")
    assert detail.status_code == 200
    assert detail.json()["windows"]["event_id"] == "4625"
    search = client.get("/api/v1/alerts", params={"search": "Microsoft-Windows-Security-Auditing"})
    assert search.status_code == 200
    assert [item["alert_id"] for item in search.json()["items"]] == ["m10-synthetic-4625-001"]


def test_windows_builtin_alert_does_not_join_linux_m9_incident(
    client: TestClient,
    auth_headers: dict[str, str],
    windows_alert: dict,
) -> None:
    assert client.post("/api/v1/alerts/ingest", headers=auth_headers, json=windows_alert).status_code == 201
    assert client.get("/api/v1/incidents").json()["page"]["total"] == 0


def test_windows_untrusted_fields_remain_data(windows_alert: dict) -> None:
    changed = copy.deepcopy(windows_alert)
    changed["data"]["win"]["eventdata"]["targetUserName"] = "<script>alert(1)</script>"
    changed["data"]["win"]["system"]["computer"] = "$(whoami)"
    alert = normalize_wazuh_alert(changed)
    assert alert.user == "<script>alert(1)</script>"
    assert alert.windows is not None and alert.windows.computer == "$(whoami)"
