import copy

import pytest
from sqlalchemy import event


SUMMARY_KEYS = {
    "id",
    "alert_id",
    "event_timestamp",
    "created_at",
    "agent_name",
    "agent_ip",
    "rule_id",
    "rule_level",
    "rule_description",
    "mitre_ids",
    "source_ip",
    "severity",
    "priority_score",
    "ai_status",
    "review_status",
}


def test_summary_empty_database_and_route_precedence(client):
    response = client.get("/api/v1/incidents/summary")
    assert response.status_code == 200
    assert response.json() == {"total": 0, "limit": 50, "offset": 0, "items": []}


def test_summary_schema_excludes_evidence_and_relationships(client, wazuh_alert):
    created = client.post("/api/v1/ingest/wazuh", json=wazuh_alert).json()
    response = client.get("/api/v1/incidents/summary")
    assert response.status_code == 200
    item = response.json()["items"][0]
    assert set(item) == SUMMARY_KEYS
    assert item["id"] == created["id"]
    assert item["severity"] == "high"
    assert item["mitre_ids"] == ["T1110"]
    for forbidden in ("raw_event", "full_log", "decoder", "rule_metadata", "reviews"):
        assert forbidden not in item


def test_summary_filtering_and_pagination_match_legacy_behavior(client, wazuh_alert):
    for index, (level, agent) in enumerate(((3, "LOW"), (8, "HIGH-A"), (8, "HIGH-B"))):
        alert = copy.deepcopy(wazuh_alert)
        alert["id"] = f"summary-{index}"
        alert["rule"]["level"] = level
        alert["agent"]["name"] = agent
        client.post("/api/v1/ingest/wazuh", json=alert)

    high = client.get("/api/v1/incidents/summary?severity=high&limit=1&offset=1")
    assert high.status_code == 200
    assert high.json()["total"] == 2
    assert high.json()["limit"] == 1
    assert high.json()["offset"] == 1
    assert len(high.json()["items"]) == 1
    assert client.get("/api/v1/incidents/summary?agent=LOW").json()["total"] == 1
    assert client.get("/api/v1/incidents/summary?mitre_id=T1110").json()["total"] == 3


def test_summary_handles_missing_optional_fields(client):
    assert client.post("/api/v1/ingest/wazuh", json={}).status_code == 201
    item = client.get("/api/v1/incidents/summary").json()["items"][0]
    assert item["alert_id"] is None
    assert item["event_timestamp"] is None
    assert item["agent_name"] is None
    assert item["agent_ip"] is None
    assert item["rule_id"] is None
    assert item["rule_level"] is None
    assert item["source_ip"] is None
    assert item["severity"] == "low"


@pytest.mark.parametrize(
    ("level", "expected"),
    [(0, "low"), (4, "medium"), (8, "high"), (12, "critical")],
)
def test_summary_preserves_severity_semantics(client, wazuh_alert, level, expected):
    wazuh_alert["id"] = f"severity-{level}"
    wazuh_alert["rule"]["level"] = level
    client.post("/api/v1/ingest/wazuh", json=wazuh_alert)
    assert client.get("/api/v1/incidents/summary").json()["items"][0]["severity"] == expected


def test_summary_requires_api_auth(client, wazuh_alert, configured_tokens):
    created = client.post(
        "/api/v1/ingest/wazuh",
        json=wazuh_alert,
        headers=configured_tokens["wazuh"],
    )
    assert created.status_code == 201
    assert client.get("/api/v1/incidents/summary").status_code == 401
    assert client.get(
        "/api/v1/incidents/summary",
        headers={"Authorization": "Bearer wrong"},
    ).status_code == 401
    assert client.get(
        "/api/v1/incidents/summary",
        headers=configured_tokens["api"],
    ).status_code == 200


def test_summary_sql_projection_never_selects_large_evidence(client, session_factory, wazuh_alert):
    alert = copy.deepcopy(wazuh_alert)
    alert["large_evidence"] = "x" * 500_000
    alert["full_log"] = "y" * 200_000
    created = client.post("/api/v1/ingest/wazuh", json=alert).json()
    statements: list[str] = []
    engine = session_factory.kw["bind"]

    def capture_statement(_connection, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement.lower())

    event.listen(engine, "before_cursor_execute", capture_statement)
    try:
        summary = client.get("/api/v1/incidents/summary")
    finally:
        event.remove(engine, "before_cursor_execute", capture_statement)

    assert summary.status_code == 200
    selects = [statement for statement in statements if statement.lstrip().startswith("select")]
    assert len(selects) == 2
    projection_sql = "\n".join(selects)
    for forbidden in ("raw_event", "full_log", "decoder", "rule_metadata", "reviews", "incident_analyses"):
        assert forbidden not in projection_sql
    assert len(summary.content) < 2_000

    detail = client.get(f"/api/v1/incidents/{created['id']}")
    assert detail.status_code == 200
    assert detail.json()["raw_event"]["large_evidence"] == "x" * 500_000
    # Existing ingestion normalization intentionally caps full_log at 100,000
    # characters; the detail route must still return that complete stored value.
    assert detail.json()["full_log"] == "y" * 100_000
