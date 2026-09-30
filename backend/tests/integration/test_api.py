import copy


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "cyberqalqon-backend"}


def test_readiness(client):
    response = client.get("/ready")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_valid_wazuh_alert_is_normalized(client, wazuh_alert):
    response = client.post("/api/v1/ingest/wazuh", json=wazuh_alert)
    assert response.status_code == 201
    body = response.json()
    assert body["rule_id"] == "5710"
    assert body["rule_level"] == 8
    assert body["agent_name"] == "LAB-WIN-01"
    assert body["source_ip"] == "198.51.100.20"
    assert body["priority_score"] == 40
    assert body["severity"] == "high"


def test_missing_optional_source_ip(client, wazuh_alert):
    del wazuh_alert["data"]["srcip"]
    response = client.post("/api/v1/ingest/wazuh", json=wazuh_alert)
    assert response.status_code == 201
    assert response.json()["source_ip"] is None


def test_missing_user(client, wazuh_alert):
    wazuh_alert["data"].pop("srcuser")
    response = client.post("/api/v1/ingest/wazuh", json=wazuh_alert)
    assert response.json()["user"] is None


def test_one_mitre_id(client, wazuh_alert):
    response = client.post("/api/v1/ingest/wazuh", json=wazuh_alert)
    assert response.json()["mitre_ids"] == ["T1110"]


def test_multiple_mitre_ids(client, wazuh_alert):
    wazuh_alert["rule"]["mitre"]["id"] = ["T1110", "T1078"]
    response = client.post("/api/v1/ingest/wazuh", json=wazuh_alert)
    assert response.json()["mitre_ids"] == ["T1110", "T1078"]


def test_no_mitre_mapping(client, wazuh_alert):
    wazuh_alert["rule"].pop("mitre")
    response = client.post("/api/v1/ingest/wazuh", json=wazuh_alert)
    assert response.json()["mitre_ids"] == []


def test_rule_level_zero(client, wazuh_alert):
    wazuh_alert["rule"]["level"] = 0
    response = client.post("/api/v1/ingest/wazuh", json=wazuh_alert)
    assert response.json()["priority_score"] == 3
    assert response.json()["severity"] == "low"


def test_rule_level_fifteen(client, wazuh_alert):
    wazuh_alert["rule"]["level"] = 15
    response = client.post("/api/v1/ingest/wazuh", json=wazuh_alert)
    assert response.json()["priority_score"] == 73
    assert response.json()["severity"] == "critical"


def test_database_persistence_and_detail(client, wazuh_alert):
    created = client.post("/api/v1/ingest/wazuh", json=wazuh_alert).json()
    detail = client.get(f"/api/v1/incidents/{created['id']}")
    assert detail.status_code == 200
    assert detail.json()["raw_event"] == wazuh_alert


def test_incident_listing(client, wazuh_alert):
    client.post("/api/v1/ingest/wazuh", json=wazuh_alert)
    response = client.get("/api/v1/incidents")
    assert response.json()["total"] == 1
    assert len(response.json()["items"]) == 1


def test_pagination(client, wazuh_alert):
    for index in range(3):
        alert = copy.deepcopy(wazuh_alert)
        alert["id"] = f"page-{index}"
        client.post("/api/v1/ingest/wazuh", json=alert)
    response = client.get("/api/v1/incidents?limit=1&offset=1")
    assert response.json()["total"] == 3
    assert response.json()["limit"] == 1
    assert response.json()["offset"] == 1
    assert len(response.json()["items"]) == 1


def test_filtering(client, wazuh_alert):
    client.post("/api/v1/ingest/wazuh", json=wazuh_alert)
    assert client.get("/api/v1/incidents?severity=high").json()["total"] == 1
    assert client.get("/api/v1/incidents?agent=LAB-WIN-01").json()["total"] == 1
    assert client.get("/api/v1/incidents?mitre_id=T1110").json()["total"] == 1
    assert client.get("/api/v1/incidents?severity=low").json()["total"] == 0


def test_missing_incident_has_stable_error(client):
    response = client.get("/api/v1/incidents/missing")
    assert response.status_code == 404
    assert response.json() == {"error": {"code": "INCIDENT_NOT_FOUND", "message": "Incident not found"}}


def test_analyst_review_history(client, wazuh_alert):
    incident_id = client.post("/api/v1/ingest/wazuh", json=wazuh_alert).json()["id"]
    first = client.post(f"/api/v1/incidents/{incident_id}/review", json={"status": "confirmed", "analyst": "analyst-1", "note": "Reviewed"})
    second = client.post(f"/api/v1/incidents/{incident_id}/review", json={"status": "false_positive", "analyst": "analyst-2"})
    assert first.status_code == 201
    assert second.json()["review_status"] == "false_positive"
    assert len(second.json()["reviews"]) == 2


def test_invalid_review_state(client, wazuh_alert):
    incident_id = client.post("/api/v1/ingest/wazuh", json=wazuh_alert).json()["id"]
    response = client.post(f"/api/v1/incidents/{incident_id}/review", json={"status": "closed", "analyst": "analyst"})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_duplicate_alert_is_idempotent(client, wazuh_alert):
    first = client.post("/api/v1/ingest/wazuh", json=wazuh_alert)
    second = client.post("/api/v1/ingest/wazuh", json=wazuh_alert)
    assert first.status_code == 201
    assert second.status_code == 200
    assert first.json()["id"] == second.json()["id"]
    assert client.get("/api/v1/incidents").json()["total"] == 1


def test_malformed_json(client):
    response = client.post("/api/v1/ingest/wazuh", content="{bad", headers={"content-type": "application/json"})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_body_must_be_json_object(client):
    response = client.post("/api/v1/ingest/wazuh", json=[])
    assert response.status_code == 422


def test_unexpected_fields_are_preserved_as_evidence(client, wazuh_alert):
    wazuh_alert["future_wazuh_field"] = {"safe": True}
    response = client.post("/api/v1/ingest/wazuh", json=wazuh_alert)
    assert response.status_code == 201
    assert response.json()["raw_event"]["future_wazuh_field"] == {"safe": True}


def test_minimal_object_does_not_fabricate_evidence(client):
    response = client.post("/api/v1/ingest/wazuh", json={})
    assert response.status_code == 201
    body = response.json()
    assert body["alert_id"] is None
    assert body["event_timestamp"] is None
    assert body["rule_level"] is None
    assert body["mitre_ids"] == []
    assert body["raw_event"] == {}


def test_ai_status_is_not_configured(client, wazuh_alert):
    response = client.post("/api/v1/ingest/wazuh", json=wazuh_alert)
    assert response.json()["ai_status"] == "not_configured"


def test_request_body_limit(client):
    response = client.post("/api/v1/ingest/wazuh", json={"full_log": "x" * 1_100_000})
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "REQUEST_TOO_LARGE"


def test_out_of_range_rule_level_is_rejected(client, wazuh_alert):
    wazuh_alert["rule"]["level"] = 16
    response = client.post("/api/v1/ingest/wazuh", json=wazuh_alert)
    assert response.status_code == 422
