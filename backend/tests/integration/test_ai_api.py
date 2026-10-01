from app.core.config import get_settings
from app.schemas.analysis import AnalysisResult


class ApiFakeAnalyzer:
    provider = "ollama"
    model = "api-test-model"
    def analyze(self, prompt: str) -> AnalysisResult:
        return AnalysisResult(summary="Observed authentication failures.", observed_facts=["Wazuh rule evidence is present."],
            severity_explanation="Review is warranted; compromise is not confirmed.", potential_mitre_techniques=[],
            investigation_steps=["Review adjacent authentication logs."], uncertainties=["Authentication outcome is unknown."])


def test_analysis_noop_retrieval_and_trigger(client, wazuh_alert):
    incident_id = client.post("/api/v1/ingest/wazuh", json=wazuh_alert).json()["id"]
    result = client.get(f"/api/v1/incidents/{incident_id}/analysis")
    assert result.status_code == 200
    assert result.json()["analysis_status"] == "not_configured"
    triggered = client.post(f"/api/v1/incidents/{incident_id}/analysis")
    assert triggered.status_code == 503
    assert triggered.json()["error"]["code"] == "AI_NOT_CONFIGURED"


def test_analysis_unknown_incident(client):
    assert client.get("/api/v1/incidents/missing/analysis").status_code == 404


def test_analysis_requires_api_token(client, wazuh_alert, configured_tokens):
    incident_id = client.post("/api/v1/ingest/wazuh", json=wazuh_alert, headers=configured_tokens["wazuh"]).json()["id"]
    assert client.get(f"/api/v1/incidents/{incident_id}/analysis").status_code == 401
    assert client.post(f"/api/v1/incidents/{incident_id}/analysis", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get(f"/api/v1/incidents/{incident_id}/analysis", headers=configured_tokens["api"]).status_code == 200


def test_analysis_complete_api_flow_and_duplicate_control(client, wazuh_alert, monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "ollama"); monkeypatch.setenv("AI_MODEL", "api-test-model"); get_settings.cache_clear()
    monkeypatch.setattr("app.services.ai_service.create_analyzer", lambda settings: ApiFakeAnalyzer())
    try:
        incident_id = client.post("/api/v1/ingest/wazuh", json=wazuh_alert).json()["id"]
        completed = client.post(f"/api/v1/incidents/{incident_id}/analysis")
        assert completed.status_code == 200 and completed.json()["analysis_status"] == "completed"
        assert client.get(f"/api/v1/incidents/{incident_id}/analysis").json()["result"]["summary"]
        assert client.post(f"/api/v1/incidents/{incident_id}/analysis").status_code == 409
        assert client.post(f"/api/v1/incidents/{incident_id}/analysis?retry=true").status_code == 200
    finally:
        get_settings.cache_clear()
