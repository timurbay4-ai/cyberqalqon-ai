from __future__ import annotations

import sqlite3

from fastapi.testclient import TestClient

from app.services.detection_quality import export_golden_datasets, quality_catalog


def _production_counts(client: TestClient, database_path) -> tuple[int, int, int, int]:
    with sqlite3.connect(database_path) as connection:
        return tuple(connection.execute(
            "SELECT (SELECT COUNT(*) FROM alerts), "
            "(SELECT COUNT(*) FROM incidents), "
            "(SELECT COUNT(*) FROM soc_cases), "
            "(SELECT COUNT(*) FROM analyst_notifications)"
        ).fetchone())  # type: ignore[return-value]


def test_all_nine_golden_datasets_pass_without_claiming_live_accuracy() -> None:
    reports = quality_catalog()
    assert [report.rule_id for report in reports] == [f"DET-{index:03d}" for index in range(1, 10)]
    assert all(len(report.fixtures) == 9 for report in reports)
    assert all(report.all_applicable_fixtures_passed for report in reports)
    assert all(report.live_ground_truth_available is False for report in reports)
    assert all(report.runtime_activation_state == "DISABLED_BY_POLICY" for report in reports)
    assert all(report.deployment_eligibility == "SHADOW_ONLY" for report in reports)
    assert all(report.enabled is False and report.side_effects is False for report in reports)
    assert all(report.metrics.false_positives == 0 for report in reports)
    assert all(report.metrics.false_negatives == 0 for report in reports)
    assert all(report.metrics.event_order_consistent for report in reports)
    assert all(report.metrics.repeat_evaluation_consistent for report in reports)
    assert all(report.metrics.duplicate_finding_rate == 0 for report in reports)


def test_exported_records_are_explicitly_synthetic_and_complete() -> None:
    payload = export_golden_datasets()
    assert payload["dataset_label"] == "SYNTHETIC TEST DATA"
    assert len(payload["rules"]) == 9
    for fixtures in payload["rules"].values():
        assert len(fixtures) == 9
        for fixture in fixtures:
            for event in fixture["events"]:
                assert event["synthetic_test_data"] is True
                assert "SYNTHETIC TEST DATA" in event["labels"]


def test_quality_api_is_read_only_and_rbac_protected(
    client: TestClient,
    database_path,
) -> None:
    before = _production_counts(client, database_path)
    response = client.get("/api/v1/detection-engineering/advanced-quality")
    assert response.status_code == 200
    assert len(response.json()) == 9
    detail = client.get("/api/v1/detection-engineering/advanced-quality/DET-009")
    assert detail.status_code == 200
    assert detail.json()["all_applicable_fixtures_passed"] is True
    assert _production_counts(client, database_path) == before

    client.cookies.clear()
    assert client.get("/api/v1/detection-engineering/advanced-quality").status_code == 401
