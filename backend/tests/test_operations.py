from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import httpx
import pytest

import app.api.routes.operations as operations_route

from app.core.config import Settings
from app.db.operations import OperationalQueryCancelled, OperationalQueryTimeout
from app.schemas.operations import ComponentObservation, OperationalSnapshot
from app.services.wazuh_api import WazuhApiClient


def _snapshot(state: str, observed_at: datetime) -> OperationalSnapshot:
    return OperationalSnapshot(
        collected_at=observed_at,
        components=[
            ComponentObservation(
                component_key="event-shipper",
                component_kind="event_shipper",
                state=state,
                authority="DURABLE_SHIPPER_STATE",
                summary=f"Shipper is {state.lower()}.",
                metrics={"archive_lag_bytes": 42, "malformed_json": 1},
                last_error="retry blocked" if state != "HEALTHY" else None,
                observed_at=observed_at,
            )
        ],
    )


def test_operational_overview_requires_authentication(unauthenticated_client) -> None:
    response = unauthenticated_client.get("/api/v1/operations/overview")
    assert response.status_code == 401


def test_operational_transitions_are_deduplicated_and_recover(client) -> None:
    repository = client.app.state.operational_repository
    started = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)

    assert repository.record_snapshot(_snapshot("DEGRADED", started)) == 1
    assert repository.record_snapshot(_snapshot("DEGRADED", started + timedelta(seconds=5))) == 0
    assert repository.record_snapshot(_snapshot("HEALTHY", started + timedelta(seconds=10))) == 1
    assert repository.record_snapshot(_snapshot("DEGRADED", started + timedelta(seconds=20))) == 1
    assert repository.record_snapshot(_snapshot("UNAVAILABLE", started)) == 0

    response = client.get("/api/v1/operations/overview")
    assert response.status_code == 200
    payload = response.json()
    assert payload["components"][0]["state"] == "DEGRADED"
    assert [item["event_type"] for item in payload["recent_events"]] == ["ISSUE", "RECOVERY", "ISSUE"]
    assert payload["recent_events"][0]["details"]["notification_suppressed_by_cooldown"] is True
    assert payload["data_quality"]["malformed_events"] == 1
    assert payload["wazuh_inventory"]["state"] == "UNAVAILABLE"

    notices = client.get("/api/v1/notifications").json()["items"]
    assert [item["category"] for item in notices] == [
        "OPERATIONAL_RECOVERY",
        "OPERATIONAL_ISSUE",
    ]
    assert all(item["target_type"] == "operational" for item in notices)


def test_operational_event_limit_is_bounded(client) -> None:
    assert client.get("/api/v1/operations/overview?event_limit=0").status_code == 422
    assert client.get("/api/v1/operations/overview?event_limit=101").status_code == 422


def test_operational_overview_offloads_sqlite_and_labels_cache(
    client, monkeypatch
) -> None:
    calls: list[tuple[object, tuple[object, ...], dict[str, object]]] = []
    original = operations_route.run_in_threadpool

    async def observed_run_in_threadpool(function, *args, **kwargs):
        calls.append((function, args, kwargs))
        return await original(function, *args, **kwargs)

    monkeypatch.setattr(
        operations_route,
        "run_in_threadpool",
        observed_run_in_threadpool,
    )
    first = client.get("/api/v1/operations/overview?event_limit=17")
    second = client.get("/api/v1/operations/overview?event_limit=17")
    assert first.status_code == 200
    assert second.status_code == 200
    assert len(calls) == 2
    assert calls[0][2]["limit"] == 17
    assert isinstance(calls[0][2]["cancel_event"], threading.Event)
    assert calls[0][2]["deadline_seconds"] == 2.0
    assert first.json()["measurement"]["state"] == "FRESH"
    assert first.json()["measurement"]["execution_model"] == "BOUNDED_THREADPOOL"
    assert first.json()["measurement"]["duration_ms"] >= 0
    assert second.json()["measurement"]["state"] == "CACHED"
    assert second.json()["measurement"]["age_seconds"] >= 0


def test_operational_overview_uses_bounded_metadata_not_event_table_aggregates(
    client, monkeypatch
) -> None:
    repository = client.app.state.operational_repository
    statements: list[str] = []
    original = repository._overview_connection

    from contextlib import contextmanager

    @contextmanager
    def traced_connection(*, cancel_event, deadline_at):
        with original(cancel_event=cancel_event, deadline_at=deadline_at) as connection:
            connection.set_trace_callback(statements.append)
            yield connection

    monkeypatch.setattr(repository, "_overview_connection", traced_connection)
    response = client.get("/api/v1/operations/overview?event_limit=23")
    assert response.status_code == 200
    payload = response.json()
    assert payload["data_quality"]["total_events_measurement"] == "EXACT"
    assert payload["data_quality"]["total_events_scope"] == "CURRENT_RETAINED_DATABASE"
    assert payload["data_quality"]["raw_evidence_records"] is None
    event_sql = [sql.lower() for sql in statements if "security_events" in sql.lower()]
    assert all("count(" not in sql for sql in event_sql)
    assert all("min(" not in sql and "max(" not in sql for sql in event_sql)
    assert any("order by occurred_at asc" in sql and "limit 1" in sql for sql in event_sql)


def test_operational_overview_singleflight_shares_one_cold_computation(
    client, monkeypatch
) -> None:
    repository = client.app.state.operational_repository
    baseline = repository.overview(limit=24)
    repository._invalidate_overview_cache()
    entered = threading.Event()
    release = threading.Event()
    calls = 0

    def blocked_compute(**_kwargs):
        nonlocal calls
        calls += 1
        entered.set()
        assert release.wait(timeout=2)
        return baseline

    monkeypatch.setattr(repository, "_compute_overview", blocked_compute)
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(repository.overview, limit=25) for _ in range(5)]
        assert entered.wait(timeout=1)
        time.sleep(0.05)
        release.set()
        results = [future.result(timeout=2) for future in futures]
    assert calls == 1
    assert {result.measurement.state for result in results} <= {"FRESH", "CACHED"}
    assert repository._overview_singleflight_joins == 4


def test_operational_overview_serves_bounded_stale_during_refresh(
    client, monkeypatch
) -> None:
    repository = client.app.state.operational_repository
    repository.overview_cache_ttl_seconds = 0
    repository.overview_stale_ttl_seconds = 30
    repository.overview(limit=26)
    time.sleep(0.01)
    entered = threading.Event()
    release = threading.Event()
    original = repository._compute_overview

    def blocked_compute(**kwargs):
        entered.set()
        assert release.wait(timeout=2)
        return original(**kwargs)

    monkeypatch.setattr(repository, "_compute_overview", blocked_compute)
    with ThreadPoolExecutor(max_workers=1) as executor:
        refresh = executor.submit(repository.overview, limit=26)
        assert entered.wait(timeout=1)
        stale = repository.overview(limit=26)
        assert stale.measurement.state == "STALE"
        assert stale.measurement.reason_code == "REFRESH_IN_PROGRESS"
        release.set()
        assert refresh.result(timeout=2).measurement.state == "FRESH"


def test_sqlite_progress_handler_interrupts_disposable_read_on_deadline(client) -> None:
    repository = client.app.state.operational_repository
    cancel = threading.Event()
    with pytest.raises(OperationalQueryTimeout):
        with repository._overview_connection(
            cancel_event=cancel,
            deadline_at=time.monotonic() + 0.01,
        ) as connection:
            connection.execute(
                "WITH RECURSIVE counter(value) AS ("
                "SELECT 1 UNION ALL SELECT value + 1 FROM counter WHERE value < 100000000"
                ") SELECT sum(value) FROM counter"
            ).fetchone()


def test_sqlite_progress_handler_interrupts_disposable_read_on_cancel(client) -> None:
    repository = client.app.state.operational_repository
    cancel = threading.Event()

    def trigger_cancel() -> None:
        time.sleep(0.01)
        cancel.set()

    thread = threading.Thread(target=trigger_cancel)
    thread.start()
    try:
        with pytest.raises(OperationalQueryCancelled):
            with repository._overview_connection(
                cancel_event=cancel,
                deadline_at=time.monotonic() + 2,
            ) as connection:
                connection.execute(
                    "WITH RECURSIVE counter(value) AS ("
                    "SELECT 1 UNION ALL SELECT value + 1 FROM counter WHERE value < 100000000"
                    ") SELECT sum(value) FROM counter"
                ).fetchone()
    finally:
        thread.join(timeout=1)


def test_failed_refresh_returns_typed_stale_snapshot_when_available(
    client, monkeypatch
) -> None:
    repository = client.app.state.operational_repository
    repository.overview_cache_ttl_seconds = 0
    repository.overview_stale_ttl_seconds = 30
    repository.overview(limit=28)
    time.sleep(0.01)

    def timeout(**_kwargs):
        raise OperationalQueryTimeout("failure injection")

    monkeypatch.setattr(repository, "_compute_overview", timeout)
    stale = repository.overview(limit=28)
    assert stale.measurement.state == "STALE"
    assert stale.measurement.reason_code == "REFRESH_FAILED"


def test_operational_overview_cache_has_a_hard_entry_bound(client) -> None:
    repository = client.app.state.operational_repository
    for limit in range(30, 42):
        repository.overview(limit=limit)
    assert len(repository._overview_cache) == 8


def test_operational_timeout_returns_typed_retryable_503(client, monkeypatch) -> None:
    repository = client.app.state.operational_repository

    def timeout(**_kwargs):
        raise OperationalQueryTimeout("bounded test timeout")

    monkeypatch.setattr(repository, "overview", timeout)
    response = client.get("/api/v1/operations/overview")
    assert response.status_code == 503
    assert response.headers["retry-after"] == "2"
    assert response.json()["detail"] == {
        "code": "OPERATIONS_QUERY_TIMEOUT",
        "message": "Operations snapshot is temporarily unavailable.",
        "retryable": True,
    }


def test_operational_snapshot_invalidates_cached_overview(client) -> None:
    repository = client.app.state.operational_repository
    started = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
    first = client.get("/api/v1/operations/overview?event_limit=19").json()
    cached = client.get("/api/v1/operations/overview?event_limit=19").json()
    assert first["measurement"]["state"] == "FRESH"
    assert cached["measurement"]["state"] == "CACHED"

    repository.record_snapshot(_snapshot("DEGRADED", started))
    refreshed = client.get("/api/v1/operations/overview?event_limit=19").json()
    assert refreshed["measurement"]["state"] == "FRESH"
    assert refreshed["components"][0]["state"] == "DEGRADED"


def test_forward_summary_does_not_merge_unproven_legacy_or_replay(client) -> None:
    repository = client.app.state.operational_repository
    observed_at = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
    snapshot = OperationalSnapshot(
        collected_at=observed_at,
        components=[
            ComponentObservation(
                component_key="event-shipper",
                component_kind="event_shipper",
                state="UNAVAILABLE",
                authority="DURABLE_SHIPPER_STATE",
                summary="Legacy cursor is blocked; forward state is not deployed.",
                metrics={
                    "legacy_checkpoint_state": "BLOCKED",
                    "legacy_continuity_status": "UNPROVEN",
                    "forward_ingestion_state": "NOT_DEPLOYED",
                    "forward_service_active": False,
                    "forward_approval_present": False,
                    "historical_replay_state": "NOT_CONFIGURED",
                },
                last_error="archive identity mismatch",
                observed_at=observed_at,
            )
        ],
    )
    repository.record_snapshot(snapshot)

    forward = client.get("/api/v1/operations/overview").json()["forward_ingestion"]
    assert forward["legacy_checkpoint_state"] == "BLOCKED"
    assert forward["legacy_continuity"] == "UNPROVEN"
    assert forward["forward_state"] == "NOT_DEPLOYED"
    assert forward["historical_replay_state"] == "NOT_STARTED"
    assert forward["approval_state"] == "ABSENT"
    assert forward["historical_gap_warning"] == "UNPROVEN_HISTORY_NOT_REPLAYED"


def test_forward_summary_exposes_only_validated_typed_metrics(client) -> None:
    repository = client.app.state.operational_repository
    observed_at = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
    generation = "a" * 64
    repository.record_snapshot(
        OperationalSnapshot(
            collected_at=observed_at,
            components=[
                ComponentObservation(
                    component_key="event-shipper",
                    component_kind="event_shipper",
                    state="DEGRADED",
                    authority="DURABLE_SHIPPER_STATE",
                    summary="Forward checkpoint is prepared, not active.",
                    metrics={
                        "legacy_checkpoint_state": "BLOCKED",
                        "legacy_continuity_status": "UNPROVEN",
                        "forward_ingestion_state": "READY",
                        "forward_service_active": False,
                        "forward_approval_present": True,
                        "forward_approval_state": "VALID",
                        "forward_approval_validation_basis": "BOUNDED_SCOPE_TIME_IDENTITY",
                        "forward_approval_expires_at_epoch": 1792497600,
                        "forward_approval_remaining_seconds": 3600.0,
                        "forward_generation_id": generation,
                        "forward_source_inode": 33582586,
                        "forward_start_offset_bytes": 688001817,
                        "forward_cursor_bytes": 688001817,
                        "forward_lag_bytes": 147710115,
                        "forward_unique_insertions": 0,
                        "forward_duplicate_acknowledgements": 0,
                        "forward_source_identity_matches": True,
                        "forward_legacy_state_unchanged": True,
                        "rate_snapshot_status": "FRESH",
                        "archive_growth_bytes_per_second": 42.5,
                        "forward_cursor_progress_bytes_per_second": 50.0,
                        "forward_net_lag_bytes_per_second": -7.5,
                        "forward_backlog_trend": "DRAINING",
                        "forward_rate_measurement_state": "FRESH",
                        "forward_unreconciled_historical_records": 465121,
                        "forward_last_successful_delivery_epoch": 1792494000,
                        "forward_checkpoint_updated_at_epoch": 1792494010,
                    },
                    last_error=None,
                    observed_at=observed_at,
                )
            ],
        )
    )

    forward = client.get("/api/v1/operations/overview").json()["forward_ingestion"]
    assert forward["forward_state"] == "READY"
    assert forward["approval_state"] == "VALID"
    assert forward["approval_validation_basis"] == "BOUNDED_SCOPE_TIME_IDENTITY"
    assert forward["approval_expires_at"] == "2026-10-20T12:00:00Z"
    assert forward["approval_remaining_seconds"] == 3600.0
    assert forward["generation_id"] == generation
    assert forward["cursor_bytes"] == 688001817
    assert forward["source_identity_matches"] is True
    assert forward["archive_growth_bytes_per_second"] == 42.5
    assert forward["cursor_progress_bytes_per_second"] == 50.0
    assert forward["net_lag_bytes_per_second"] == -7.5
    assert forward["net_backlog_trend"] == "DRAINING"
    assert forward["rate_measurement_state"] == "FRESH"
    assert forward["unreconciled_historical_records"] == 465121
    assert forward["last_successful_delivery"] == "2026-10-20T11:00:00Z"
    assert forward["checkpoint_updated_at"] == "2026-10-20T11:00:10Z"


def test_wazuh_api_missing_credentials_preserves_unavailable_state() -> None:
    result = WazuhApiClient(Settings()).fetch_inventory()
    assert result.available is False
    assert "credentials" in result.reason


@pytest.mark.parametrize(
    "settings",
    [
        {"wazuh_api_url": "http://127.0.0.1:55000"},
        {"wazuh_api_url": "https://wazuh.example:55000"},
        {"wazuh_api_username": "reader"},
        {"wazuh_api_password": "secret"},
    ],
)
def test_wazuh_api_configuration_rejects_unsafe_or_partial_values(settings) -> None:
    with pytest.raises(ValueError):
        Settings(**settings)


def test_wazuh_api_reads_only_bounded_inventory(monkeypatch) -> None:
    requests: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path))
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, text="signed-token")
        if request.url.path == "/agents":
            return httpx.Response(
                200,
                json={
                    "data": {
                        "affected_items": [
                            {
                                "id": "001",
                                "name": "linux-agent",
                                "status": "active",
                                "ip": "127.0.0.1",
                                "manager": "lab-manager",
                                "lastKeepAlive": "2026-10-09T12:00:00Z",
                                "os": {"name": "Linux", "platform": "linux", "version": "1"},
                            },
                            {"id": "../../bad", "name": "unexpected-agent", "status": "active"},
                        ]
                    }
                },
            )
        if request.url.path == "/manager/info":
            return httpx.Response(200, json={"data": {"affected_items": [{"name": "lab-manager", "version": "v4.14.8"}]}})
        if request.url.path == "/manager/status":
            return httpx.Response(200, json={"data": {"affected_items": [{"wazuh-analysisd": "running"}]}})
        return httpx.Response(404)

    settings = Settings(wazuh_api_username="reader", wazuh_api_password="secret-value")
    client = WazuhApiClient(settings)
    monkeypatch.setattr(
        client,
        "_client",
        lambda: httpx.Client(
            base_url="https://127.0.0.1:55000",
            transport=httpx.MockTransport(handler),
        ),
    )

    result = client.fetch_inventory()
    assert result.available is True
    assert result.manager_identity == "lab-manager"
    assert result.manager_version == "v4.14.8"
    assert result.manager_health == "HEALTHY"
    assert result.agents[0].last_keepalive == "2026-10-09T12:00:00Z"
    assert len(result.agents) == 1
    assert result.rejected_agent_count == 1
    assert requests == [
        ("POST", "/security/user/authenticate"),
        ("GET", "/agents"),
        ("GET", "/manager/info"),
        ("GET", "/manager/status"),
    ]


def test_wazuh_api_rejects_oversized_response(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, text="x" * 128)
        return httpx.Response(200, content=b"x" * 257)

    settings = Settings(
        wazuh_api_username="reader",
        wazuh_api_password="secret-value",
        wazuh_api_max_response_bytes=256,
    )
    client = WazuhApiClient(settings)
    monkeypatch.setattr(
        client,
        "_client",
        lambda: httpx.Client(
            base_url="https://127.0.0.1:55000",
            transport=httpx.MockTransport(handler),
        ),
    )
    result = client.fetch_inventory()
    assert result.available is False
    assert "size limit" in result.reason


def test_wazuh_api_timeout_retries_are_bounded(monkeypatch) -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ConnectTimeout("bounded timeout", request=request)

    settings = Settings(
        wazuh_api_username="reader",
        wazuh_api_password="secret-value",
        wazuh_api_timeout_seconds=0.1,
        wazuh_api_retry_attempts=1,
    )
    client = WazuhApiClient(settings)
    monkeypatch.setattr(
        client,
        "_client",
        lambda: httpx.Client(
            base_url="https://127.0.0.1:55000",
            transport=httpx.MockTransport(handler),
        ),
    )

    result = client.fetch_inventory()
    assert result.available is False
    assert attempts == 2


def test_wazuh_api_credential_file_rotation_fails_closed(monkeypatch, tmp_path) -> None:
    missing = tmp_path / "rotated-reader.username"
    monkeypatch.delenv("WAZUH_API_USERNAME", raising=False)
    monkeypatch.delenv("WAZUH_API_PASSWORD", raising=False)
    monkeypatch.setenv("WAZUH_API_USERNAME_FILE", str(missing))
    monkeypatch.setenv("WAZUH_API_PASSWORD_FILE", str(tmp_path / "reader.password"))

    with pytest.raises(ValueError, match="Unable to read WAZUH_API_USERNAME_FILE"):
        Settings.from_env()
