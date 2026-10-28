from __future__ import annotations

import asyncio
import sqlite3
import threading
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json

import pytest

from app.api.routes.cqql import _run_cancellable
from app.db.cqql import (
    CQQL_MAX_CONCURRENT_QUERIES,
    CQQLQueryCancelledError,
    CQQLSearchRepository,
)
from app.services.cqql import (
    MAX_BOOLEAN_CLAUSES,
    MAX_QUERY_LENGTH,
    CQQLQueryError,
    BooleanExpression,
    Comparison,
    Negation,
    compile_cqql,
    parse_cqql,
)


def event_payload(
    event_id: str,
    timestamp: datetime,
    *,
    source_ip: str = "192.0.2.10",
    severity: int = 8,
) -> dict:
    return {
        "timestamp": timestamp.isoformat(),
        "id": event_id,
        "agent": {"id": "025", "name": "cqql-synthetic-host"},
        "rule": {
            "id": "100120",
            "level": severity,
            "description": "Synthetic CQQL validation event",
            "groups": ["web", "authentication"],
            "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]},
        },
        "decoder": {"name": "nginx-accesslog"},
        "data": {"srcip": source_ip, "dstip": "198.51.100.20", "dstport": "443"},
        "full_log": "failed login synthetic CQQL evidence",
    }


def test_parser_applies_not_and_or_precedence() -> None:
    parsed = parse_cqql(
        'NOT event.outcome = "success" OR host.name = "WIN-01" '
        'AND event.severity >= 7'
    )
    assert isinstance(parsed.expression, BooleanExpression)
    assert parsed.expression.operator == "OR"
    assert isinstance(parsed.expression.left, Negation)
    assert isinstance(parsed.expression.right, BooleanExpression)
    assert parsed.expression.right.operator == "AND"
    assert parsed.clause_count == 3


def test_compiler_uses_only_parameters_for_untrusted_values() -> None:
    compiled = compile_cqql('host.name = "x\\\" OR 1=1 --"')
    assert "1=1" not in compiled.sql
    assert compiled.parameters == ('x" OR 1=1 --',)
    assert compiled.sql == "(e.hostname = ? COLLATE NOCASE)"


def test_compiler_validates_ips_numbers_mitre_and_literal_fts() -> None:
    compiled = compile_cqql(
        'source.ip = "2001:0db8::1" AND event.severity >= 8 '
        'AND mitre.id = "t1110" AND text CONTAINS "failed OR login*"'
    )
    assert compiled.parameters == (
        "2001:db8::1",
        8,
        "T1110",
        '"failed" AND "or" AND "login"',
    )
    assert compiled.uses_fts is True
    assert "MATCH ?" in compiled.sql
    assert "login*" not in compiled.sql


def test_compiler_classifies_cost_and_only_hints_safe_same_field_or() -> None:
    broad_or = compile_cqql('event.code = "4625" OR event.code = "4688"')
    assert broad_or.cost_class == "HIGH"
    assert broad_or.plan_class == "BOOLEAN_COMPLEX"
    assert broad_or.planner_strategy == "TIME_ORDERED_OR"
    assert broad_or.referenced_fields == ("event.code",)

    mixed_or = compile_cqql('event.code = "4625" OR source.ip = "192.0.2.10"')
    assert mixed_or.planner_strategy == "DEFAULT"
    fts = compile_cqql('text CONTAINS "failed login"')
    assert fts.cost_class == "HIGH"
    assert fts.plan_class == "FTS_SELECTIVITY_UNKNOWN"
    equality = compile_cqql('source.ip = "192.0.2.10"')
    assert equality.cost_class == "LOW"
    assert equality.plan_class == "INDEX_FRIENDLY"


def test_compiler_only_hints_conservative_nested_boolean_shapes() -> None:
    nested = compile_cqql(
        '(event.code = "4625" OR event.code = "4688") AND event.severity >= 8'
    )
    assert nested.plan_class == "BOOLEAN_COMPLEX"
    assert nested.planner_strategy == "TIME_ORDERED_BOOLEAN"
    assert "TIME_ORDERED_BOOLEAN" in nested.diagnostic_reasons

    two_or_groups = compile_cqql(
        '(event.code = "4625" OR event.code = "4688") AND '
        '(event.outcome = "success" OR event.outcome = "failure")'
    )
    assert two_or_groups.planner_strategy == "TIME_ORDERED_BOOLEAN"

    mixed_or = compile_cqql(
        '(event.code = "4625" OR source.ip = "192.0.2.10") AND event.severity >= 8'
    )
    assert mixed_or.planner_strategy == "DEFAULT"
    assert compile_cqql(
        '(event.code = "4625" OR event.code = "4688") AND text CONTAINS "login"'
    ).planner_strategy == "DEFAULT"
    assert compile_cqql(
        '(event.code = "4625" OR event.code = "4688") AND NOT event.severity = 8'
    ).planner_strategy == "DEFAULT"
    assert compile_cqql('mitre.id = "T1110"').plan_class == "UNKNOWN_COST"
    assert compile_cqql('NOT event.outcome = "success"').plan_class == "RESOURCE_LIMITED"


@pytest.mark.parametrize(
    ("query", "code"),
    [
        ('payload.secret = "x"', "unknown_field"),
        ('event.timestamp >= "2026-01-01T00:00:00Z"', "unsupported_field"),
        ('event.severity = "8"', "type_error"),
        ('source.ip = "999.1.1.1"', "invalid_ip"),
        ('event.code > "4625"', "unsupported_operator"),
        ('text = "failed"', "unsupported_operator"),
        ('mitre.id = "TXYZ"', "invalid_mitre_id"),
        ('event.outcome = "success" trailing', "unexpected_token"),
        ('event.outcome = "unterminated', "unterminated_string"),
    ],
)
def test_parser_rejects_unsupported_or_malformed_queries(query: str, code: str) -> None:
    with pytest.raises(CQQLQueryError) as error:
        compile_cqql(query)
    assert error.value.code == code
    assert error.value.position >= 0


def test_parser_enforces_length_clause_and_depth_limits() -> None:
    with pytest.raises(CQQLQueryError, match="character") as too_long:
        compile_cqql('host.name = "' + "a" * MAX_QUERY_LENGTH + '"')
    assert too_long.value.code == "query_too_long"

    maximum_clauses = " OR ".join(
        'event.code = "4625"' for _ in range(MAX_BOOLEAN_CLAUSES)
    )
    assert compile_cqql(maximum_clauses).clause_count == MAX_BOOLEAN_CLAUSES
    clauses = maximum_clauses + ' OR event.code = "4625"'
    with pytest.raises(CQQLQueryError) as too_many:
        compile_cqql(clauses)
    assert too_many.value.code == "too_many_clauses"

    with pytest.raises(CQQLQueryError) as too_deep:
        compile_cqql("(" * 9 + 'event.code = "4625"' + ")" * 9)
    assert too_deep.value.code == "expression_too_deep"


def test_parser_handles_unicode_as_data() -> None:
    parsed = parse_cqql('host.name = "ҚАЛҚОН-01"')
    assert isinstance(parsed.expression, Comparison)
    assert parsed.expression.value == "ҚАЛҚОН-01"


def test_m27_labeled_synthetic_search_quality_dataset(client, auth_headers) -> None:
    fixture_path = Path(__file__).parent / "fixtures" / "cqql_m27_search_quality.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert fixture["synthetic_only"] is True
    base = datetime.fromisoformat(fixture["base_time"])
    event_ids: dict[str, str] = {}
    for item in fixture["events"]:
        timestamp = base + timedelta(seconds=int(item["offset"]))
        payload = {
            "timestamp": timestamp.isoformat(),
            "id": f"m27-quality-{item['label']}",
            "agent": {"id": item["agent_id"], "name": item["agent"]},
            "rule": {
                "id": item["rule_id"],
                "level": item["level"],
                "description": item["description"],
                "groups": item["groups"],
                "mitre": {"id": item["mitre"], "tactic": [], "technique": []},
            },
            "decoder": {"name": item["decoder"]},
            "data": {"srcip": item["source_ip"]},
            "full_log": item["full_log"],
        }
        response = client.post("/api/v1/events/ingest", headers=auth_headers, json=payload)
        assert response.status_code == 201, response.text
        event_ids[item["label"]] = response.json()["event"]["event_id"]

    for case in fixture["queries"]:
        response = client.post(
            "/api/v1/siem/search",
            json={
                "query": case["cqql"],
                "start_time": (base - timedelta(minutes=1)).isoformat(),
                "end_time": (base + timedelta(minutes=1)).isoformat(),
                "sort": "newest",
                "limit": 100,
            },
        )
        assert response.status_code == 200, (case["name"], response.text)
        actual = {item["event_id"] for item in response.json()["items"]}
        expected = {event_ids[label] for label in case["expected_labels"]}
        assert actual == expected, case["name"]
        assert len(response.json()["items"]) == len(actual)


def test_search_api_is_authenticated_parameterized_and_keyset_paginated(
    client,
    auth_headers,
) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    for index in range(3):
        response = client.post(
            "/api/v1/events/ingest",
            headers=auth_headers,
            json=event_payload(f"cqql-{index}", now - timedelta(seconds=index)),
        )
        assert response.status_code == 201, response.text

    request = {
        "query": 'source.ip = "192.0.2.10" AND event.severity >= 8',
        "start_time": (now - timedelta(hours=1)).isoformat(),
        "end_time": (now + timedelta(minutes=1)).isoformat(),
        "limit": 1,
        "sort": "newest",
    }
    first = client.post("/api/v1/siem/search", json=request)
    assert first.status_code == 200, first.text
    body = first.json()
    assert len(body["items"]) == 1
    assert body["page"]["count_mode"] == "UNKNOWN"
    assert "total" not in body["page"]
    assert body["page"]["next_cursor"]
    assert body["metadata"]["query_status"] == "COMPLETE"
    assert body["metadata"]["clause_count"] == 2
    assert first.headers["x-cqql-version"] == "cqql-v1"
    assert first.headers["cache-control"] == "no-store"

    cursor = body["page"]["next_cursor"]
    tampered_cursor = ("A" if cursor[0] != "A" else "B") + cursor[1:]
    tampered = client.post(
        "/api/v1/siem/search",
        json={**request, "cursor": tampered_cursor},
    )
    assert tampered.status_code == 422
    assert tampered.json()["detail"]["code"] == "invalid_cursor"

    second = client.post(
        "/api/v1/siem/search",
        json={**request, "cursor": body["page"]["next_cursor"]},
    )
    assert second.status_code == 200
    assert second.json()["items"][0]["event_id"] != body["items"][0]["event_id"]

    mismatched = client.post(
        "/api/v1/siem/search",
        json={
            **request,
            "query": 'source.ip = "192.0.2.11"',
            "cursor": body["page"]["next_cursor"],
        },
    )
    assert mismatched.status_code == 422
    assert mismatched.json()["detail"]["code"] == "invalid_cursor"


@pytest.mark.parametrize("sort", ["newest", "oldest"])
def test_time_ordered_or_is_equivalent_to_reference_with_nulls_and_pagination(
    client, auth_headers, database_path, sort
) -> None:
    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(minutes=5)
    event_ids: list[str] = []
    for index, rule_id in enumerate(("100120", "100121", "100120", "100122", "100121", "100120")):
        payload = event_payload(f"cqql-or-{sort}-{index}", start + timedelta(minutes=index))
        payload["rule"]["id"] = rule_id
        response = client.post("/api/v1/events/ingest", headers=auth_headers, json=payload)
        assert response.status_code == 201, response.text
        event_ids.append(response.json()["event"]["event_id"])
    with sqlite3.connect(database_path) as connection:
        connection.execute("UPDATE security_events SET rule_id=NULL WHERE event_id=?", (event_ids[3],))

    compiled = compile_cqql('rule.id = "100120" OR rule.id = "100121"')
    direction = "DESC" if sort == "newest" else "ASC"
    with sqlite3.connect(database_path) as connection:
        reference = [
            str(row[0]) for row in connection.execute(
                f"SELECT e.event_id FROM security_events e "
                f"WHERE e.occurred_at BETWEEN ? AND ? AND {compiled.sql} "
                f"ORDER BY e.occurred_at {direction}, e.event_id {direction}",
                (start.isoformat(), end.isoformat(), *compiled.parameters),
            )
        ]

    repository = CQQLSearchRepository(database_path)
    actual: list[str] = []
    cursor = None
    while True:
        page = repository.search(
            compiled, start_time=start, end_time=end, sort=sort,
            limit=2, cursor=cursor,
        )
        actual.extend(item.event_id for item in page.items)
        cursor = page.next_cursor
        if cursor is None:
            break
    assert actual == reference
    assert len(actual) == len(set(actual))


@pytest.mark.parametrize("sort", ["newest", "oldest"])
def test_time_ordered_nested_boolean_is_equivalent_to_default_planner(
    client, auth_headers, database_path, sort
) -> None:
    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(minutes=12)
    event_ids: list[str] = []
    for index, (rule_id, severity) in enumerate(
        (
            ("100120", 7), ("100121", 8), ("100120", 9), ("100122", 10),
            ("100121", 11), ("100120", 12), ("100121", 3), ("100120", 8),
        )
    ):
        payload = event_payload(
            f"cqql-m27-{sort}-{index}",
            start + timedelta(minutes=index),
            severity=severity,
        )
        payload["rule"]["id"] = rule_id
        response = client.post("/api/v1/events/ingest", headers=auth_headers, json=payload)
        assert response.status_code == 201, response.text
        event_ids.append(response.json()["event"]["event_id"])
    with sqlite3.connect(database_path) as connection:
        connection.execute("UPDATE security_events SET severity=NULL WHERE event_id=?", (event_ids[6],))

    compiled = compile_cqql(
        '(rule.id = "100120" OR rule.id = "100121") AND event.severity >= 8'
    )
    assert compiled.planner_strategy == "TIME_ORDERED_BOOLEAN"
    reference_compiled = replace(compiled, planner_strategy="DEFAULT")
    repository = CQQLSearchRepository(database_path)

    def collect(candidate) -> list[str]:
        actual: list[str] = []
        cursor = None
        while True:
            page = repository.search(
                candidate,
                start_time=start,
                end_time=end,
                sort=sort,
                limit=2,
                cursor=cursor,
            )
            actual.extend(item.event_id for item in page.items)
            cursor = page.next_cursor
            if cursor is None:
                return actual

    optimized = collect(compiled)
    reference = collect(reference_compiled)
    assert optimized == reference
    assert len(optimized) == len(set(optimized))


def test_search_api_rejects_unauthenticated_unbounded_and_invalid_requests(
    unauthenticated_client,
    client,
) -> None:
    now = datetime.now(timezone.utc)
    payload = {
        "query": 'event.code = "4625"',
        "start_time": (now - timedelta(hours=1)).isoformat(),
        "end_time": now.isoformat(),
    }
    assert unauthenticated_client.post("/api/v1/siem/search", json=payload).status_code == 401
    assert unauthenticated_client.get("/api/v1/siem/search/fields").status_code == 401
    assert unauthenticated_client.post(
        "/api/v1/siem/search/analytics",
        json={**payload, "group_by": ["source.ip"]},
    ).status_code == 401
    assert unauthenticated_client.post(
        "/api/v1/siem/search/export.csv",
        json={**payload, "fields": ["event_id"]},
    ).status_code == 401
    missing_range = client.post(
        "/api/v1/siem/search", json={"query": 'event.code = "4625"'}
    )
    assert missing_range.status_code == 422
    invalid_sort = client.post(
        "/api/v1/siem/search", json={**payload, "sort": "occurred_at; DROP TABLE alerts"}
    )
    assert invalid_sort.status_code == 422
    naive_time = client.post(
        "/api/v1/siem/search",
        json={**payload, "start_time": "2026-10-21T01:00:00"},
    )
    assert naive_time.status_code == 422
    oversized_range = client.post(
        "/api/v1/siem/search",
        json={
            **payload,
            "start_time": (now - timedelta(days=32)).isoformat(),
        },
    )
    assert oversized_range.status_code == 422
    sensitive_export = client.post(
        "/api/v1/siem/search/export.csv",
        json={**payload, "fields": ["raw_event_json"]},
    )
    assert sensitive_export.status_code == 422


def test_search_catalog_and_analytics_are_bounded(client, auth_headers) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    for index, source in enumerate(("192.0.2.10", "192.0.2.10", "192.0.2.11")):
        assert client.post(
            "/api/v1/events/ingest",
            headers=auth_headers,
            json=event_payload(f"analytics-{index}", now - timedelta(minutes=index), source_ip=source),
        ).status_code == 201

    catalog = client.get("/api/v1/siem/search/fields")
    assert catalog.status_code == 200
    fields = {field["name"]: field for field in catalog.json()["fields"]}
    assert fields["event.timestamp"]["searchable"] is False
    assert fields["source.ip"]["indexed"] is True
    assert fields["event.channel"]["indexed"] is False
    assert catalog.json()["limits"]["maximum_boolean_clauses"] == MAX_BOOLEAN_CLAUSES

    analytics = client.post(
        "/api/v1/siem/search/analytics",
        json={
            "query": "event.severity >= 0",
            "start_time": (now - timedelta(hours=1)).isoformat(),
            "end_time": (now + timedelta(minutes=1)).isoformat(),
            "group_by": ["source.ip", "event.severity"],
            "top_n": 1,
            "interval": "hour",
        },
    )
    assert analytics.status_code == 200, analytics.text
    body = analytics.json()
    assert body["matching_events"] == 3
    assert body["completeness"] == "EXACT_WITHIN_BOUNDED_RANGE"
    assert body["sparse_time_series"] is True
    assert body["groups"][0]["buckets"][0] == {"name": "192.0.2.10", "count": 2}
    assert body["groups"][0]["truncated"] is True


def test_search_deadline_and_concurrency_fail_closed(client, monkeypatch) -> None:
    now = datetime.now(timezone.utc)
    request = {
        "query": 'event.code = "4625"',
        "start_time": (now - timedelta(hours=1)).isoformat(),
        "end_time": now.isoformat(),
    }
    repository = client.app.state.cqql_search_repository
    monkeypatch.setattr(
        repository,
        "_install_deadline",
        lambda connection, _deadline, _cancel=None: connection.set_progress_handler(lambda: 1, 1),
    )
    timeout = client.post("/api/v1/siem/search", json=request)
    assert timeout.status_code == 408
    assert timeout.json()["detail"]["code"] == "query_timeout"

    monkeypatch.undo()
    for _ in range(CQQL_MAX_CONCURRENT_QUERIES):
        assert repository._slots.acquire(timeout=0.1)  # noqa: SLF001 - intentional capacity test
    try:
        busy = client.post("/api/v1/siem/search", json=request)
        assert busy.status_code == 429
        assert busy.json()["detail"]["code"] == "query_capacity_exceeded"
    finally:
        for _ in range(CQQL_MAX_CONCURRENT_QUERIES):
            repository._slots.release()  # noqa: SLF001


def test_search_is_read_only(client, database_path) -> None:
    now = datetime.now(timezone.utc)
    with sqlite3.connect(database_path) as connection:
        before = connection.total_changes
        event_count = connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
    response = client.post(
        "/api/v1/siem/search",
        json={
            "query": 'text CONTAINS "nothing synthetic"',
            "start_time": (now - timedelta(days=1)).isoformat(),
            "end_time": now.isoformat(),
        },
    )
    assert response.status_code == 200
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == event_count
        assert connection.total_changes == before


def test_connection_local_cancellation_interrupts_execution_and_queue(database_path) -> None:
    repository = CQQLSearchRepository(database_path)
    cancellation = threading.Event()
    with sqlite3.connect(":memory:") as connection:
        repository._install_deadline(  # noqa: SLF001 - explicit interrupt contract test
            connection, time.perf_counter() + 5, cancellation
        )
        timer = threading.Timer(0.01, cancellation.set)
        timer.start()
        try:
            with pytest.raises(sqlite3.OperationalError, match="interrupted"):
                connection.execute(
                    "WITH RECURSIVE count(value) AS (VALUES(0) UNION ALL "
                    "SELECT value + 1 FROM count WHERE value < 100000000) "
                    "SELECT SUM(value) FROM count"
                ).fetchone()
        finally:
            timer.cancel()
            connection.set_progress_handler(None, 0)
    translated = repository._translate_sqlite(  # noqa: SLF001
        sqlite3.OperationalError("interrupted"), cancellation
    )
    assert isinstance(translated, CQQLQueryCancelledError)

    for _ in range(CQQL_MAX_CONCURRENT_QUERIES):
        assert repository._slots.acquire(timeout=0.1)  # noqa: SLF001
    queued_cancel = threading.Event()
    queued_cancel.set()
    queued_cancel.set()  # cancellation is intentionally idempotent
    try:
        with pytest.raises(CQQLQueryCancelledError, match="before execution"):
            repository.search(
                compile_cqql('event.code = "4625"'),
                start_time=datetime.now(timezone.utc) - timedelta(hours=1),
                end_time=datetime.now(timezone.utc),
                sort="newest", limit=10, cursor=None,
                cancel_event=queued_cancel,
            )
    finally:
        for _ in range(CQQL_MAX_CONCURRENT_QUERIES):
            repository._slots.release()  # noqa: SLF001


def test_asgi_disconnect_and_task_cancellation_join_the_sqlite_worker() -> None:
    class DisconnectingRequest:
        async def is_disconnected(self) -> bool:
            return True

    class ConnectedRequest:
        async def is_disconnected(self) -> bool:
            return False

    def blocking_worker(*, cancel_event: threading.Event) -> None:
        worker_started.set()
        if not cancel_event.wait(1):
            raise AssertionError("cancellation was not propagated to the worker")
        worker_released.set()
        raise CQQLQueryCancelledError("worker cancellation acknowledged")

    async def disconnected_client() -> None:
        with pytest.raises(CQQLQueryCancelledError, match="cancelled by the client"):
            await _run_cancellable(DisconnectingRequest(), blocking_worker)

    worker_started = threading.Event()
    worker_released = threading.Event()
    asyncio.run(disconnected_client())
    assert worker_started.is_set()
    assert worker_released.is_set()

    async def cancelled_asgi_task() -> None:
        task = asyncio.create_task(_run_cancellable(ConnectedRequest(), blocking_worker))
        while not worker_started.is_set():
            await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    worker_started.clear()
    worker_released.clear()
    asyncio.run(cancelled_asgi_task())
    assert worker_released.is_set()


def test_asgi_receive_disconnect_cancels_and_joins_worker() -> None:
    class TransportRequest:
        async def receive(self) -> dict[str, str]:
            await transport_ready.wait()
            return {"type": "http.disconnect"}

    def blocking_worker(*, cancel_event: threading.Event) -> None:
        worker_started.set()
        if not cancel_event.wait(1):
            raise AssertionError("ASGI transport disconnect was not propagated")
        worker_released.set()
        raise CQQLQueryCancelledError("worker cancellation acknowledged")

    async def execute() -> None:
        task = asyncio.create_task(_run_cancellable(TransportRequest(), blocking_worker))
        while not worker_started.is_set():
            await asyncio.sleep(0)
        transport_ready.set()
        with pytest.raises(CQQLQueryCancelledError, match="cancelled by the client"):
            await task

    worker_started = threading.Event()
    worker_released = threading.Event()
    transport_ready = asyncio.Event()
    asyncio.run(execute())
    assert worker_released.is_set()


def test_cqql_csv_export_is_bounded_neutralized_and_audited(
    client, auth_headers, monkeypatch
) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload = event_payload("cqql-export", now)
    payload["rule"]["description"] = "=WEBSERVICE(\"https://invalid.example\")"
    assert client.post("/api/v1/events/ingest", headers=auth_headers, json=payload).status_code == 201
    raw_query = 'rule.id = "100120"'
    request = {
        "query": raw_query,
        "start_time": (now - timedelta(minutes=1)).isoformat(),
        "end_time": (now + timedelta(minutes=1)).isoformat(),
        "fields": ["message", "event_id"],
        "limit": 1000,
    }
    exported = client.post("/api/v1/siem/search/export.csv", json=request)
    assert exported.status_code == 200, exported.text
    assert exported.headers["x-cqql-export-rows"] == "1"
    assert exported.headers["x-cqql-export-truncated"] == "false"
    assert "'=WEBSERVICE" in exported.text
    assert len(exported.content) <= 1_000_000

    audit = client.app.state.audit_repository.list(action="CQQL_RESULTS_EXPORTED", limit=1)[0]
    assert audit.details["rows_exported"] == 1
    assert audit.details["query_fingerprint"] == compile_cqql(raw_query).fingerprint
    assert raw_query not in str(audit.details)

    monkeypatch.setattr("app.api.routes.cqql.CQQL_EXPORT_BYTE_LIMIT", 20)
    truncated = client.post("/api/v1/siem/search/export.csv", json=request)
    assert truncated.status_code == 200
    assert truncated.headers["x-cqql-export-truncated"] == "true"
    assert len(truncated.content) <= 20


def test_cqql_is_preserved_in_owned_saved_searches(client) -> None:
    created = client.post(
        "/api/v1/events/saved-searches",
        json={
            "name": "CQQL failed logons",
            "query": {
                "relative_minutes": 1_440,
                "cqql": 'event.code = "4625" AND event.outcome = "failure"',
                "sort": "newest",
            },
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["query"]["cqql"] == 'event.code = "4625" AND event.outcome = "failure"'
    listed = client.get("/api/v1/events/saved-searches")
    assert listed.status_code == 200
    assert listed.json()[0]["query"]["cqql"] == created.json()["query"]["cqql"]

    invalid = client.post(
        "/api/v1/events/saved-searches",
        json={
            "name": "Unsafe",
            "query": {"relative_minutes": 60, "cqql": 'payload.secret = "x"'},
        },
    )
    assert invalid.status_code == 422

    ambiguous = client.post(
        "/api/v1/events/saved-searches",
        json={
            "name": "Ambiguous",
            "query": {
                "relative_minutes": 60,
                "cqql": 'event.code = "4625"',
                "source_ip": "192.0.2.10",
            },
        },
    )
    assert ambiguous.status_code == 422


def test_threat_hunts_combine_cqql_without_creating_detections(client, auth_headers) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    assert client.post(
        "/api/v1/events/ingest",
        headers=auth_headers,
        json=event_payload("cqql-hunt", now, severity=10),
    ).status_code == 201
    hunted = client.get(
        "/api/v1/threat-hunts",
        params={
            "relative_minutes": 15,
            "cqql": 'source.ip = "192.0.2.10" AND event.severity >= 10',
        },
    )
    assert hunted.status_code == 200, hunted.text
    assert hunted.json()["total"] == 1
    assert hunted.json()["items"][0]["event_id"].startswith("EVT-")

    saved = client.post(
        "/api/v1/threat-hunts/saved",
        json={
            "name": "High severity source",
            "query": {
                "relative_minutes": 15,
                "cqql": 'source.ip = "192.0.2.10" AND event.severity >= 10',
            },
        },
    )
    assert saved.status_code == 201, saved.text
    assert saved.json()["query"]["cqql"].startswith("source.ip")

    with sqlite3.connect(client.app.state.event_repository.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 0


def test_threat_hunt_cqql_deadline_and_capacity_fail_closed(client, monkeypatch) -> None:
    repository = client.app.state.detection_engineering_repository
    monkeypatch.setattr(
        repository,
        "_install_hunt_deadline",
        lambda connection, _deadline: connection.set_progress_handler(lambda: 1, 1),
    )
    timeout = client.get(
        "/api/v1/threat-hunts",
        params={"relative_minutes": 15, "cqql": 'event.code = "4625"'},
    )
    assert timeout.status_code == 408
    assert timeout.json()["detail"]["code"] == "query_timeout"

    monkeypatch.undo()
    for _ in range(4):
        assert repository._hunt_slots.acquire(timeout=0.1)  # noqa: SLF001
    try:
        busy = client.get(
            "/api/v1/threat-hunts",
            params={"relative_minutes": 15, "cqql": 'event.code = "4625"'},
        )
        assert busy.status_code == 429
        assert busy.json()["detail"]["code"] == "query_capacity_exceeded"
    finally:
        for _ in range(4):
            repository._hunt_slots.release()  # noqa: SLF001
