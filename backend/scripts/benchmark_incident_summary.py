"""Reproducible legacy-list versus lightweight-summary benchmark.

Uses only synthetic incidents in an in-memory SQLite database. Run from the
backend directory with::

    .venv\Scripts\python.exe scripts\benchmark_incident_summary.py
"""

from __future__ import annotations

import argparse
import json
import logging
import statistics
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import perf_counter
from typing import Any, Callable

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.security import require_api_auth  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.session import get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models.incident import Incident  # noqa: E402
from app.repositories.incidents import IncidentRepository  # noqa: E402
from app.schemas.incident import (  # noqa: E402
    IncidentListResponse,
    IncidentResponse,
    IncidentSummaryListResponse,
    IncidentSummaryResponse,
)


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]


def measure(call: Callable[[], Any], repeats: int) -> list[float]:
    timings: list[float] = []
    for _ in range(repeats):
        started = perf_counter()
        call()
        timings.append((perf_counter() - started) * 1000)
    return timings


def timing_stats(values: list[float]) -> dict[str, float]:
    return {
        "median_ms": round(statistics.median(values), 3),
        "p95_ms": round(percentile(values, 0.95), 3),
    }


def create_incidents(count: int, evidence_chars: int) -> list[Incident]:
    created = datetime(2026, 9, 30, 16, 0, tzinfo=timezone.utc)
    evidence = "x" * evidence_chars
    rows: list[Incident] = []
    for index in range(count):
        level = (index % 15) + 1
        severity = "critical" if level >= 12 else "high" if level >= 8 else "medium" if level >= 4 else "low"
        rows.append(
            Incident(
                dedupe_key=f"synthetic-benchmark-{index}",
                alert_id=f"benchmark-{index}",
                event_timestamp=created + timedelta(seconds=index),
                created_at=created + timedelta(seconds=index),
                updated_at=created + timedelta(seconds=index),
                agent_id="001",
                agent_name="BENCH-ENDPOINT",
                agent_ip="192.0.2.10",
                rule_id="5710",
                rule_level=level,
                rule_description="Synthetic benchmark authentication event",
                rule_metadata={"description": "synthetic", "payload": evidence},
                mitre_ids=["T1110"],
                mitre_tactics=["Credential Access"],
                mitre_techniques=["Brute Force"],
                source_ip="198.51.100.20",
                destination_ip="192.0.2.10",
                decoder={"name": "synthetic", "payload": evidence},
                full_log=evidence,
                raw_event={"synthetic": True, "payload": evidence},
                severity=severity,
                priority_score=level * 5,
                ai_status="not_configured",
                review_status="needs_review",
            )
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--incidents", type=int, default=1_000)
    parser.add_argument("--evidence-chars", type=int, default=20_000)
    parser.add_argument("--page-size", type=int, default=50)
    parser.add_argument("--repeats", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=5)
    args = parser.parse_args()
    logging.getLogger("httpx").setLevel(logging.WARNING)

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with factory() as session:
        session.add_all(create_incidents(args.incidents, args.evidence_chars))
        session.commit()

    def override_get_db():
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[require_api_auth] = lambda: None
    client = TestClient(app)
    query = f"?severity=high&limit={args.page_size}&offset=0"
    paths = {
        "legacy": f"/api/v1/incidents{query}",
        "summary": f"/api/v1/incidents/summary{query}",
    }

    try:
        for _ in range(args.warmups):
            for path in paths.values():
                response = client.get(path)
                response.raise_for_status()

        responses = {name: client.get(path) for name, path in paths.items()}
        endpoint_timings = {
            name: measure(lambda path=path: client.get(path).raise_for_status(), args.repeats)
            for name, path in paths.items()
        }

        sql_by_endpoint: dict[str, list[str]] = {}
        for name, path in paths.items():
            statements: list[str] = []

            def capture(_connection, _cursor, statement, _parameters, _context, _executemany):
                if statement.lstrip().lower().startswith("select"):
                    statements.append(statement)

            event.listen(engine, "before_cursor_execute", capture)
            try:
                client.get(path).raise_for_status()
            finally:
                event.remove(engine, "before_cursor_execute", capture)
            sql_by_endpoint[name] = statements

        filters = {
            "limit": args.page_size,
            "offset": 0,
            "severity": "high",
            "agent": None,
            "mitre_id": None,
        }
        query_timings: dict[str, list[float]] = {"legacy": [], "summary": []}
        serialization_timings: dict[str, list[float]] = {"legacy": [], "summary": []}
        for _ in range(args.repeats):
            with factory() as session:
                repository = IncidentRepository(session)
                started = perf_counter()
                legacy_total, legacy_rows = repository.list(**filters)
                query_timings["legacy"].append((perf_counter() - started) * 1000)
                started = perf_counter()
                legacy_model = IncidentListResponse(
                    total=legacy_total,
                    limit=args.page_size,
                    offset=0,
                    items=[IncidentResponse.model_validate(row) for row in legacy_rows],
                )
                json.dumps(legacy_model.model_dump(mode="json"), separators=(",", ":"))
                serialization_timings["legacy"].append((perf_counter() - started) * 1000)

                started = perf_counter()
                summary_total, summary_rows = repository.list_summaries(**filters)
                query_timings["summary"].append((perf_counter() - started) * 1000)
                started = perf_counter()
                summary_model = IncidentSummaryListResponse(
                    total=summary_total,
                    limit=args.page_size,
                    offset=0,
                    items=[IncidentSummaryResponse.model_validate(row) for row in summary_rows],
                )
                json.dumps(summary_model.model_dump(mode="json"), separators=(",", ":"))
                serialization_timings["summary"].append((perf_counter() - started) * 1000)

        output = {
            "conditions": {
                "database": "SQLite in-memory",
                "synthetic_incidents": args.incidents,
                "evidence_chars_per_large_field": args.evidence_chars,
                "filter": "severity=high",
                "page_size": args.page_size,
                "warmups": args.warmups,
                "measured_repeats": args.repeats,
            },
            "legacy": {
                "payload_bytes": len(responses["legacy"].content),
                "endpoint": timing_stats(endpoint_timings["legacy"]),
                "repository_query": timing_stats(query_timings["legacy"]),
                "serialization": timing_stats(serialization_timings["legacy"]),
                "select_count": len(sql_by_endpoint["legacy"]),
                "selects_large_evidence_columns": any(
                    token in "\n".join(sql_by_endpoint["legacy"]).lower()
                    for token in ("raw_event", "full_log", "decoder", "rule_metadata")
                ),
            },
            "summary": {
                "payload_bytes": len(responses["summary"].content),
                "endpoint": timing_stats(endpoint_timings["summary"]),
                "repository_query": timing_stats(query_timings["summary"]),
                "serialization": timing_stats(serialization_timings["summary"]),
                "select_count": len(sql_by_endpoint["summary"]),
                "selects_large_evidence_columns": any(
                    token in "\n".join(sql_by_endpoint["summary"]).lower()
                    for token in ("raw_event", "full_log", "decoder", "rule_metadata")
                ),
            },
        }
        print(json.dumps(output, indent=2))
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(engine)
        engine.dispose()


if __name__ == "__main__":
    main()
