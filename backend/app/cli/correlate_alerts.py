"""Read-only historical correlation dry-run; this command never writes incidents."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from app.core.config import Settings
from app.db.alerts import AlertRepository
from app.services.incident_correlation import (
    SUPPORTED_RULE_IDS,
    AlertEvidence,
    build_correlation_plan,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", help="Override DATABASE_URL for the read-only scan")
    parser.add_argument("--limit", type=int, default=1000, help="Newest alerts to inspect (1-5000)")
    parser.add_argument("--window-seconds", type=int, help="Override the configured window")
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    if not 1 <= args.limit <= 5000:
        raise SystemExit("--limit must be between 1 and 5000")
    settings = Settings.from_env()
    database_url = args.database_url or settings.database_url
    path: Path = AlertRepository(database_url).path
    window_seconds = args.window_seconds or settings.correlation_window_seconds
    if not 1 <= window_seconds <= 86_400:
        raise SystemExit("--window-seconds must be between 1 and 86400")

    uri = f"file:{path.as_posix()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    placeholders = ", ".join("?" for _ in SUPPORTED_RULE_IDS)
    rows = connection.execute(
        f"""
        SELECT alert_id, occurred_at, normalized_json, raw_event_json
        FROM alerts
        WHERE rule_id IN ({placeholders})
        ORDER BY occurred_at DESC, alert_id DESC
        LIMIT ?
        """,
        (*sorted(SUPPORTED_RULE_IDS), args.limit),
    ).fetchall()
    evidence = [AlertEvidence.from_row(row) for row in reversed(rows)]
    proposals: dict[tuple[str, tuple[str, ...]], dict[str, object]] = {}
    for pivot in evidence:
        nearby = [
            item
            for item in evidence
            if item.agent_id == pivot.agent_id
            and abs((item.occurred_at - pivot.occurred_at).total_seconds()) <= window_seconds
        ][: settings.correlation_max_candidates]
        plan = build_correlation_plan(
            nearby,
            pivot_alert_id=pivot.alert_id,
            window_seconds=window_seconds,
            max_links=settings.correlation_max_links,
        )
        if plan is None:
            continue
        alert_ids = tuple(item.alert_id for item in plan.alerts)
        proposals[(plan.rule_id, alert_ids)] = {
            "correlation_rule": plan.rule_id,
            "classification": plan.classification,
            "confidence": plan.confidence,
            "severity": plan.severity,
            "alert_ids": list(alert_ids),
            "source_identity": plan.source_identity,
            "target_identity": plan.target_identity,
            "first_seen": plan.first_seen.isoformat(),
            "last_seen": plan.last_seen.isoformat(),
            "interval_seconds": plan.interval_seconds,
            "reason": plan.explanation,
        }
    output = {
        "mode": "dry-run",
        "database": str(path),
        "alerts_inspected": len(evidence),
        "window_seconds": window_seconds,
        "candidate_groups": list(proposals.values()),
        "writes_performed": 0,
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
