"""Bounded AI context reads and append-only analysis persistence."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from app.schemas.ai import AIAnalysisRecord
from app.services.wazuh_normalizer import canonical_json


class AIRepository:
    def __init__(self, database_path: Path) -> None:
        self.path = database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def alert_material(self, alert_id: str) -> dict | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT normalized_json, raw_event_json, ingested_at FROM alerts WHERE alert_id = ?",
                (alert_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "normalized": json.loads(row["normalized_json"]),
            "raw_event": json.loads(row["raw_event_json"]),
            "target_updated_at": row["ingested_at"],
        }

    def incident_material(
        self,
        incident_id: str,
        *,
        alert_limit: int,
        note_limit: int,
        history_limit: int,
    ) -> dict | None:
        with self._connect() as connection:
            incident = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            if incident is None:
                return None
            counts = {
                "alerts": int(connection.execute(
                    "SELECT COUNT(*) FROM incident_alerts WHERE incident_id = ?", (incident_id,)
                ).fetchone()[0]),
                "notes": int(connection.execute(
                    "SELECT COUNT(*) FROM incident_notes WHERE incident_id = ?", (incident_id,)
                ).fetchone()[0]),
                "history": int(connection.execute(
                    "SELECT COUNT(*) FROM incident_history WHERE incident_id = ?", (incident_id,)
                ).fetchone()[0]),
            }
            alerts = connection.execute(
                """
                SELECT a.normalized_json
                FROM incident_alerts ia
                JOIN alerts a ON a.alert_id = ia.alert_id
                WHERE ia.incident_id = ?
                ORDER BY a.rule_level DESC, a.occurred_at DESC, a.alert_id DESC
                LIMIT ?
                """,
                (incident_id, alert_limit),
            ).fetchall()
            notes = connection.execute(
                """
                SELECT note_id, body, author, author_id, created_at
                FROM incident_notes WHERE incident_id = ?
                ORDER BY created_at DESC, note_id DESC LIMIT ?
                """,
                (incident_id, note_limit),
            ).fetchall()
            history = connection.execute(
                """
                SELECT event_id, event_type, actor_display, actor, actor_id,
                       occurred_at, details_json
                FROM incident_history WHERE incident_id = ?
                ORDER BY history_id DESC LIMIT ?
                """,
                (incident_id, history_limit),
            ).fetchall()
        return {
            "incident": dict(incident),
            "alerts": [json.loads(row["normalized_json"]) for row in alerts],
            "notes": [dict(row) for row in notes],
            "history": [
                {
                    "event_id": row["event_id"],
                    "event_type": row["event_type"],
                    "actor": row["actor_display"] or row["actor"],
                    "actor_id": row["actor_id"],
                    "occurred_at": row["occurred_at"],
                    "details": json.loads(row["details_json"]),
                }
                for row in history
            ],
            "counts": counts,
            "target_updated_at": incident["updated_at"],
        }

    def insert(self, record: AIAnalysisRecord, *, target_updated_at: str | None) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO ai_analyses (
                    analysis_id, analysis_type, target_type, target_id,
                    requested_by, requested_by_display, requested_at, completed_at,
                    provider, model, model_digest, policy_version, schema_version,
                    context_fingerprint, context_bytes, context_truncated,
                    context_metadata_json, target_updated_at, result_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.analysis_id,
                    record.analysis_type.value,
                    record.target_type.value,
                    record.target_id,
                    record.requested_by.analyst_id,
                    record.requested_by.display,
                    record.requested_at.isoformat(),
                    record.completed_at.isoformat(),
                    record.provider,
                    record.model,
                    record.model_digest,
                    record.policy_version,
                    record.schema_version,
                    record.context_fingerprint,
                    record.context.context_bytes,
                    int(record.context.truncated),
                    canonical_json(record.context.model_dump(mode="json")),
                    target_updated_at,
                    canonical_json(record.result.model_dump(mode="json")),
                ),
            )

    @staticmethod
    def _record(row: sqlite3.Row, *, stale: bool) -> AIAnalysisRecord:
        return AIAnalysisRecord.model_validate(
            {
                "analysis_id": row["analysis_id"],
                "analysis_type": row["analysis_type"],
                "target_type": row["target_type"],
                "target_id": row["target_id"],
                "requested_by": {
                    "analyst_id": row["requested_by"],
                    "display": row["requested_by_display"],
                },
                "requested_at": row["requested_at"],
                "completed_at": row["completed_at"],
                "provider": row["provider"],
                "model": row["model"],
                "model_digest": row["model_digest"],
                "policy_version": row["policy_version"],
                "schema_version": row["schema_version"],
                "context_fingerprint": row["context_fingerprint"],
                "context": json.loads(row["context_metadata_json"]),
                "stale": stale,
                "result": json.loads(row["result_json"]),
            }
        )

    def get(self, analysis_id: str) -> AIAnalysisRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM ai_analyses WHERE analysis_id = ?", (analysis_id,)
            ).fetchone()
        return None if row is None else self._record(row, stale=False)

    def list_for_target(self, target_type: str, target_id: str, *, limit: int) -> list[AIAnalysisRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM ai_analyses
                WHERE target_type = ? AND target_id = ?
                ORDER BY completed_at DESC, analysis_id DESC LIMIT ?
                """,
                (target_type, target_id, limit),
            ).fetchall()
        return [self._record(row, stale=False) for row in rows]
