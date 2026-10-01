from __future__ import annotations

from io import StringIO
import logging
import sqlite3
import threading
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from app.db.base import Base
from app.db.session import create_database_engine, get_db
from app.db.sqlite_diagnostics import inspect_sqlite_foreign_keys
from app.main import app
from app.models.incident import Incident
from app.models.review import Review


def _database_url(path) -> str:
    return f"sqlite:///{path.as_posix()}"


def _incident(identifier: str) -> Incident:
    return Incident(
        id=identifier,
        dedupe_key=f"dedupe-{identifier}",
        raw_event={"synthetic": True},
        severity="low",
        priority_score=1,
    )


def test_sqlite_connection_uses_configured_busy_timeout_and_safe_default_gate(tmp_path):
    engine = create_database_engine(_database_url(tmp_path / "settings.db"), sqlite_busy_timeout_ms=275)
    try:
        with engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA busy_timeout").scalar_one() == 275
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 0
    finally:
        engine.dispose()


def test_write_contention_succeeds_when_lock_clears_before_timeout(tmp_path):
    database_url = _database_url(tmp_path / "resolved-lock.db")
    holder_engine = create_database_engine(database_url, sqlite_busy_timeout_ms=1_000)
    writer_engine = create_database_engine(database_url, sqlite_busy_timeout_ms=1_000)
    with holder_engine.begin() as connection:
        connection.execute(text("CREATE TABLE writes (value TEXT)"))

    holder = holder_engine.connect()
    holder.exec_driver_sql("BEGIN IMMEDIATE")
    holder.execute(text("INSERT INTO writes VALUES ('holder')"))
    release = threading.Timer(0.15, holder.commit)
    release.start()
    started = time.monotonic()
    try:
        with writer_engine.begin() as connection:
            connection.execute(text("INSERT INTO writes VALUES ('writer')"))
        elapsed = time.monotonic() - started
        assert 0.10 <= elapsed < 3.0
        with writer_engine.connect() as connection:
            assert connection.scalar(text("SELECT COUNT(*) FROM writes")) == 2
    finally:
        release.join(timeout=1)
        holder.close()
        holder_engine.dispose()
        writer_engine.dispose()


def test_persistent_write_contention_fails_after_configured_timeout(tmp_path):
    database_url = _database_url(tmp_path / "persistent-lock.db")
    holder_engine = create_database_engine(database_url, sqlite_busy_timeout_ms=200)
    writer_engine = create_database_engine(database_url, sqlite_busy_timeout_ms=200)
    with holder_engine.begin() as connection:
        connection.execute(text("CREATE TABLE writes (value TEXT)"))

    holder = holder_engine.connect()
    holder.exec_driver_sql("BEGIN IMMEDIATE")
    holder.execute(text("INSERT INTO writes VALUES ('holder')"))
    started = time.monotonic()
    try:
        with pytest.raises(OperationalError, match="database is locked") as caught:
            with writer_engine.begin() as connection:
                connection.execute(text("INSERT INTO writes VALUES (:value)"), {"value": "synthetic-event"})
        elapsed = time.monotonic() - started
        assert 0.15 <= elapsed < 1.5
        assert "synthetic-event" not in str(caught.value)
    finally:
        holder.rollback()
        holder.close()
        holder_engine.dispose()
        writer_engine.dispose()


def test_foreign_key_gate_enforces_actual_review_relationship_and_cascade(tmp_path):
    engine = create_database_engine(
        _database_url(tmp_path / "foreign-keys.db"),
        sqlite_foreign_keys=True,
    )
    Base.metadata.create_all(engine)
    try:
        first = engine.connect()
        second = engine.connect()
        try:
            assert first.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
            assert second.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
        finally:
            first.close()
            second.close()

        with Session(engine) as session:
            incident = _incident("parent")
            incident.reviews.append(
                Review(id="valid-review", status="confirmed", analyst="synthetic-analyst")
            )
            session.add(incident)
            session.commit()

        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO reviews "
                        "(id, incident_id, status, analyst, created_at) "
                        "VALUES ('orphan', 'missing', 'confirmed', 'synthetic', CURRENT_TIMESTAMP)"
                    )
                )

        with engine.begin() as connection:
            connection.execute(text("DELETE FROM incidents WHERE id = 'parent'"))
            assert connection.scalar(text("SELECT COUNT(*) FROM reviews")) == 0
    finally:
        engine.dispose()


def test_foreign_key_diagnostic_reports_orphan_without_modifying_data(tmp_path):
    engine = create_database_engine(_database_url(tmp_path / "diagnostic.db"))
    Base.metadata.create_all(engine)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO reviews "
                    "(id, incident_id, status, analyst, created_at) "
                    "VALUES ('orphan', 'missing', 'confirmed', 'synthetic', CURRENT_TIMESTAMP)"
                )
            )
        violations = inspect_sqlite_foreign_keys(engine)
        assert len(violations) == 1
        assert violations[0].table == "reviews"
        assert violations[0].parent == "incidents"
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT COUNT(*) FROM reviews")) == 1
    finally:
        engine.dispose()


def test_failed_transaction_rolls_back_all_writes_and_session_recovers(tmp_path):
    engine = create_database_engine(
        _database_url(tmp_path / "rollback.db"),
        sqlite_foreign_keys=True,
    )
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as session:
            session.add(_incident("rolled-back-parent"))
            session.add(
                Review(
                    id="invalid-review",
                    incident_id="missing-parent",
                    status="confirmed",
                    analyst="synthetic-analyst",
                )
            )
            with pytest.raises(IntegrityError):
                session.commit()
            session.rollback()
            assert session.scalar(select(func.count()).select_from(Incident)) == 0

            session.add(_incident("recovered-parent"))
            session.commit()
            assert session.scalar(select(func.count()).select_from(Incident)) == 1
    finally:
        engine.dispose()


def test_database_failure_response_and_log_do_not_expose_bound_parameters():
    secret = "SYNTHETIC-EVENT-SECRET-31c8"

    def unavailable_database():
        raise OperationalError(
            "SELECT :secret",
            {"secret": secret},
            sqlite3.OperationalError("synthetic database unavailable"),
            hide_parameters=True,
        )
        yield

    app.dependency_overrides[get_db] = unavailable_database
    client = TestClient(app, raise_server_exceptions=False)
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
    application_logger = logging.getLogger("app.main")
    previous_level = application_logger.level
    previous_disabled = application_logger.disabled
    application_logger.setLevel(logging.ERROR)
    application_logger.disabled = False
    application_logger.addHandler(handler)
    try:
        response = client.get("/ready")
        rendered_log = stream.getvalue()
        assert response.status_code == 503
        assert response.json() == {
            "error": {
                "code": "DATABASE_UNAVAILABLE",
                "message": "Database unavailable",
            }
        }
        assert secret not in response.text
        assert secret not in rendered_log
        assert "SQL parameters hidden due to hide_parameters=True" in rendered_log
    finally:
        application_logger.removeHandler(handler)
        application_logger.setLevel(previous_level)
        application_logger.disabled = previous_disabled
        handler.close()
        client.close()
        app.dependency_overrides.clear()
