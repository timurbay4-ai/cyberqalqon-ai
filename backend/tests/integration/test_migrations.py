from datetime import datetime, timezone
from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.schema_verifier import create_read_only_sqlite_engine, verify_database_schema
from app.db.session import get_db
from app.db.sqlite_backup import backup_sqlite_database, inspect_sqlite_database, restore_sqlite_database
from app.main import app
from app.models.incident import Incident
from app.models.review import Review


BACKEND_ROOT = Path(__file__).parents[2]
ALEMBIC_INI = BACKEND_ROOT / "alembic.ini"
BASELINE_REVISION = "20261001_0001"


def alembic_config(database_path: Path) -> Config:
    config = Config(str(ALEMBIC_INI))
    config.attributes["database_url"] = f"sqlite:///{database_path.as_posix()}"
    return config


def assert_verified(database_path: Path, *, allow_alembic_version: bool) -> None:
    engine = create_read_only_sqlite_engine(database_path)
    try:
        report = verify_database_schema(engine, allow_alembic_version=allow_alembic_version)
    finally:
        engine.dispose()
    assert report.valid, report.to_dict()


def test_fresh_upgrade_matches_models_and_supports_application_workflows(tmp_path, wazuh_alert):
    database = tmp_path / "fresh.db"
    config = alembic_config(database)
    command.upgrade(config, "head")

    engine = create_engine(f"sqlite:///{database.as_posix()}")
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    try:
        inspector = inspect(engine)
        assert set(inspector.get_table_names()) == {"alembic_version", "incidents", "reviews"}
        assert_verified(database, allow_alembic_version=True)
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == BASELINE_REVISION
        command.check(config)

        def override_get_db():
            with factory() as session:
                yield session

        app.dependency_overrides[get_db] = override_get_db
        client = TestClient(app)
        try:
            created = client.post("/api/v1/ingest/wazuh", json=wazuh_alert)
            assert created.status_code == 201
            incident_id = created.json()["id"]
            summary = client.get("/api/v1/incidents/summary")
            assert summary.status_code == 200
            assert summary.json()["items"][0]["id"] == incident_id
            reviewed = client.post(
                f"/api/v1/incidents/{incident_id}/review",
                json={"status": "confirmed", "analyst": "migration-test"},
            )
            assert reviewed.status_code == 201
            detail = client.get(f"/api/v1/incidents/{incident_id}")
            assert detail.status_code == 200
            assert detail.json()["review_status"] == "confirmed"
            assert len(detail.json()["reviews"]) == 1
        finally:
            client.close()
            app.dependency_overrides.clear()
    finally:
        engine.dispose()


def test_disposable_database_downgrade_and_reupgrade(tmp_path):
    database = tmp_path / "round-trip.db"
    config = alembic_config(database)
    command.upgrade(config, "head")
    command.downgrade(config, "base")

    engine = create_engine(f"sqlite:///{database.as_posix()}")
    try:
        assert set(inspect(engine).get_table_names()) == {"alembic_version"}
    finally:
        engine.dispose()

    command.upgrade(config, "head")
    assert_verified(database, allow_alembic_version=True)


def test_verified_existing_database_adoption_on_restored_copy(tmp_path):
    original = tmp_path / "representative-original.db"
    backup = tmp_path / "representative-backup.db"
    adopted_copy = tmp_path / "representative-adopted.db"
    original_engine = create_engine(f"sqlite:///{original.as_posix()}")
    Base.metadata.create_all(original_engine)
    now = datetime(2026, 10, 1, tzinfo=timezone.utc)
    try:
        with sessionmaker(bind=original_engine, expire_on_commit=False)() as session:
            incident = Incident(
                id="representative-incident",
                dedupe_key="representative-dedupe",
                created_at=now,
                updated_at=now,
                rule_metadata={},
                mitre_ids=["T1110"],
                mitre_tactics=[],
                mitre_techniques=[],
                raw_event={"sensitive": "never-printed"},
                severity="high",
                priority_score=40,
                repetition_count=1,
                asset_importance="normal",
                ai_status="not_configured",
                review_status="confirmed",
            )
            incident.reviews.append(
                Review(id="representative-review", status="confirmed", analyst="migration-test", created_at=now)
            )
            session.add(incident)
            session.commit()
    finally:
        original_engine.dispose()

    assert_verified(original, allow_alembic_version=False)
    backup_sqlite_database(original, backup)
    restore_sqlite_database(backup, adopted_copy)
    before_adoption = inspect_sqlite_database(adopted_copy)

    config = alembic_config(adopted_copy)
    command.stamp(config, BASELINE_REVISION)
    command.upgrade(config, "head")
    assert_verified(adopted_copy, allow_alembic_version=True)
    after_adoption = inspect_sqlite_database(adopted_copy)

    assert before_adoption.row_counts["incidents"] == after_adoption.row_counts["incidents"] == 1
    assert before_adoption.row_counts["reviews"] == after_adoption.row_counts["reviews"] == 1
    assert before_adoption.table_sha256["incidents"] == after_adoption.table_sha256["incidents"]
    assert before_adoption.table_sha256["reviews"] == after_adoption.table_sha256["reviews"]

    adopted_engine = create_engine(f"sqlite:///{adopted_copy.as_posix()}")
    try:
        with sessionmaker(bind=adopted_engine)() as session:
            restored_incident = session.scalar(select(Incident).where(Incident.id == "representative-incident"))
            assert restored_incident is not None
            assert restored_incident.raw_event == {"sensitive": "never-printed"}
            assert len(restored_incident.reviews) == 1
    finally:
        adopted_engine.dispose()
