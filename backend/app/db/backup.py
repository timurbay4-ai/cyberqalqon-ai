"""Online SQLite backup, integrity verification, and deliberate restore helpers."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import uuid
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.db.migrations import MIGRATIONS, MigrationError, apply_migrations
from app.version import APPLICATION_VERSION, BUILD_TIMESTAMP, GIT_COMMIT


class BackupError(RuntimeError):
    """Raised when backup or restore cannot be completed safely."""


@dataclass(frozen=True, slots=True)
class BackupInspection:
    schema_version: int
    migration_versions: tuple[int, ...]
    size_bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class BackupArtifact:
    database_path: Path
    metadata_path: Path
    inspection: BackupInspection


@dataclass(frozen=True, slots=True)
class RestoreResult:
    database_path: Path
    safety_backup: BackupArtifact | None
    invalidated_sessions: int
    schema_version: int


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _readonly_connection(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=30)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _migration_history(connection: sqlite3.Connection) -> tuple[int, ...]:
    tables = {
        str(row[0])
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    if not {"alerts", "schema_migrations"} <= tables:
        raise BackupError("SQLite file is not a CyberQalqon database")
    rows = connection.execute(
        "SELECT version, name FROM schema_migrations ORDER BY version"
    ).fetchall()
    versions = tuple(int(row[0]) for row in rows)
    if not versions or versions != tuple(range(1, versions[-1] + 1)):
        raise BackupError("Database migration history is incomplete")
    known = {migration.version: migration.name for migration in MIGRATIONS}
    if versions[-1] > len(MIGRATIONS):
        raise BackupError("Database schema is newer than this application")
    for version, name in rows:
        if known.get(int(version)) != str(name):
            raise BackupError("Database migration history does not match this application")
    user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if user_version != versions[-1]:
        raise BackupError("Database schema version disagrees with migration history")
    return versions


def inspect_backup(path: Path) -> BackupInspection:
    """Validate a standalone CyberQalqon SQLite file without mutating it."""

    path = path.resolve()
    if not path.is_file():
        raise BackupError("Backup file does not exist")
    try:
        with closing(_readonly_connection(path)) as connection:
            integrity = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            if integrity != "ok":
                raise BackupError("SQLite integrity check failed")
            versions = _migration_history(connection)
    except BackupError:
        raise
    except sqlite3.Error as exc:
        raise BackupError("Backup is not a readable SQLite database") from exc
    return BackupInspection(
        schema_version=versions[-1],
        migration_versions=versions,
        size_bytes=path.stat().st_size,
        sha256=_sha256(path),
    )


def _write_metadata(path: Path, payload: dict[str, Any]) -> None:
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except OSError as exc:
        raise BackupError("Unable to create backup metadata") from exc
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(encoded)
            destination.flush()
            os.fsync(destination.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _validate_filename(filename: str) -> None:
    if not filename or Path(filename).name != filename or not filename.endswith(".db"):
        raise BackupError("Backup filename must be a plain name ending in .db")


def create_backup(
    source_path: Path,
    output_dir: Path,
    *,
    filename: str | None = None,
    purpose: str = "scheduled",
) -> BackupArtifact:
    """Create and verify a transactionally consistent online SQLite backup."""

    source_path = source_path.resolve()
    output_dir = output_dir.resolve()
    if not source_path.is_file():
        raise BackupError("Source database does not exist")
    if not output_dir.is_dir():
        raise BackupError("Backup output directory does not exist")
    created_at = _utc_now()
    backup_name = filename or (
        f"cyberqalqon-{created_at.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}.db"
    )
    _validate_filename(backup_name)
    target = output_dir / backup_name
    metadata_path = Path(f"{target}.json")
    if target.exists() or metadata_path.exists():
        raise BackupError("Backup destination already exists")

    try:
        descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        with closing(_readonly_connection(source_path)) as source, closing(
            sqlite3.connect(target, timeout=30)
        ) as destination:
            source.backup(destination, pages=256, sleep=0.05)
            destination.commit()
        inspection = inspect_backup(target)
        metadata = {
            "metadata_version": 1,
            "created_at": created_at.isoformat(),
            "purpose": purpose,
            "application_version": APPLICATION_VERSION,
            "git_commit": GIT_COMMIT,
            "build_timestamp": BUILD_TIMESTAMP,
            "database_filename": target.name,
            "schema_version": inspection.schema_version,
            "migration_versions": list(inspection.migration_versions),
            "size_bytes": inspection.size_bytes,
            "sha256": inspection.sha256,
            "integrity_check": "ok",
        }
        _write_metadata(metadata_path, metadata)
        return BackupArtifact(target, metadata_path, inspection)
    except BackupError:
        target.unlink(missing_ok=True)
        metadata_path.unlink(missing_ok=True)
        raise
    except (OSError, sqlite3.Error) as exc:
        target.unlink(missing_ok=True)
        metadata_path.unlink(missing_ok=True)
        raise BackupError("Unable to create SQLite backup") from exc


def verify_backup(path: Path, metadata_path: Path | None = None) -> BackupInspection:
    """Verify SQLite integrity plus the sidecar hash and non-secret metadata."""

    path = path.resolve()
    metadata_path = (metadata_path or Path(f"{path}.json")).resolve()
    inspection = inspect_backup(path)
    if not metadata_path.is_file():
        raise BackupError("Backup metadata file does not exist")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupError("Backup metadata is not valid JSON") from exc
    expected = {
        "metadata_version": 1,
        "database_filename": path.name,
        "schema_version": inspection.schema_version,
        "migration_versions": list(inspection.migration_versions),
        "size_bytes": inspection.size_bytes,
        "sha256": inspection.sha256,
        "integrity_check": "ok",
    }
    if not isinstance(metadata, dict) or any(metadata.get(key) != value for key, value in expected.items()):
        raise BackupError("Backup metadata does not match the database file")
    return inspection


def _copy_database(source_path: Path, destination_path: Path) -> None:
    descriptor = os.open(destination_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    with closing(_readonly_connection(source_path)) as source, closing(
        sqlite3.connect(destination_path, timeout=30)
    ) as destination:
        source.backup(destination, pages=256, sleep=0.05)
        destination.commit()


def _prepare_stopped_target(path: Path) -> None:
    """Checkpoint WAL and prove the target is not held by a running backend."""

    try:
        with closing(sqlite3.connect(path, timeout=1)) as connection:
            checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if checkpoint is not None and int(checkpoint[0]) != 0:
                raise BackupError("Restore target is busy; stop the backend before restore")
            journal_mode = str(connection.execute("PRAGMA journal_mode = DELETE").fetchone()[0])
            if journal_mode.lower() != "delete":
                raise BackupError("Restore target could not leave WAL mode")
    except BackupError:
        raise
    except sqlite3.Error as exc:
        raise BackupError("Restore target is busy; stop the backend before restore") from exc


def restore_backup(
    backup_path: Path,
    metadata_path: Path,
    target_path: Path,
    preserve_dir: Path,
) -> RestoreResult:
    """Validate, migrate, and atomically restore while invalidating sessions.

    The caller must stop the backend first. This helper preserves an existing
    target as a verified online backup before replacing it.
    """

    backup_path = backup_path.resolve()
    metadata_path = metadata_path.resolve()
    target_path = target_path.resolve()
    preserve_dir = preserve_dir.resolve()
    verify_backup(backup_path, metadata_path)
    if backup_path == target_path:
        raise BackupError("Backup and restore target must be different files")
    if not target_path.parent.is_dir():
        raise BackupError("Restore target directory does not exist")
    if not preserve_dir.is_dir():
        raise BackupError("Safety-backup directory does not exist")

    safety_backup: BackupArtifact | None = None
    if target_path.exists():
        _prepare_stopped_target(target_path)
        timestamp = _utc_now().strftime("%Y%m%dT%H%M%SZ")
        safety_backup = create_backup(
            target_path,
            preserve_dir,
            filename=f"cyberqalqon-pre-restore-{timestamp}-{uuid.uuid4().hex[:8]}.db",
            purpose="pre-restore-safety-copy",
        )

    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".cyberqalqon-restore-", suffix=".db", dir=target_path.parent
        )
        os.close(descriptor)
        temporary_path = Path(temporary_name)
        temporary_path.unlink()
        _copy_database(backup_path, temporary_path)
        with closing(sqlite3.connect(temporary_path, timeout=30)) as restored:
            restored.execute("PRAGMA foreign_keys = ON")
            restored.execute("PRAGMA busy_timeout = 5000")
            try:
                versions = apply_migrations(restored)
            except MigrationError as exc:
                raise BackupError("Restored database cannot be migrated safely") from exc
            cursor = restored.execute("DELETE FROM analyst_sessions")
            invalidated_sessions = max(cursor.rowcount, 0)
            foreign_key_errors = restored.execute("PRAGMA foreign_key_check").fetchall()
            if foreign_key_errors:
                raise BackupError("Restored database failed foreign-key validation")
            if str(restored.execute("PRAGMA quick_check").fetchone()[0]) != "ok":
                raise BackupError("Restored database failed integrity validation")
            restored.commit()
            restored.execute("PRAGMA journal_mode = DELETE").fetchone()
        for suffix in ("-wal", "-shm"):
            Path(f"{target_path}{suffix}").unlink(missing_ok=True)
        os.replace(temporary_path, target_path)
        temporary_path = None
        os.chmod(target_path, 0o600)
        inspect_backup(target_path)
        return RestoreResult(
            database_path=target_path,
            safety_backup=safety_backup,
            invalidated_sessions=invalidated_sessions,
            schema_version=versions[-1],
        )
    except BackupError:
        raise
    except (OSError, sqlite3.Error) as exc:
        raise BackupError("Unable to restore SQLite backup") from exc
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
