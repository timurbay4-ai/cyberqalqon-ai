"""Non-overwriting SQLite online backup and restore helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from typing import Any


@dataclass(frozen=True)
class DatabaseSnapshot:
    integrity_check: str
    schema_sha256: str
    row_counts: dict[str, int]
    table_sha256: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class BackupResult:
    source: str
    destination: str
    destination_sha256: str
    snapshot: DatabaseSnapshot

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["snapshot"] = self.snapshot.to_dict()
        return result


def _read_only_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    connection.execute("PRAGMA query_only = ON")
    return connection


def _user_tables(connection: sqlite3.Connection) -> list[str]:
    return [
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]


def _table_digest(connection: sqlite3.Connection, table_name: str) -> tuple[int, str]:
    quoted = table_name.replace('"', '""')
    primary_keys = [
        row[1]
        for row in sorted(connection.execute(f'PRAGMA table_info("{quoted}")'), key=lambda row: row[5])
        if row[5]
    ]
    order_clause = ""
    if primary_keys:
        columns = ", ".join(f'"{column.replace(chr(34), chr(34) * 2)}"' for column in primary_keys)
        order_clause = f" ORDER BY {columns}"
    digest = sha256()
    count = 0
    for row in connection.execute(f'SELECT * FROM "{quoted}"{order_clause}'):
        digest.update(json.dumps(row, ensure_ascii=False, default=str, separators=(",", ":")).encode("utf-8"))
        digest.update(b"\n")
        count += 1
    return count, digest.hexdigest()


def inspect_sqlite_database(database_path: str | Path) -> DatabaseSnapshot:
    path = Path(database_path).resolve(strict=True)
    with _read_only_connection(path) as connection:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        schema_rows = list(
            connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
            )
        )
        schema_digest = sha256(
            json.dumps(schema_rows, ensure_ascii=False, default=str, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        counts: dict[str, int] = {}
        digests: dict[str, str] = {}
        for table_name in _user_tables(connection):
            count, digest = _table_digest(connection, table_name)
            counts[table_name] = count
            digests[table_name] = digest
    return DatabaseSnapshot(integrity, schema_digest, counts, digests)


def _file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_database(source: Path, destination: Path) -> BackupResult:
    source = source.resolve(strict=True)
    destination = destination.resolve(strict=False)
    if source == destination:
        raise ValueError("Source and destination must be different files")
    if destination.exists():
        raise FileExistsError(f"Refusing to overwrite existing database: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)

    source_snapshot = inspect_sqlite_database(source)
    if source_snapshot.integrity_check != "ok":
        raise RuntimeError(f"Source database failed integrity_check: {source_snapshot.integrity_check}")
    with _read_only_connection(source) as source_connection:
        with sqlite3.connect(destination) as destination_connection:
            source_connection.backup(destination_connection)

    destination_snapshot = inspect_sqlite_database(destination)
    if destination_snapshot != source_snapshot:
        raise RuntimeError("SQLite copy verification failed; destination was retained for investigation")
    file_digest = _file_sha256(destination)
    return BackupResult(str(source), str(destination), file_digest, destination_snapshot)


def backup_sqlite_database(source: str | Path, destination: str | Path) -> BackupResult:
    return _copy_database(Path(source), Path(destination))


def restore_sqlite_database(backup: str | Path, destination: str | Path) -> BackupResult:
    return _copy_database(Path(backup), Path(destination))
