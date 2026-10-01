"""Read-only SQLite integrity diagnostics."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from sqlalchemy.engine import Engine


@dataclass(frozen=True)
class ForeignKeyViolation:
    table: str
    row_id: int | None
    parent: str
    foreign_key_id: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def inspect_sqlite_foreign_keys(engine: Engine) -> tuple[ForeignKeyViolation, ...]:
    """Return foreign-key violations without modifying schema or data."""
    if engine.dialect.name != "sqlite":
        raise ValueError("Foreign-key diagnostics are only available for SQLite")

    with engine.connect() as connection:
        rows = connection.exec_driver_sql("PRAGMA foreign_key_check").all()
    return tuple(
        ForeignKeyViolation(
            table=row[0],
            row_id=row[1],
            parent=row[2],
            foreign_key_id=row[3],
        )
        for row in rows
    )
