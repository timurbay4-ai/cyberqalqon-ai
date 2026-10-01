"""Strict, read-only verification for adopting an existing database."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String, Text, create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.sql.schema import UniqueConstraint
from sqlalchemy.types import TypeDecorator

from app.db.base import Base
from app.models import incident, review  # noqa: F401


BASELINE_REVISION = "20261001_0001"


@dataclass(frozen=True)
class SchemaIssue:
    code: str
    object_name: str
    message: str


@dataclass(frozen=True)
class SchemaVerificationReport:
    valid: bool
    issues: tuple[SchemaIssue, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "issues": [asdict(issue) for issue in self.issues]}


def _type_signature(column_type: Any) -> tuple[str, int | None]:
    while isinstance(column_type, TypeDecorator):
        column_type = column_type.impl
    if isinstance(column_type, JSON):
        return ("json", None)
    if isinstance(column_type, Text):
        return ("text", None)
    if isinstance(column_type, String):
        return ("string", column_type.length)
    if isinstance(column_type, Integer):
        return ("integer", None)
    if isinstance(column_type, DateTime):
        # SQLite does not preserve the timezone flag in reflected DDL.
        return ("datetime", None)
    return (column_type.__class__.__name__.lower(), None)


def _normalize_default(value: Any) -> str | None:
    if value is None:
        return None
    return str(value).strip().strip("()")


def _expected_indexes(table: Any) -> set[tuple[str, tuple[str, ...], bool]]:
    return {
        (index.name, tuple(column.name for column in index.columns), bool(index.unique))
        for index in table.indexes
    }


def _actual_indexes(inspector: Any, table_name: str) -> set[tuple[str, tuple[str, ...], bool]]:
    return {
        (index["name"], tuple(index["column_names"]), bool(index.get("unique")))
        for index in inspector.get_indexes(table_name)
    }


def _expected_unique_constraints(table: Any) -> set[tuple[str | None, tuple[str, ...]]]:
    return {
        (constraint.name, tuple(column.name for column in constraint.columns))
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    }


def _actual_unique_constraints(inspector: Any, table_name: str) -> set[tuple[str | None, tuple[str, ...]]]:
    return {
        (constraint.get("name"), tuple(constraint["column_names"]))
        for constraint in inspector.get_unique_constraints(table_name)
    }


def _expected_foreign_keys(table: Any) -> set[tuple[tuple[str, ...], str, tuple[str, ...], str | None]]:
    result = set()
    for constraint in table.foreign_key_constraints:
        referred = list(constraint.elements)
        result.add(
            (
                tuple(element.parent.name for element in referred),
                referred[0].column.table.name,
                tuple(element.column.name for element in referred),
                (constraint.ondelete or "").upper() or None,
            )
        )
    return result


def _actual_foreign_keys(inspector: Any, table_name: str) -> set[tuple[tuple[str, ...], str, tuple[str, ...], str | None]]:
    return {
        (
            tuple(foreign_key["constrained_columns"]),
            foreign_key["referred_table"],
            tuple(foreign_key["referred_columns"]),
            (foreign_key.get("options", {}).get("ondelete") or "").upper() or None,
        )
        for foreign_key in inspector.get_foreign_keys(table_name)
    }


def verify_database_schema(
    engine: Engine,
    *,
    allow_alembic_version: bool = False,
) -> SchemaVerificationReport:
    """Compare an existing schema to the exact non-AI SQLAlchemy metadata."""
    inspector = inspect(engine)
    expected_tables = set(Base.metadata.tables)
    allowed_tables = expected_tables | ({"alembic_version"} if allow_alembic_version else set())
    actual_tables = set(inspector.get_table_names())
    issues: list[SchemaIssue] = []

    for table_name in sorted(expected_tables - actual_tables):
        issues.append(SchemaIssue("missing_table", table_name, "Expected table is missing"))
    for table_name in sorted(actual_tables - allowed_tables):
        code = "unexpected_ai_table" if table_name == "incident_analyses" else "unexpected_table"
        issues.append(SchemaIssue(code, table_name, "Unexpected table blocks baseline adoption"))

    if allow_alembic_version and "alembic_version" in actual_tables:
        version_columns = inspector.get_columns("alembic_version")
        version_schema = [
            (
                column["name"],
                _type_signature(column["type"]),
                bool(column["nullable"]),
                bool(column.get("primary_key")),
            )
            for column in version_columns
        ]
        expected_version_schema = [("version_num", ("string", 32), False, True)]
        if version_schema != expected_version_schema:
            issues.append(
                SchemaIssue(
                    "alembic_version_schema_mismatch",
                    "alembic_version",
                    f"Expected {expected_version_schema}; found {version_schema}",
                )
            )
        else:
            with engine.connect() as connection:
                revisions = list(connection.scalars(text("SELECT version_num FROM alembic_version")))
            if revisions != [BASELINE_REVISION]:
                issues.append(
                    SchemaIssue(
                        "alembic_revision_mismatch",
                        "alembic_version.version_num",
                        f"Expected [{BASELINE_REVISION!r}]; found {revisions!r}",
                    )
                )

    for table_name in sorted(expected_tables & actual_tables):
        expected_table = Base.metadata.tables[table_name]
        actual_columns = inspector.get_columns(table_name)
        expected_names = [column.name for column in expected_table.columns]
        actual_names = [column["name"] for column in actual_columns]
        if expected_names != actual_names:
            issues.append(
                SchemaIssue(
                    "column_order_or_set_mismatch",
                    table_name,
                    f"Expected columns {expected_names}; found {actual_names}",
                )
            )

        expected_by_name = {column.name: column for column in expected_table.columns}
        actual_by_name = {column["name"]: column for column in actual_columns}
        for column_name in sorted(set(expected_by_name) & set(actual_by_name)):
            expected = expected_by_name[column_name]
            actual = actual_by_name[column_name]
            object_name = f"{table_name}.{column_name}"
            if _type_signature(expected.type) != _type_signature(actual["type"]):
                issues.append(
                    SchemaIssue(
                        "column_type_mismatch",
                        object_name,
                        f"Expected {_type_signature(expected.type)}; found {_type_signature(actual['type'])}",
                    )
                )
            if bool(expected.nullable) != bool(actual["nullable"]):
                issues.append(
                    SchemaIssue(
                        "column_nullability_mismatch",
                        object_name,
                        f"Expected nullable={expected.nullable}; found nullable={actual['nullable']}",
                    )
                )
            if bool(expected.primary_key) != bool(actual.get("primary_key")):
                issues.append(
                    SchemaIssue(
                        "column_primary_key_mismatch",
                        object_name,
                        f"Expected primary_key={expected.primary_key}; found primary_key={actual.get('primary_key')}",
                    )
                )
            expected_default = _normalize_default(expected.server_default.arg if expected.server_default else None)
            actual_default = _normalize_default(actual.get("default"))
            if expected_default != actual_default:
                issues.append(
                    SchemaIssue(
                        "column_server_default_mismatch",
                        object_name,
                        f"Expected server default {expected_default}; found {actual_default}",
                    )
                )

        expected_pk = tuple(column.name for column in expected_table.primary_key.columns)
        actual_pk = tuple(inspector.get_pk_constraint(table_name).get("constrained_columns") or ())
        if expected_pk != actual_pk:
            issues.append(SchemaIssue("primary_key_mismatch", table_name, f"Expected {expected_pk}; found {actual_pk}"))

        expected_indexes = _expected_indexes(expected_table)
        actual_indexes = _actual_indexes(inspector, table_name)
        if expected_indexes != actual_indexes:
            issues.append(
                SchemaIssue(
                    "index_mismatch",
                    table_name,
                    f"Expected {sorted(expected_indexes)}; found {sorted(actual_indexes)}",
                )
            )

        expected_unique = _expected_unique_constraints(expected_table)
        actual_unique = _actual_unique_constraints(inspector, table_name)
        if expected_unique != actual_unique:
            issues.append(
                SchemaIssue(
                    "unique_constraint_mismatch",
                    table_name,
                    f"Expected {sorted(expected_unique)}; found {sorted(actual_unique)}",
                )
            )

        expected_fks = _expected_foreign_keys(expected_table)
        actual_fks = _actual_foreign_keys(inspector, table_name)
        if expected_fks != actual_fks:
            issues.append(
                SchemaIssue(
                    "foreign_key_mismatch",
                    table_name,
                    f"Expected {sorted(expected_fks)}; found {sorted(actual_fks)}",
                )
            )

    return SchemaVerificationReport(valid=not issues, issues=tuple(issues))


def create_read_only_sqlite_engine(database_path: str | Path) -> Engine:
    path = Path(database_path).resolve(strict=True)
    uri = f"sqlite+pysqlite:///file:{path.as_posix()}?mode=ro&uri=true"
    return create_engine(uri, pool_pre_ping=True)
