"""Database engine, session factory, and FastAPI dependency."""

from collections.abc import Generator
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session, sessionmaker
from app.core.config import get_settings


def create_database_engine(
    database_url: str,
    *,
    sqlite_busy_timeout_ms: int = 5_000,
    sqlite_foreign_keys: bool = False,
) -> Engine:
    """Create an application engine with safe logging and gated SQLite hardening."""
    if sqlite_busy_timeout_ms <= 0:
        raise ValueError("sqlite_busy_timeout_ms must be positive")

    is_sqlite = make_url(database_url).get_backend_name() == "sqlite"
    connect_args = (
        {
            "check_same_thread": False,
            "timeout": sqlite_busy_timeout_ms / 1_000,
        }
        if is_sqlite
        else {}
    )
    database_engine = create_engine(
        database_url,
        connect_args=connect_args,
        pool_pre_ping=True,
        hide_parameters=True,
    )

    if is_sqlite and sqlite_foreign_keys:

        @event.listens_for(database_engine, "connect")
        def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA foreign_keys = ON")
                enabled = cursor.execute("PRAGMA foreign_keys").fetchone()[0]
            finally:
                cursor.close()
            if enabled != 1:
                raise RuntimeError("SQLite foreign key enforcement could not be enabled")

    return database_engine


settings = get_settings()
engine = create_database_engine(
    settings.database_url,
    sqlite_busy_timeout_ms=settings.sqlite_busy_timeout_ms,
    sqlite_foreign_keys=settings.sqlite_foreign_keys,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    with SessionLocal() as session:
        yield session
