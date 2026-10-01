from __future__ import annotations

import traceback

import pytest
from sqlalchemy import text
from sqlalchemy.exc import ArgumentError, IntegrityError

from app.core.config import get_settings
from app.db import session as session_module
from app.db.session import create_database_engine


def test_engine_hides_bound_parameters_in_database_exceptions():
    secret = "SYNTHETIC-CREDENTIAL-9f21"
    engine = create_database_engine("sqlite://")
    try:
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE secrets (value TEXT UNIQUE)"))
            connection.execute(text("INSERT INTO secrets VALUES (:value)"), {"value": secret})

        with pytest.raises(IntegrityError) as caught:
            with engine.begin() as connection:
                connection.execute(text("INSERT INTO secrets VALUES (:value)"), {"value": secret})

        rendered = "".join(traceback.format_exception(caught.value))
        assert secret not in rendered
        assert "SQL parameters hidden due to hide_parameters=True" in rendered
        assert caught.value.params == (secret,)
    finally:
        engine.dispose()


def test_database_settings_are_explicit_and_configurable(monkeypatch):
    monkeypatch.setenv("SQLITE_BUSY_TIMEOUT_MS", "2750")
    monkeypatch.setenv("SQLITE_FOREIGN_KEYS", "true")
    get_settings.cache_clear()
    try:
        settings = get_settings()
        assert settings.sqlite_busy_timeout_ms == 2750
        assert settings.sqlite_foreign_keys is True
    finally:
        get_settings.cache_clear()


def test_invalid_database_url_fails_before_connecting():
    with pytest.raises(ArgumentError):
        create_database_engine("not a database url")


def test_non_sqlite_engine_does_not_receive_sqlite_connection_arguments(monkeypatch):
    sentinel = object()
    captured = {}

    def fake_create_engine(database_url, **kwargs):
        captured["database_url"] = database_url
        captured.update(kwargs)
        return sentinel

    monkeypatch.setattr(session_module, "create_engine", fake_create_engine)
    result = create_database_engine("postgresql://example.invalid/cyberqalqon")

    assert result is sentinel
    assert captured == {
        "database_url": "postgresql://example.invalid/cyberqalqon",
        "connect_args": {},
        "pool_pre_ping": True,
        "hide_parameters": True,
    }


def test_non_positive_busy_timeout_is_rejected():
    with pytest.raises(ValueError, match="must be positive"):
        create_database_engine("sqlite://", sqlite_busy_timeout_ms=0)
