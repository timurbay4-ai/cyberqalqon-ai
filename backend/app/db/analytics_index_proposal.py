"""Explicit disposable schema-17 analytics index proposal; no startup DDL."""
from __future__ import annotations

import sqlite3
import time

INDEX_NAME = 'idx_m29_analytics_cover_v1'
COVER_COLUMNS = (
    'occurred_at', 'event_id', 'hostname', 'source_ip', 'severity', 'event_code',
    'event_category', 'source_type', 'outcome', 'rule_id', 'event_provider',
)
INDEX_SQL = f'CREATE INDEX {INDEX_NAME} ON security_events (' + ','.join(COVER_COLUMNS) + ')'


def available(connection: sqlite3.Connection) -> bool:
    row = connection.execute("SELECT sql FROM sqlite_master WHERE type='index' AND name=?", (INDEX_NAME,)).fetchone()
    return row is not None and ''.join(row[0].lower().split()) == ''.join(INDEX_SQL.lower().split())


def _guard(connection, disposable_only):
    if disposable_only is not True or connection.in_transaction:
        raise ValueError('index proposal requires explicit disposable scope and clean transaction')
    if connection.execute('PRAGMA user_version').fetchone()[0] != 17:
        raise ValueError('index proposal requires schema 17')


def install(connection, *, disposable_only=False, inject_failure=None):
    _guard(connection, disposable_only)
    started = time.perf_counter()
    connection.execute('BEGIN IMMEDIATE')
    try:
        connection.execute(INDEX_SQL)
        if inject_failure is not None: inject_failure(connection)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return {'version': 'm29-analytics-cover-v1', 'schema': 17,
            'migration_ms': round((time.perf_counter()-started)*1000, 3)}


def uninstall(connection, *, disposable_only=False):
    _guard(connection, disposable_only)
    connection.execute('BEGIN IMMEDIATE')
    try:
        if not available(connection):
            raise ValueError('index definition does not match reviewed proposal')
        connection.execute('DROP INDEX ' + INDEX_NAME)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
