"""M29 disposable-only storage proposal. Never imported by application startup.

Keeps the legacy MATCH table/columns and event IDs. A separate derived locator
maps actual FTS rowids; it does NOT assume that event and FTS rowids coincide.
No schema-version bump, FTS rebuild, vacuum or automatic activation is performed.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time

TRIGGERS = ('security_events_fts_insert', 'security_events_fts_delete', 'security_events_fts_update')

OPTIMIZED = (
    """CREATE TRIGGER security_events_fts_insert AFTER INSERT ON security_events BEGIN
    INSERT INTO security_events_fts(event_id, search_text) VALUES(new.event_id, new.search_text);
    INSERT INTO m29_fts_locator(event_id, fts_rowid) VALUES(new.event_id, last_insert_rowid());
    END""",
    """CREATE TRIGGER security_events_fts_delete AFTER DELETE ON security_events BEGIN
    SELECT CASE WHEN (SELECT event_id FROM security_events_fts WHERE rowid=(
      SELECT fts_rowid FROM m29_fts_locator WHERE event_id=old.event_id)) IS NOT old.event_id
      THEN RAISE(ABORT, 'FTS locator missing or mismatched') END;
    DELETE FROM security_events_fts WHERE rowid=(SELECT fts_rowid FROM m29_fts_locator WHERE event_id=old.event_id);
    DELETE FROM m29_fts_locator WHERE event_id=old.event_id;
    END""",
    """CREATE TRIGGER security_events_fts_update AFTER UPDATE OF search_text ON security_events BEGIN
    SELECT CASE WHEN (SELECT event_id FROM security_events_fts WHERE rowid=(
      SELECT fts_rowid FROM m29_fts_locator WHERE event_id=old.event_id)) IS NOT old.event_id
      THEN RAISE(ABORT, 'FTS locator missing or mismatched') END;
    UPDATE security_events_fts SET search_text=new.search_text
      WHERE rowid=(SELECT fts_rowid FROM m29_fts_locator WHERE event_id=old.event_id);
    END""",
)


def normalized(sql: str) -> str:
    return ''.join(sql.lower().split()).replace('ifnotexists', '')


def legacy_valid(statements):
    expected = (
        'CREATE TRIGGER security_events_fts_insert AFTER INSERT ON security_events BEGIN '
        'INSERT INTO security_events_fts(event_id, search_text) VALUES (new.event_id, new.search_text); END',
        'CREATE TRIGGER security_events_fts_delete AFTER DELETE ON security_events BEGIN '
        'DELETE FROM security_events_fts WHERE event_id = old.event_id; END',
        'CREATE TRIGGER security_events_fts_update AFTER UPDATE OF search_text ON security_events BEGIN '
        'DELETE FROM security_events_fts WHERE event_id = old.event_id; '
        'INSERT INTO security_events_fts(event_id, search_text) VALUES (new.event_id, new.search_text); END',
    )
    return [normalized(item) for item in statements] == [normalized(item) for item in expected]


def _guard(connection, disposable_only):
    if disposable_only is not True:
        raise ValueError('M29 storage proposal requires explicit disposable-test scope')
    if connection.in_transaction:
        raise ValueError('migration requires a clean transaction boundary')
    if connection.execute('PRAGMA user_version').fetchone()[0] != 17:
        raise ValueError('M29 proposal requires schema 17')


def _triggers(connection):
    rows = {row[0]: row[1] for row in connection.execute(
        "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND name IN (?,?,?)", TRIGGERS)}
    if set(rows) != set(TRIGGERS):
        raise ValueError('expected legacy FTS triggers are missing')
    return [rows[name] for name in TRIGGERS]


def verify_fts_content(connection, *, locator=False):
    count = connection.execute('SELECT COUNT(*) FROM security_events').fetchone()[0]
    fts_count, distinct = connection.execute(
        'SELECT COUNT(*), COUNT(DISTINCT event_id) FROM security_events_fts').fetchone()
    if count != fts_count or count != distinct:
        raise ValueError('FTS event identity/count mismatch')
    if connection.execute('SELECT 1 FROM security_events_fts f LEFT JOIN security_events e '
                          'ON e.event_id=f.event_id WHERE e.event_id IS NULL OR f.search_text IS NOT e.search_text LIMIT 1').fetchone():
        raise ValueError('FTS evidence text mismatch')
    if locator:
        locator_count = connection.execute('SELECT COUNT(*) FROM m29_fts_locator').fetchone()[0]
        mismatch = connection.execute('SELECT 1 FROM security_events_fts f LEFT JOIN m29_fts_locator m '
            'ON m.event_id=f.event_id WHERE m.fts_rowid IS NOT f.rowid LIMIT 1').fetchone()
        if locator_count != count or mismatch:
            raise ValueError('FTS locator mismatch')
    connection.execute("INSERT INTO security_events_fts(security_events_fts) VALUES('integrity-check')")
    return count


def install(connection, *, disposable_only=False, inject_failure=None):
    """Explicit offline proposal; SQLite DDL + locator backfill commit atomically."""
    _guard(connection, disposable_only)
    started = time.perf_counter()
    connection.execute('BEGIN IMMEDIATE')
    try:
        old = _triggers(connection)
        if not legacy_valid(old):
            raise ValueError('unrecognized/custom FTS triggers; refusing replacement')
        count = verify_fts_content(connection)
        connection.execute('CREATE TABLE m29_fts_locator(event_id TEXT PRIMARY KEY, fts_rowid INTEGER NOT NULL UNIQUE) WITHOUT ROWID')
        connection.execute('INSERT INTO m29_fts_locator(event_id,fts_rowid) SELECT event_id,rowid FROM security_events_fts')
        connection.execute('CREATE TABLE m29_fts_locator_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL, prior_json TEXT NOT NULL, prior_sha256 TEXT NOT NULL)')
        payload = json.dumps(old, separators=(',', ':'))
        connection.execute('INSERT INTO m29_fts_locator_meta VALUES(1,1,?,?)',
                           (payload, hashlib.sha256(payload.encode()).hexdigest()))
        for name, sql in zip(TRIGGERS, OPTIMIZED, strict=True):
            connection.execute('DROP TRIGGER ' + name)
            connection.execute(sql)
        if inject_failure is not None:
            inject_failure(connection)
        verify_fts_content(connection, locator=True)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return {'version': 'm29-fts-locator-v1', 'events': count,
            'migration_ms': round((time.perf_counter()-started)*1000, 3), 'schema': 17}


def uninstall(connection, *, disposable_only=False):
    """Restore verified legacy triggers, retaining all current events and FTS rows."""
    _guard(connection, disposable_only)
    connection.execute('BEGIN IMMEDIATE')
    try:
        if [normalized(item) for item in _triggers(connection)] != [normalized(item) for item in OPTIMIZED]:
            raise ValueError('optimized trigger checksum mismatch')
        row = connection.execute('SELECT version,prior_json,prior_sha256 FROM m29_fts_locator_meta WHERE singleton=1').fetchone()
        if row is None or row[0] != 1 or hashlib.sha256(row[1].encode()).hexdigest() != row[2]:
            raise ValueError('rollback metadata checksum mismatch')
        old = json.loads(row[1])
        if not legacy_valid(old):
            raise ValueError('rollback DDL is not the known legacy contract')
        verify_fts_content(connection, locator=True)
        for name, sql in zip(TRIGGERS, old, strict=True):
            connection.execute('DROP TRIGGER ' + name)
            connection.execute(sql)
        connection.execute('DROP TABLE m29_fts_locator')
        connection.execute('DROP TABLE m29_fts_locator_meta')
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
