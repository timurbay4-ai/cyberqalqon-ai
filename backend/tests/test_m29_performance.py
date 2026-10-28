from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
from contextlib import closing
from datetime import datetime, timedelta, timezone

import pytest

from app.db.alerts import AlertRepository
from app.db.events import EventRepository
from app.db import fts_locator_proposal as locator
from app.db import analytics_index_proposal as covering
from app.db.cqql import CQQLSearchRepository
from app.services.cqql import compile_cqql
from app.services.event_normalizer import normalize_wazuh_event


def payload(index, *, provider='SYNTHETIC-Provider', at=None):
    return {'timestamp': (at or datetime.now(timezone.utc)).isoformat(),
        'id': f'SYNTHETIC-M29-{index}', 'agent': {'id': '929', 'name': 'SYNTH-M29-HOST'},
        'decoder': {'name': 'windows_eventchannel'},
        'data': {'win': {'system': {'eventID': '4625', 'providerName': provider,
                                   'channel': 'Security', 'computer': 'SYNTH-M29-HOST'}}},
        'rule': {'id': '992900', 'level': index % 17, 'description': 'SYNTHETIC M29 telemetry'},
        'full_log': 'SYNTHETIC security event'}


@pytest.fixture
def storage(tmp_path):
    path = tmp_path / 'm29-disposable.db'
    AlertRepository(f'sqlite:///{path.as_posix()}', migration_target_version=17).initialize()
    repository = EventRepository(path, retention_days=30, max_records=100_000)
    now = datetime.now(timezone.utc)
    ids = [repository.ingest(normalize_wazuh_event(payload(i, at=now)), now=now).event.event_id for i in range(8)]
    return path, repository, ids


def evidence(connection):
    rows = connection.execute('SELECT event_id,deduplication_id,raw_event_json,structured_json FROM security_events ORDER BY event_id').fetchall()
    return hashlib.sha256(json.dumps([tuple(row) for row in rows]).encode()).hexdigest()


def test_locator_explicit_guard_and_roundtrip_with_nonmatching_rowids(storage):
    path, repository, ids = storage
    with closing(sqlite3.connect(path)) as connection:
        with pytest.raises(ValueError, match='disposable'):
            locator.install(connection)
        connection.execute('UPDATE security_events SET search_text=search_text || ? WHERE event_id=?', (' changed_before_upgrade', ids[0]))
        connection.commit()
        before = evidence(connection)
        rowids = connection.execute('SELECT e.rowid,f.rowid FROM security_events e JOIN security_events_fts f ON e.event_id=f.event_id WHERE e.event_id=?', (ids[0],)).fetchone()
        assert rowids[0] != rowids[1]
        locator.install(connection, disposable_only=True)
        assert evidence(connection) == before
        with pytest.raises(ValueError):
            locator.install(connection, disposable_only=True)
        connection.execute('UPDATE security_events SET search_text=search_text || ? WHERE event_id=?', (' changed_after_upgrade', ids[0]))
        connection.commit()
        assert connection.execute("SELECT COUNT(*) FROM security_events_fts WHERE security_events_fts MATCH 'changed_after_upgrade'").fetchone()[0] == 1
        event = normalize_wazuh_event(payload(100))
        repository.ingest(event)
        assert repository.ingest(event).duplicate
        connection.execute('DELETE FROM security_events WHERE event_id=?', (event.event_id,))
        connection.commit()
        assert locator.verify_fts_content(connection, locator=True) == 8
        connection.commit()
        locator.uninstall(connection, disposable_only=True)
        assert evidence(connection) == before
        assert connection.execute('PRAGMA user_version').fetchone()[0] == 17
        assert connection.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
        assert not connection.execute('PRAGMA foreign_key_check').fetchall()


def test_locator_interrupted_migration_is_atomic_and_retryable(storage):
    path, _, _ = storage
    with closing(sqlite3.connect(path)) as connection:
        before = evidence(connection)
        def fail(_connection):
            raise RuntimeError('SYNTHETIC migration interruption')
        with pytest.raises(RuntimeError):
            locator.install(connection, disposable_only=True, inject_failure=fail)
        assert connection.execute("SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'm29_fts_locator%'").fetchone()[0] == 0
        assert locator.legacy_valid(locator._triggers(connection))
        assert evidence(connection) == before
        locator.install(connection, disposable_only=True)


def test_locator_rejects_custom_trigger_and_bad_rollback_metadata(storage):
    path, _, _ = storage
    with closing(sqlite3.connect(path)) as connection:
        locator.install(connection, disposable_only=True)
        connection.execute("UPDATE m29_fts_locator_meta SET prior_sha256='tampered'")
        connection.commit()
        before = evidence(connection)
        with pytest.raises(ValueError, match='checksum'):
            locator.uninstall(connection, disposable_only=True)
        assert evidence(connection) == before
        assert locator.verify_fts_content(connection, locator=True) == 8


def test_failed_retention_rolls_back_event_counter_fts_and_locator(storage):
    path, _, ids = storage
    repository = EventRepository(path, retention_days=30, max_records=8)
    with closing(sqlite3.connect(path)) as connection:
        locator.install(connection, disposable_only=True)
        before = evidence(connection)
        connection.execute("CREATE TRIGGER m29_injected_failure BEFORE DELETE ON security_events BEGIN SELECT RAISE(ABORT,'SYNTHETIC cleanup failure'); END")
        connection.commit()
        with pytest.raises(sqlite3.IntegrityError):
            repository.ingest(normalize_wazuh_event(payload(100)))
        assert evidence(connection) == before
        assert connection.execute('SELECT retained_records FROM security_event_store_state').fetchone()[0] == 8
        assert locator.verify_fts_content(connection, locator=True) == 8
        connection.commit()
        connection.execute('DROP TRIGGER m29_injected_failure')
        connection.commit()
    event = normalize_wazuh_event(payload(100))
    assert not repository.ingest(event).duplicate
    assert repository.ingest(event).duplicate


def test_uncommitted_process_crash_recovers_evidence_and_fts(storage):
    path, _, ids = storage
    with closing(sqlite3.connect(path)) as connection:
        locator.install(connection, disposable_only=True)
        before = evidence(connection)
    code = "import os,sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('BEGIN IMMEDIATE'); c.execute('DELETE FROM security_events WHERE event_id=?',(sys.argv[2],)); os._exit(17)"
    result = subprocess.run([sys.executable, '-c', code, str(path), ids[0]], timeout=15, capture_output=True)
    assert result.returncode == 17
    with closing(sqlite3.connect(path)) as connection:
        assert evidence(connection) == before
        assert locator.verify_fts_content(connection, locator=True) == 8
        assert connection.execute('PRAGMA quick_check').fetchone()[0] == 'ok'


def test_single_event_capacity_failure_has_no_ack_and_duplicate_remains_safe(client, auth_headers, sample_alert, database_path):
    alert = dict(sample_alert)
    alert['timestamp'] = datetime.now(timezone.utc).isoformat()
    assert client.post('/api/v1/alerts/ingest', headers=auth_headers, json=alert).status_code == 201
    client.app.state.event_repository.max_records = 1
    rejected = client.post('/api/v1/events/ingest', headers=auth_headers, json=payload(900))
    assert rejected.status_code == 503
    assert rejected.json()['detail']['code'] == 'retention_capacity_exhausted'
    assert rejected.headers['retry-after'] == '5'
    assert client.post('/api/v1/events/ingest', headers=auth_headers, json=alert).status_code == 200
    metrics = client.app.state.ingestion_metrics.snapshot()
    assert metrics['inserted'] == 0 and metrics['duplicates'] == 1
    with closing(sqlite3.connect(database_path)) as connection:
        assert connection.execute('SELECT COUNT(*) FROM security_events').fetchone()[0] == 1
        assert connection.execute('SELECT retained_records FROM security_event_store_state').fetchone()[0] == 1
        assert not connection.execute('PRAGMA foreign_key_check').fetchall()


def test_trigger_failure_is_sanitized_503_not_false_ack(client, auth_headers, database_path):
    first = client.post('/api/v1/events/ingest', headers=auth_headers, json=payload(901))
    assert first.status_code == 201
    client.app.state.event_repository.max_records = 1
    with closing(sqlite3.connect(database_path)) as connection:
        before = evidence(connection)
        connection.execute("CREATE TRIGGER m29_injected BEFORE DELETE ON security_events BEGIN SELECT RAISE(ABORT,'SYNTHETIC-private-error'); END")
        connection.commit()
    rejected = client.post('/api/v1/events/ingest', headers=auth_headers, json=payload(902))
    assert rejected.status_code == 503
    assert 'SYNTHETIC-private-error' not in rejected.text
    assert client.app.state.ingestion_metrics.snapshot()['inserted'] == 1
    with closing(sqlite3.connect(database_path)) as connection:
        assert evidence(connection) == before
        assert connection.execute('SELECT retained_records FROM security_event_store_state').fetchone()[0] == 1


@pytest.mark.parametrize('sort', ['newest', 'oldest'])
@pytest.mark.parametrize('query', [
    'event.provider = "SYNTHETIC-Provider"',
    'event.provider = "synthetic-provider" AND event.severity >= 3',
    'event.provider = "x\' OR 1=1 --"',
    'NOT event.provider = "missing"',
])
def test_late_materialization_matches_reference_across_pages(storage, sort, query):
    path, _, _ = storage
    repository = CQQLSearchRepository(path)
    compiled = compile_cqql(query)
    start, end = datetime.now(timezone.utc)-timedelta(days=1), datetime.now(timezone.utc)+timedelta(minutes=1)
    direction = 'DESC' if sort == 'newest' else 'ASC'
    with closing(sqlite3.connect(path)) as connection:
        expected = [row[0] for row in connection.execute(
            f'SELECT e.event_id FROM security_events e WHERE e.occurred_at BETWEEN ? AND ? AND {compiled.sql} ORDER BY e.occurred_at {direction},e.event_id {direction}',
            (start.isoformat(), end.isoformat(), *compiled.parameters))]
    actual, cursor = [], None
    while True:
        result = repository.search(compiled, start_time=start, end_time=end, sort=sort, limit=3, cursor=cursor)
        actual.extend(row.event_id for row in result.items)
        cursor = result.next_cursor
        if not cursor: break
    assert actual == expected
    assert len(actual) == len(set(actual))


@pytest.mark.parametrize('groups', [[], ['event.provider'], ['event.category','event.severity','event.source_type'], ['source.ip','host.name','event.code']])
def test_shared_analytics_exact_counts_and_null_topn_semantics(storage, groups):
    from app.db.cqql import GROUP_COLUMNS
    path, _, _ = storage
    start, end = datetime.now(timezone.utc)-timedelta(days=1), datetime.now(timezone.utc)+timedelta(minutes=1)
    result = CQQLSearchRepository(path).analytics(compile_cqql('event.severity >= 0'), start_time=start,
        end_time=end, group_by=groups, top_n=2, interval='hour')
    assert result.matching_events == sum(row.count for row in result.time_series) == 8
    with closing(sqlite3.connect(path)) as connection:
        for group in result.groups:
            col = GROUP_COLUMNS[group.field]
            rows = connection.execute(f'SELECT CAST({col} AS TEXT),COUNT(*) AS n FROM security_events e WHERE {col} IS NOT NULL GROUP BY {col} ORDER BY n DESC,CAST({col} AS TEXT) LIMIT 3').fetchall()
            assert [(row.name,row.count) for row in group.buckets] == rows[:2]
            assert group.truncated == (len(rows)>2)


def test_covering_index_atomic_upgrade_startup_compatibility_and_rollback(storage, monkeypatch):
    path, _, _ = storage
    with closing(sqlite3.connect(path)) as connection:
        before = evidence(connection)
        def fail(_connection): raise RuntimeError('SYNTHETIC index interruption')
        with pytest.raises(RuntimeError):
            covering.install(connection, disposable_only=True, inject_failure=fail)
        assert not covering.available(connection)
        locator.install(connection, disposable_only=True)
        covering.install(connection, disposable_only=True)
        assert covering.available(connection)
        assert evidence(connection) == before
    AlertRepository(f'sqlite:///{path.as_posix()}', migration_target_version=17).initialize()
    traced = []
    repository = CQQLSearchRepository(path)
    original = repository._connect
    def connect():
        connection = original()
        connection.set_trace_callback(traced.append)
        return connection
    monkeypatch.setattr(repository, '_connect', connect)
    now = datetime.now(timezone.utc)
    result = repository.analytics(compile_cqql('event.severity >= 0'), start_time=now-timedelta(days=1),
        end_time=now+timedelta(minutes=1), group_by=['event.provider','event.severity'], top_n=3, interval='hour')
    assert result.matching_events == 8
    aggregates = [sql for sql in traced if sql.startswith('WITH matched AS MATERIALIZED')]
    assert len(aggregates) == 1
    assert 'INDEXED BY idx_m29_analytics_cover_v1' in aggregates[0]
    with closing(sqlite3.connect(path)) as connection:
        assert locator.verify_fts_content(connection, locator=True) == 8
        connection.commit()
        covering.uninstall(connection, disposable_only=True)
        locator.uninstall(connection, disposable_only=True)
        assert not covering.available(connection)
        assert evidence(connection) == before


def test_custom_fts_trigger_is_not_overwritten(storage):
    path, _, _ = storage
    with closing(sqlite3.connect(path)) as connection:
        before = evidence(connection)
        connection.execute('DROP TRIGGER security_events_fts_delete')
        connection.execute('CREATE TRIGGER security_events_fts_delete AFTER DELETE ON security_events BEGIN SELECT 1; END')
        connection.commit()
        with pytest.raises(ValueError, match='custom'):
            locator.install(connection, disposable_only=True)
        assert evidence(connection) == before
        assert not connection.execute("SELECT 1 FROM sqlite_master WHERE name='m29_fts_locator'").fetchone()


def test_missing_locator_fails_closed_and_fixture_repair_allows_retry(storage):
    path, _, _ = storage
    repository = EventRepository(path, retention_days=30, max_records=8)
    event = normalize_wazuh_event(payload(910))
    with closing(sqlite3.connect(path)) as connection:
        locator.install(connection, disposable_only=True)
        missing = connection.execute('SELECT event_id FROM security_events ORDER BY occurred_at,event_id LIMIT 1').fetchone()[0]
        connection.execute('DELETE FROM m29_fts_locator WHERE event_id=?', (missing,))
        connection.commit()
        before = evidence(connection)
        with pytest.raises(sqlite3.IntegrityError, match='locator missing'):
            repository.ingest(event)
        assert evidence(connection) == before
        assert connection.execute('SELECT retained_records FROM security_event_store_state').fetchone()[0] == 8
        # Explicit repair is confined to this synthetic fixture, never runtime code.
        connection.execute('INSERT INTO m29_fts_locator SELECT event_id,rowid FROM security_events_fts WHERE event_id=?', (missing,))
        connection.commit()
    assert not repository.ingest(event).duplicate
    assert repository.ingest(event).duplicate


def test_age_cleanup_keeps_protected_bytes_and_indexes_consistent(storage):
    from scripts.m29_synthetic import protect
    path, repository, ids = storage
    now = datetime.now(timezone.utc)
    with closing(sqlite3.connect(path)) as connection:
        connection.execute('PRAGMA foreign_keys=ON')
        protect(connection, [ids[0]], now)
        connection.commit()
        original = connection.execute('SELECT raw_event_json,structured_json FROM security_events WHERE event_id=?', (ids[0],)).fetchone()
        locator.install(connection, disposable_only=True)
    future = now+timedelta(days=31)
    event = normalize_wazuh_event(payload(911, at=future))
    assert not repository.ingest(event, now=future).duplicate
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute('SELECT raw_event_json,structured_json FROM security_events WHERE event_id=?', (ids[0],)).fetchone() == original
        assert locator.verify_fts_content(connection, locator=True) == 2
        assert connection.execute('SELECT retained_records FROM security_event_store_state').fetchone()[0] == 2
        assert not connection.execute('PRAGMA foreign_key_check').fetchall()


def test_verified_backup_and_forward_safe_downgrade_preserve_post_upgrade_writes(storage):
    path, repository, _ = storage
    backup = path.with_name('m29-consistent-backup.db')
    restored = path.with_name('m29-disposable-restore.db')
    with closing(sqlite3.connect(path)) as source, closing(sqlite3.connect(backup)) as target:
        source.backup(target)
        before = evidence(source)
        assert evidence(target) == before
    digest = hashlib.sha256(backup.read_bytes()).hexdigest()
    with closing(sqlite3.connect(path)) as connection:
        locator.install(connection, disposable_only=True)
        covering.install(connection, disposable_only=True)
    event = normalize_wazuh_event(payload(912))
    assert not repository.ingest(event).duplicate
    with closing(sqlite3.connect(path)) as connection:
        covering.uninstall(connection, disposable_only=True)
        locator.uninstall(connection, disposable_only=True)
        assert connection.execute('SELECT COUNT(*) FROM security_events').fetchone()[0] == 9
        assert connection.execute('SELECT 1 FROM security_events WHERE event_id=?', (event.event_id,)).fetchone()
    assert hashlib.sha256(backup.read_bytes()).hexdigest() == digest
    with closing(sqlite3.connect(backup)) as source, closing(sqlite3.connect(restored)) as destination:
        source.backup(destination)
        assert evidence(destination) == before
        assert destination.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
        assert destination.execute('SELECT COUNT(*) FROM security_events').fetchone()[0] == 8
        # A stale backup is NOT an acceptable substitute for current acknowledged state.
        assert not destination.execute('SELECT 1 FROM security_events WHERE event_id=?', (event.event_id,)).fetchone()


def test_real_process_exit_during_migration_rolls_back_ddl(storage):
    path, _, _ = storage
    from pathlib import Path
    backend = Path(__file__).parents[1]
    with closing(sqlite3.connect(path)) as connection:
        before = evidence(connection)
    code = "import os,sqlite3,sys; sys.path.insert(0,sys.argv[2]); from app.db.fts_locator_proposal import install; c=sqlite3.connect(sys.argv[1]); install(c,disposable_only=True,inject_failure=lambda _:os._exit(18))"
    result = subprocess.run([sys.executable,'-c',code,str(path),str(backend)], timeout=20, capture_output=True)
    assert result.returncode == 18
    with closing(sqlite3.connect(path)) as connection:
        assert evidence(connection) == before
        assert not connection.execute("SELECT 1 FROM sqlite_master WHERE name LIKE 'm29_fts_locator%'").fetchall()
        assert locator.legacy_valid(locator._triggers(connection))
        assert connection.execute('PRAGMA quick_check').fetchone()[0] == 'ok'


def test_analytics_null_provider_sparse_utc_and_topn_exact_with_cover(storage):
    path, repository, _ = storage
    now = datetime.now(timezone.utc)
    raw = payload(920, at=now-timedelta(hours=3))
    raw['data']['win']['system'].pop('providerName')
    repository.ingest(normalize_wazuh_event(raw), now=now)
    with closing(sqlite3.connect(path)) as connection:
        covering.install(connection, disposable_only=True)
    result = CQQLSearchRepository(path).analytics(compile_cqql('event.severity >= 0'),
        start_time=now-timedelta(days=1),end_time=now+timedelta(minutes=1),
        group_by=['event.provider'],top_n=1,interval='hour')
    assert result.matching_events == sum(row.count for row in result.time_series) == 9
    assert [(bucket.name,bucket.count) for bucket in result.groups[0].buckets] == [('SYNTHETIC-Provider',8)]
    assert not result.groups[0].truncated
    assert [bucket.count for bucket in result.time_series] == [1,8]
    assert all(bucket.timestamp.utcoffset() == timedelta(0) for bucket in result.time_series)


def test_custom_cover_definition_is_neither_trusted_nor_removed(storage):
    path, _, _ = storage
    with closing(sqlite3.connect(path)) as connection:
        connection.execute(f'CREATE INDEX {covering.INDEX_NAME} ON security_events(event_id)')
        connection.commit()
        assert not covering.available(connection)
        with pytest.raises(ValueError,match='definition'):
            covering.uninstall(connection,disposable_only=True)
        assert connection.execute('SELECT sql FROM sqlite_master WHERE name=?',(covering.INDEX_NAME,)).fetchone()
    now = datetime.now(timezone.utc)
    result = CQQLSearchRepository(path).analytics(compile_cqql('event.severity >= 0'),
        start_time=now-timedelta(days=1),end_time=now+timedelta(minutes=1),
        group_by=['event.provider'],top_n=1,interval='day')
    assert result.matching_events == 8


@pytest.mark.parametrize('operation',['delete','update'])
def test_wrong_existing_fts_rowid_cannot_delete_or_overwrite_another_event(storage,operation):
    path, _, _ = storage
    repository = EventRepository(path,retention_days=30,max_records=8)
    with closing(sqlite3.connect(path)) as connection:
        locator.install(connection,disposable_only=True)
        first,second = connection.execute('SELECT m.event_id,m.fts_rowid FROM m29_fts_locator m '
            'JOIN security_events e ON e.event_id=m.event_id ORDER BY e.occurred_at,e.event_id LIMIT 2').fetchall()
        connection.execute('UPDATE m29_fts_locator SET fts_rowid=-1 WHERE event_id=?',(first[0],))
        connection.execute('UPDATE m29_fts_locator SET fts_rowid=? WHERE event_id=?',(first[1],second[0]))
        connection.execute('UPDATE m29_fts_locator SET fts_rowid=? WHERE event_id=?',(second[1],first[0]))
        connection.commit()
        before = evidence(connection)
        if operation == 'delete':
            with pytest.raises(sqlite3.IntegrityError,match='mismatched'):
                repository.ingest(normalize_wazuh_event(payload(921)))
        else:
            with pytest.raises(sqlite3.IntegrityError,match='mismatched'):
                connection.execute('UPDATE security_events SET search_text=? WHERE event_id=?',('SYNTHETIC overwrite',first[0]))
            connection.rollback()
        assert evidence(connection) == before
        assert connection.execute('SELECT retained_records FROM security_event_store_state').fetchone()[0] == 8
        assert connection.execute('SELECT COUNT(*) FROM security_events_fts').fetchone()[0] == 8
