import asyncio
from contextlib import closing
import json
import sqlite3

import pytest

from app.services.request_tracing import TraceCollector, TraceMiddleware
from scripts.m33p1_native_probe import OwnProcessCounters, counter_delta, installed


def test_own_process_counters_have_monotonic_values_without_enumeration():
    counter = OwnProcessCounters()
    before = counter.snapshot()
    sum(i * i for i in range(10000))
    delta = counter_delta(before, counter.snapshot())
    if counter.available:
        assert delta['thread_cycles'] > 0
        assert all(value >= 0 for value in delta.values())
    else:
        assert delta is None
    with pytest.raises(ValueError):
        counter_delta({'thread_cycles': 2}, {'thread_cycles': 1})


def test_native_probe_records_failures_ids_and_restores_hooks(tmp_path):
    import m33_request_trace
    from scripts.m33p1_native_probe import installed
    original = m33_request_trace.sql_span
    original_call = TraceMiddleware.__call__
    collector = TraceCollector()
    async def app(scope, receive, send):
        with closing(sqlite3.connect(tmp_path/'SYNTHETIC.db', factory=m33_request_trace.TraceConnection)) as c:
            c.execute('CREATE TABLE secret_payload_is_not_exported(id INTEGER PRIMARY KEY)')
            c.execute('BEGIN IMMEDIATE')
            c.execute('INSERT INTO secret_payload_is_not_exported VALUES(?)', (1,))
            c.commit()
            with pytest.raises(sqlite3.IntegrityError):
                c.execute('INSERT INTO secret_payload_is_not_exported VALUES(?)', (1,))
            c.rollback()
        # Windows timer resolution can coalesce a 2 ms and 6 ms wakeup. Give the
        # real heartbeat more than one scheduler quantum; no wall-time assertion.
        await asyncio.sleep(.04)
        await send({'type': 'http.response.start', 'status': 200, 'headers': []})
        await send({'type': 'http.response.body', 'body': b'ok'})
    async def noop(*args): pass
    with installed() as report:
        asyncio.run(TraceMiddleware(app, collector)({'type': 'http'}, noop, noop))
    row = collector.export()['requests'][0]
    assert report['native_calls'] and report['event_loop_lateness']
    assert {r['request_id'] for r in report['native_calls']} == {row['request_id']}
    assert any(r['failed'] for r in report['native_calls'])
    assert all(r['end_ns'] >= r['start_ns'] for r in report['native_calls'])
    assert b'secret_payload' not in json.dumps(report).encode()
    assert m33_request_trace.sql_span is original and TraceMiddleware.__call__ is original_call


def test_probe_bound_and_exception_restore():
    import m33_request_trace
    original = m33_request_trace.sql_span
    with pytest.raises(ValueError):
        with installed(capacity=0): pass
    with pytest.raises(RuntimeError):
        with installed(capacity=1):
            raise RuntimeError('synthetic')
    assert m33_request_trace.sql_span is original


def test_diagnostic_reuse_serializes_worker_threads_and_rolls_back_conflicts(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from datetime import datetime, timezone
    from app.db.alerts import AlertRepository
    from app.db.events import EventRepository, EventIdConflictError
    from app.services.event_normalizer import normalize_wazuh_event
    from app.services.source_adapters import SourceContext
    from scripts.m30_synthetic import win
    from scripts.m33p1_reuse_control import installed as reuse
    path = tmp_path/'SYNTHETIC-reuse.db'
    AlertRepository(f'sqlite:///{path.as_posix()}', migration_target_version=17).initialize()
    repository = EventRepository(path, retention_days=30, max_records=100000)
    original = EventRepository._connect
    rows = [normalize_wazuh_event(win(991100+i, datetime.now(timezone.utc), '4688'),
            context=SourceContext(transport_authenticated=True)) for i in range(8)]
    with reuse() as report:
        with ThreadPoolExecutor(max_workers=2) as pool:
            assert not any(row.duplicate for row in pool.map(repository.ingest, rows))
            assert all(row.duplicate for row in pool.map(repository.ingest, rows))
        with pytest.raises(EventIdConflictError):
            repository.ingest(rows[0].model_copy(update={'deduplication_id':'0'*64}))
        assert repository.ingest(rows[0]).duplicate
    assert report['physical_connections'] == report['physical_closed'] == 1
    assert report['leases'] == 18 and EventRepository._connect is original
    with closing(sqlite3.connect(path)) as c:
        assert c.execute('SELECT COUNT(*) FROM security_events').fetchone()[0] == 8
        assert c.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
        assert not c.execute('PRAGMA foreign_key_check').fetchall()


def test_health_does_not_initialize_unrelated_api_route_contexts(tmp_path, monkeypatch):
    import fastapi.routing
    from fastapi.testclient import TestClient
    from app.main import create_app
    from app.core.config import Settings
    app = create_app(Settings(database_url='sqlite:///'+(tmp_path/'SYNTHETIC-health.db').as_posix(),
        ai_enabled=False, correlation_enabled=False, allow_m14_schema_migration=False))
    def forbidden_build(*args, **kwargs):
        raise RuntimeError('Health must not initialize unrelated API routers')
    with TestClient(app) as client:
        with monkeypatch.context() as patch:
            patch.setattr(fastapi.routing._IncludedRouter, '_build_effective_context', forbidden_build)
            response = client.get('/health')
            assert response.status_code == 200
            assert response.json() == {'status':'ok','service':'cyberqalqon-backend'}
        # Normal API authentication remains required once routers are used.
        assert client.get('/api/v1/events').status_code == 401
