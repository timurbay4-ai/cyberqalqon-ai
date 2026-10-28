import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import sys
from contextlib import closing
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from app.services.request_tracing import TraceCollector, TraceMiddleware, accounting, span, union_ns


def test_interval_union_and_exact_accounting():
    assert union_ns([(0, 10), (2, 4), (8, 20), (22, 25)]) == 23
    row={'start_ns':10,'end_ns':100,'spans':[{'start_ns':20,'end_ns':60},{'start_ns':30,'end_ns':80}]}
    result=accounting(row,0,110)
    assert result=={'http_total_ns':110,'measured_union_ns':60,'server_unattributed_ns':30,'transport_or_client_ns':20}
    with pytest.raises(ValueError):union_ns([(5,1)])


def test_trace_constructor_gate_and_default_inert(tmp_path):
    settings=Settings(database_url=f'sqlite:///{(tmp_path/"source.db").as_posix()}',ai_enabled=False)
    with pytest.raises(ValueError,match='disposable'):create_app(settings,disposable_request_traces=TraceCollector())
    with TestClient(create_app(settings)) as client:
        assert 'x-perf-trace-id' not in client.get('/health').headers


def test_concurrent_request_ids_context_and_private_input(tmp_path):
    collector=TraceCollector()
    settings=Settings(database_url=f'sqlite:///{(tmp_path/"source.db").as_posix()}',ai_enabled=False,wazuh_ingest_api_key='SYNTHETIC-secret')
    with TestClient(create_app(settings,disposable_detection_simulation=True,disposable_request_traces=collector)) as client:
        def request(_):return client.post('/api/v1/events/ingest?private=do-not-store',headers={'X-API-Key':'wrong-private-key','X-Perf-Trace-ID':'forged'},json={'secret':'do-not-store'})
        with ThreadPoolExecutor(4) as pool:responses=list(pool.map(request,range(12)))
    exported=collector.export();text=str(exported)
    assert all(r.status_code==401 for r in responses)
    ids={r.headers['x-perf-trace-id'] for r in responses}
    assert len(ids)==12 and all(len(i)==32 for i in ids)
    assert not any(secret in text for secret in ('do-not-store','wrong-private-key','SYNTHETIC-secret','forged'))
    assert all(r['end_ns']>=r['start_ns'] and not r['incomplete'] for r in exported['requests'])
    assert all(any(s['stage']=='INGEST_AUTH' for s in r['spans']) for r in exported['requests'])
    assert all(next(s for s in r['spans']if s['stage']=='INGEST_AUTH')['failed'] for r in exported['requests'])


def test_trace_bounds_are_explicit_and_failures_close():
    collector=TraceCollector(capacity=1,max_spans=1)
    async def app(scope,receive,send):
        with span('OUTER'):
            with span('INNER'):pass
        raise RuntimeError('private-error-message')
    wrapped=TraceMiddleware(app,collector)
    async def noop(*args):pass
    with pytest.raises(RuntimeError):asyncio.run(wrapped({'type':'http'},noop,noop))
    assert collector.export()['requests'][0]['incomplete']
    assert collector.export()['requests'][0]['end_ns'] is not None
    with pytest.raises(RuntimeError):asyncio.run(wrapped({'type':'http'},noop,noop))
    assert collector.dropped==1
    assert 'private-error-message' not in str(collector.export())
    collector.clear_completed()
    assert collector.export()=={'dropped':0,'requests':[]}
    collector.begin()
    with pytest.raises(RuntimeError,match='active'):collector.clear_completed()


def test_sql_explicit_commit_rollback_close_and_hook_restoration(tmp_path):
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
    from m33_request_trace import installed
    original=sqlite3.connect
    collector=TraceCollector()
    async def app(scope,receive,send):
        with installed():
            connection=sqlite3.connect(tmp_path/'test.db')
            connection.execute('CREATE TABLE synthetic(id INTEGER PRIMARY KEY)')
            connection.execute('INSERT INTO synthetic VALUES(1)');connection.commit()
            connection.execute('INSERT INTO synthetic VALUES(2)');connection.rollback()
            assert connection.execute('SELECT COUNT(*) FROM synthetic').fetchone()[0]==1
            connection.close()
        await send({'type':'http.response.start','status':200,'headers':[]})
        await send({'type':'http.response.body','body':b'ok'})
    async def noop(*args):pass
    asyncio.run(TraceMiddleware(app,collector)({'type':'http'},noop,noop))
    assert sqlite3.connect is original
    stages={s['stage'] for s in collector.export()['requests'][0]['spans']}
    assert {'SQLITE_OPEN','SQLITE_EXPLICIT_COMMIT','SQLITE_EXPLICIT_ROLLBACK','SQLITE_CLOSE_CHECKPOINT_INCLUSIVE','SQLITE_FETCH_ONE'}<=stages


@pytest.mark.parametrize('fault',['COMMIT','FTS','RETENTION','BUSY'])
def test_traced_ingest_failure_is_not_acknowledged_and_retry_recovers(tmp_path,monkeypatch,fault):
    from scripts.m30_synthetic import win
    from m33_request_trace import installed, TraceConnection
    collector=TraceCollector()
    settings=Settings(database_url=f'sqlite:///{(tmp_path/"source.db").as_posix()}',ai_enabled=False,wazuh_ingest_api_key='SYNTHETIC-key')
    raw=win(880001,datetime.now(timezone.utc),'4688')
    original_fts_trigger=None
    with TestClient(create_app(settings,disposable_detection_simulation=True,disposable_request_traces=collector)) as client, installed():
        repo=client.app.state.event_repository
        with monkeypatch.context() as patch:
            if fault=='COMMIT':
                def failed_commit(self):raise sqlite3.OperationalError('SYNTHETIC-private-fault')
                patch.setattr(TraceConnection,'_commit_native',failed_commit)
            elif fault=='RETENTION':
                def failed_retention(*args,**kwargs):raise sqlite3.OperationalError('SYNTHETIC-private-fault')
                patch.setattr(repo,'_enforce_retention',failed_retention)
            elif fault=='BUSY':
                def busy():raise sqlite3.OperationalError('database is locked SYNTHETIC-private-fault')
                patch.setattr(repo,'_connect',busy)
            else:
                with closing(sqlite3.connect(repo.path)) as c:
                    original_fts_trigger=c.execute("SELECT sql FROM sqlite_master WHERE name='security_events_fts_insert'").fetchone()[0]
                    c.execute('DROP TRIGGER security_events_fts_insert')
                    c.execute("CREATE TRIGGER security_events_fts_insert AFTER INSERT ON security_events BEGIN SELECT RAISE(ABORT,'SYNTHETIC-private-fault'); END")
                    c.commit()
            failed=client.post('/api/v1/events/ingest',headers={'X-API-Key':'SYNTHETIC-key'},json=raw)
            assert failed.status_code==503 and 'SYNTHETIC-private-fault' not in failed.text
        with closing(sqlite3.connect(repo.path)) as c:
            assert c.execute('SELECT COUNT(*) FROM security_events').fetchone()[0]==0
            if original_fts_trigger:
                c.execute('DROP TRIGGER security_events_fts_insert');c.execute(original_fts_trigger)
            c.commit()
            assert c.execute('PRAGMA quick_check').fetchone()[0]=='ok'
            assert not c.execute('PRAGMA foreign_key_check').fetchall()
        inserted=client.post('/api/v1/events/ingest',headers={'X-API-Key':'SYNTHETIC-key'},json=raw)
        duplicate=client.post('/api/v1/events/ingest',headers={'X-API-Key':'SYNTHETIC-key'},json=raw)
        assert inserted.status_code==201 and duplicate.status_code==200
        assert inserted.json()['event']['event_id']==duplicate.json()['event']['event_id']
    rows=collector.export()['requests']
    assert [row['status'] for row in rows]==[503,201,200]
    assert all(row['end_ns'] is not None for row in rows)
    assert 'SYNTHETIC-private-fault' not in str(rows)
    if fault=='COMMIT':
        assert any(s['stage']=='SQLITE_EXPLICIT_COMMIT' and s['failed'] for s in rows[0]['spans'])
        assert any(s['stage']=='SQLITE_CONTEXT_ROLLBACK' and not s['failed'] for s in rows[0]['spans'])


def test_disconnect_and_cancellation_finish_trace_without_fabricating_response():
    collector=TraceCollector()
    async def app(scope,receive,send):
        with span('SYNTHETIC_CANCELLED_WORK'):
            raise asyncio.CancelledError()
    async def noop(*args):pass
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(TraceMiddleware(app,collector)({'type':'http'},noop,noop))
    row=collector.export()['requests'][0]
    assert row['status'] is None and row['end_ns'] is not None
    assert row['spans'][0]['failed'] and 'response_complete_ns' not in row['milestones']


def test_worker_context_propagates_and_span_parent_is_valid():
    from app.services.request_tracing import traced_threadpool
    collector=TraceCollector()
    async def app(scope,receive,send):
        def work():
            with span('SYNTHETIC_SQL_WORK'):return 42
        assert await traced_threadpool(work)==42
        await send({'type':'http.response.start','status':200,'headers':[]})
        await send({'type':'http.response.body','body':b'ok'})
    async def noop(*args):pass
    asyncio.run(TraceMiddleware(app,collector)({'type':'http'},noop,noop))
    row=collector.export()['requests'][0]
    stages={s['stage']:s for s in row['spans']}
    assert stages['SYNTHETIC_SQL_WORK']['parent']==stages['INGEST_WORKER']['id']
    assert all(s['end_ns']>=s['start_ns'] for s in row['spans'])
    assert row['milestones']['response_complete_ns']<=row['end_ns']


def test_real_disposable_sqlite_busy_trace_is_typed_and_recovers(tmp_path,monkeypatch):
    from scripts.m30_synthetic import win
    from m33_request_trace import installed
    collector=TraceCollector()
    settings=Settings(database_url=f'sqlite:///{(tmp_path/"source.db").as_posix()}',ai_enabled=False,wazuh_ingest_api_key='SYNTHETIC-key')
    with TestClient(create_app(settings,disposable_detection_simulation=True,disposable_request_traces=collector)) as client, installed():
        repo=client.app.state.event_repository
        original=repo._connect
        def short_test_timeout():
            connection=original();connection.execute('PRAGMA busy_timeout=50');return connection
        # Only this disposable fixture. The production 5000ms policy is intact.
        monkeypatch.setattr(repo,'_connect',short_test_timeout)
        raw=win(880005,datetime.now(timezone.utc),'4688')
        with closing(sqlite3.connect(repo.path)) as blocker:
            blocker.execute('BEGIN IMMEDIATE')
            result=client.post('/api/v1/events/ingest',headers={'X-API-Key':'SYNTHETIC-key'},json=raw)
            assert result.status_code==503
            blocker.rollback()
        assert client.post('/api/v1/events/ingest',headers={'X-API-Key':'SYNTHETIC-key'},json=raw).status_code==201
    busy=collector.export()['requests'][0]
    begin=next(s for s in busy['spans'] if s['stage']=='SQLITE_BEGIN_LOCK_INCLUSIVE')
    assert begin['failed'] and begin['resource']=='SOURCE'
    assert begin['end_ns']-begin['start_ns']>=20_000_000
    assert not any(s['stage']=='SQLITE_EXPLICIT_COMMIT' and not s['failed'] for s in busy['spans'])


def test_gc_observer_does_not_reenter_trace_lock_and_is_restored():
    import gc
    from m33_request_trace import installed
    collector=TraceCollector()
    callbacks=list(gc.callbacks)
    async def app(scope,receive,send):
        with collector._rows[0].lock:
            gc.collect()
        await send({'type':'http.response.start','status':200,'headers':[]})
        await send({'type':'http.response.body','body':b'ok'})
    async def noop(*args):pass
    with installed() as diagnostic:
        asyncio.run(TraceMiddleware(app,collector)({'type':'http'},noop,noop))
    row=collector.export()['requests'][0]
    assert any(event['invoking_request_id']==row['request_id'] for event in diagnostic['gc_events'])
    assert not diagnostic['gc_overflow'] and gc.callbacks==callbacks


def test_duplicate_after_legitimate_retention_is_new_but_newer_set_stays_idempotent(tmp_path):
    from datetime import timedelta
    from app.db.alerts import AlertRepository
    from app.db.events import EventRepository
    from app.services.event_normalizer import normalize_wazuh_event
    from app.services.source_adapters import SourceContext
    from scripts.m30_synthetic import win
    path=tmp_path/'source.db'
    AlertRepository(f'sqlite:///{path.as_posix()}',migration_target_version=17).initialize()
    repo=EventRepository(path,retention_days=30,max_records=2)
    now=datetime.now(timezone.utc)-timedelta(minutes=1)
    def event(index,at):return normalize_wazuh_event(win(index,at,'4688'),context=SourceContext(transport_authenticated=True))
    repo.ingest(event(1,now));repo.ingest(event(2,now))
    old=event(3,now-timedelta(seconds=20));repo.ingest(old)
    repo.ingest(event(4,now-timedelta(seconds=19)))
    # Correct contract: the previous accepted but unprotected event was evicted.
    assert repo.ingest(old).duplicate is False
    repo=EventRepository(path,retention_days=30,max_records=25)
    newer=[event(100+i,now+timedelta(seconds=60+i)) for i in range(20)]
    for row in newer:assert not repo.ingest(row).duplicate
    for row in newer:assert repo.ingest(row).duplicate
    with closing(sqlite3.connect(path)) as c:
        assert c.execute('SELECT COUNT(*) FROM security_events').fetchone()[0]<=25
        assert c.execute('PRAGMA quick_check').fetchone()[0]=='ok'
        assert not c.execute('PRAGMA foreign_key_check').fetchall()


def test_cancelled_ingest_joins_owned_sqlite_worker_before_trace_completion(tmp_path,monkeypatch):
    import threading
    from scripts.m30_synthetic import win
    collector=TraceCollector()
    settings=Settings(database_url=f'sqlite:///{(tmp_path/"source.db").as_posix()}',ai_enabled=False,wazuh_ingest_api_key='SYNTHETIC-key')
    app=create_app(settings,disposable_detection_simulation=True,disposable_request_traces=collector)
    raw=win(880010,datetime.now(timezone.utc),'4688')
    import json
    body=json.dumps(raw).encode()
    entered,release,finished=threading.Event(),threading.Event(),threading.Event()
    async def exercise():
        async with app.router.lifespan_context(app):
            repo=app.state.event_repository;original=repo.ingest
            def blocked(*args,**kwargs):
                entered.set();assert release.wait(5)
                try:return original(*args,**kwargs)
                finally:finished.set()
            monkeypatch.setattr(repo,'ingest',blocked)
            delivered=False
            async def receive():
                nonlocal delivered
                if not delivered:
                    delivered=True;return {'type':'http.request','body':body,'more_body':False}
                await asyncio.Event().wait()
            sent=[]
            async def send(message):sent.append(message)
            scope={'type':'http','asgi':{'version':'3.0'},'http_version':'1.1','method':'POST',
                   'path':'/api/v1/events/ingest','raw_path':b'/api/v1/events/ingest','query_string':b'',
                   'scheme':'http','server':('127.0.0.1',8000),'client':('127.0.0.1',12345),
                   'headers':[(b'content-type',b'application/json'),(b'x-api-key',b'SYNTHETIC-key')]}
            task=asyncio.create_task(app(scope,receive,send))
            assert await asyncio.to_thread(entered.wait,5)
            task.cancel()
            await asyncio.sleep(.01);release.set()
            try:await task
            except asyncio.CancelledError:pass
            assert finished.is_set()
            assert not any(m.get('status')==201 for m in sent)
    try:asyncio.run(exercise())
    finally:release.set();finished.wait(5)
    row=collector.export()['requests'][0]
    worker=next(s for s in row['spans']if s['stage']=='INGEST_WORKER')
    assert worker['end_ns'] is not None and worker['end_ns']<=row['end_ns']
    # A lost response may leave a committed event; the normal retry must dedup.
    with TestClient(create_app(settings)) as client:
        assert client.post('/api/v1/events/ingest',headers={'X-API-Key':'SYNTHETIC-key'},json=raw).status_code==200
