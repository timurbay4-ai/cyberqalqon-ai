from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
import sqlite3
import threading

import pytest

from app.services.continuous_shadow import prepare, ContinuousShadowWorker, ContinuousShadowError
from app.services.shadow_rules import catalog
from app.services.shadow_detection import snapshot_columns
from scripts.m30_synthetic import ssh, win
from tests.test_m31_history import BASE, PREFIX, prepared, client, ingest


def worker_for(client, prepared, *, rule_id='SHADOW-WINDOWS-AUTH', fault_hook=None):
    service = client.app.state.shadow_history_service
    rule = next(value for value in catalog() if value.rule_id == rule_id)
    path = prepared[1].path.parent / 'm34-independent-evaluation.db'
    prepare(path, service, rule, first_end=BASE+timedelta(seconds=60), disposable_only=True)
    return ContinuousShadowWorker(path, service, rule, disposable_only=True, fault_hook=fault_hook)


def test_network_query_expressions_never_change_physical_snapshot_columns():
    columns = snapshot_columns().split(',')
    assert 'structured_json' in columns and 'raw_event_json' in columns
    assert all(value.isidentifier() for value in columns)
    assert len(columns) == len(set(columns))


@pytest.mark.parametrize('scenario', ['windows', 'linux'])
def test_continuous_findings_are_durable_deduplicated_and_investigable(client, prepared, scenario):
    if scenario == 'linux':
        ingest(client, [ssh(i, BASE+timedelta(seconds=i*10), i == 3) for i in range(4)])
    else:
        ingest(client)
    rule_id = 'SHADOW-SSH-AUTH' if scenario == 'linux' else 'SHADOW-WINDOWS-AUTH'
    worker = worker_for(client, prepared, rule_id=rule_id)
    with worker:
        first = worker.tick()
        second = worker.tick()
        assert first['ticks_committed'] == 1 and second['ticks_committed'] == 2
        assert first['last_finding_ids'] == second['last_finding_ids']
        assert len(first['last_finding_ids']) == 1
        finding = first['last_finding_ids'][0]
        detail = client.get(PREFIX+'/findings/'+finding).json()
        assert detail['revision'] == 1 and len(detail['matching_evidence']['evidence']) == 4
        response = client.post('/api/v1/investigations/workbench', json={
            'target_type': 'DURABLE_SHADOW_FINDING', 'target_id': finding, 'shadow_revision': 1,
            'relative_minutes': None, 'start_time': (BASE-timedelta(seconds=1)).isoformat(),
            'end_time': (BASE+timedelta(minutes=2)).isoformat()})
        assert response.status_code == 200, response.text
        assert response.json()['durable_shadow_context']['finding_id'] == finding
        assert second['source_checkpoint_reused'] is False and second['historical_continuity'] == 'UNPROVEN'
    reopened = ContinuousShadowWorker(worker.path, worker.service, worker.rule, disposable_only=True)
    with reopened:
        third = reopened.tick()
        assert third['ticks_committed'] == 3 and third['last_finding_ids'] == first['last_finding_ids']
    with closing(sqlite3.connect(prepared[1].source)) as connection:
        assert connection.execute('PRAGMA user_version').fetchone()[0] == 17
        assert connection.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
        assert connection.execute('PRAGMA foreign_key_check').fetchall() == []


@pytest.mark.parametrize('stage', ['AFTER_PENDING_COMMIT', 'AFTER_HISTORY_COMMIT', 'BEFORE_CHECKPOINT_COMMIT'])
def test_continuous_crash_windows_keep_pending_request_and_never_skip(client, prepared, stage):
    ingest(client)
    def fail(value):
        if value == stage:
            raise RuntimeError('SYNTHETIC crash')
    worker = worker_for(client, prepared, fault_hook=fail)
    with worker:
        with pytest.raises(RuntimeError, match='SYNTHETIC'):
            worker.tick()
        state = worker.status()
        assert state['ticks_committed'] == 0 and state['pending_evaluation']
    restored = ContinuousShadowWorker(worker.path, worker.service, worker.rule, disposable_only=True)
    with restored:
        result = restored.tick()
        assert result['ticks_committed'] == 1 and len(result['last_finding_ids']) == 1
        assert not result['pending_evaluation']
    with closing(sqlite3.connect(prepared[1].path)) as connection:
        assert connection.execute('SELECT COUNT(*) FROM shadow_runs').fetchone()[0] == 1
        assert connection.execute('SELECT COUNT(*) FROM shadow_findings').fetchone()[0] == 1


@pytest.mark.parametrize('mode', ['missing', 'changed'])
def test_continuous_source_gap_or_tampering_never_advances_checkpoint(client, prepared, mode):
    ingest(client)
    with worker_for(client, prepared) as worker:
        worker.tick()
        with closing(sqlite3.connect(prepared[1].source)) as connection:
            if mode == 'missing':
                connection.execute('DELETE FROM security_events')
            else:
                connection.execute("UPDATE security_events SET message='SYNTHETIC changed'")
            connection.commit()
        with pytest.raises(ContinuousShadowError, match='SOURCE_RETENTION_GAP' if mode == 'missing' else 'SOURCE_CONTENT_CHANGED'):
            worker.tick()
        assert worker.status()['ticks_committed'] == 1


def test_continuous_late_arrival_is_accounted_without_claiming_replay(client, prepared):
    ingest(client)
    with worker_for(client, prepared) as worker:
        worker.tick()
        ingest(client, [win(34001, BASE-timedelta(seconds=1000))])
        result = worker.tick()
        assert result['late_observed'] == 1 and result['late_outside_overlap'] == 1
        assert result['gap_status'] == 'UNPROVEN'


def test_continuous_cancellation_not_due_and_owned_loop_shutdown(client, prepared):
    worker = worker_for(client, prepared)
    stop = threading.Event()
    with worker:
        due = worker.tick(now=BASE)
        assert due['state'] == 'NOT_DUE' and due['ticks_committed'] == 0
        stop.set()
        result = worker.run(stop)
        assert result['ticks_committed'] == 0
        with pytest.raises(ContinuousShadowError, match='WORKER_CANCELLED'):
            worker.tick(cancel_event=stop)
    assert worker.status()['state'] == 'DEGRADED'  # Cancellation was observed, not hidden.


def test_continuous_namespace_refuses_existing_checkpoint_and_rule_drift(client, prepared):
    worker = worker_for(client, prepared)
    original = worker.path.read_bytes()
    with pytest.raises(ContinuousShadowError, match='NEW_ISOLATED'):
        prepare(worker.path, worker.service, worker.rule, first_end=BASE, disposable_only=True)
    assert worker.path.read_bytes() == original
    changed = worker.rule.model_copy(update={'title': 'Different version'})
    with pytest.raises(ContinuousShadowError, match='BINDING'):
        with ContinuousShadowWorker(worker.path, worker.service, changed, disposable_only=True):
            pass


def test_continuous_owner_lock_and_backpressure_are_explicit(client, prepared):
    with worker_for(client, prepared) as worker:
        other = ContinuousShadowWorker(worker.path, worker.service, worker.rule, disposable_only=True)
        with pytest.raises(OSError):
            other.open()
        worker._lock.acquire()
        try:
            with pytest.raises(ContinuousShadowError, match='BACKPRESSURE'):
                worker.tick()
        finally:
            worker._lock.release()


def test_continuous_corrupt_checkpoint_is_typed_and_fail_closed(client, prepared):
    worker = worker_for(client, prepared)
    with closing(sqlite3.connect(worker.path)) as connection:
        connection.execute("UPDATE checkpoint SET data='{}'")
        connection.commit()
    with pytest.raises(ContinuousShadowError, match='BINDING|UNAVAILABLE'):
        worker.open()


@pytest.mark.parametrize('source', ['windows', 'linux'])
@pytest.mark.parametrize('scenario', ['benign', 'ambiguous'])
def test_continuous_negative_authentication_scenarios_do_not_create_findings(client, prepared, scenario, source):
    if source == 'linux':
        rows = [ssh(34050+i, BASE+timedelta(seconds=i*10), i == 3) for i in range(4)]
        if scenario == 'benign':
            rows = rows[-1:]
        else:
            rows[-1]['agent']['id'] = 'different-endpoint'
    elif scenario == 'benign':
        rows = [win(34050, BASE, '4624')]
    else:
        rows = [win(34050+i, BASE+timedelta(seconds=i*10), '4625' if i < 3 else '4624',
                    agent='different-endpoint' if i == 3 else '930') for i in range(4)]
    ingest(client, rows)
    with worker_for(client, prepared, rule_id='SHADOW-SSH-AUTH' if source == 'linux' else 'SHADOW-WINDOWS-AUTH') as worker:
        assert worker.tick()['last_finding_ids'] == []


def test_continuous_unsealed_history_crash_is_an_explicit_recovery_blocker(client, prepared):
    from app.db.shadow_history import ShadowStoreError
    ingest(client)
    service = client.app.state.shadow_history_service
    original = service._fault
    def fail(stage):
        if stage == 'AFTER_RUN_BEGIN':
            raise RuntimeError('SYNTHETIC unsealed crash')
    worker = worker_for(client, prepared)
    with worker:
        service._fault = fail
        try:
            with pytest.raises(ShadowStoreError):
                worker.tick()
        finally:
            service._fault = original
        # Preserve this legacy M34 no-witness case explicitly. New M35 runs
        # have a durable intent and are covered by the new recovery tests.
        with closing(sqlite3.connect(prepared[1].path)) as connection:
            row=connection.execute('SELECT run_id,request_json FROM shadow_runs').fetchone()
            body=json.loads(row[1]);body.pop('recovery_intent')
            connection.execute('UPDATE shadow_runs SET request_json=? WHERE run_id=?',
                               (json.dumps(body,separators=(',',':'),sort_keys=True),row[0]))
            connection.commit()
        with pytest.raises(ShadowStoreError):
            worker.tick()
        state = worker.status()
        assert state['pending_evaluation'] and state['ticks_committed'] == 0
        with closing(sqlite3.connect(prepared[1].path)) as connection:
            assert connection.execute('SELECT COUNT(*) FROM shadow_findings').fetchone()[0] == 0
            assert connection.execute('SELECT snapshot_json FROM shadow_runs').fetchone()[0] is None


def test_owned_continuous_loop_runs_then_joins_before_owner_shutdown(client,prepared):
    ingest(client)
    committed,stop=threading.Event(),threading.Event()
    result=[]
    def observe(stage):
        if stage=='BEFORE_CHECKPOINT_COMMIT':committed.set()
    worker=worker_for(client,prepared,fault_hook=observe)
    with worker:
        def run():
            try:result.append(worker.run(stop,poll_seconds=.05))
            except BaseException as error:result.append(error)
        thread=threading.Thread(target=run,name='SYNTHETIC-owned-m34-loop')
        thread.start()
        try:assert committed.wait(5)
        finally:stop.set();thread.join(5)
        assert not thread.is_alive() and result and isinstance(result[0],dict)
        assert worker.status()['ticks_committed']==1


def test_checkpoint_journal_policy_changes_fail_closed(client,prepared):
    worker=worker_for(client,prepared)
    with closing(sqlite3.connect(worker.path)) as connection:
        connection.execute('PRAGMA journal_mode=DELETE')
    with pytest.raises(ContinuousShadowError,match='DURABILITY_POLICY'):
        worker.open()
