from contextlib import closing
from datetime import timedelta
import json
import sqlite3
import threading

import pytest

from app.db.shadow_history import sha,ShadowStoreError
from app.db.cqql import CQQLQueryCancelledError,CQQLQueryBusyError
from app.services.continuous_shadow import ContinuousShadowWorker,ContinuousShadowError,MAX_TICKS
from app.services.shadow_detection import ShadowResourceLimitError
from app.services.wazuh_normalizer import canonical_json
from scripts.m30_synthetic import win
from tests.test_m31_history import client,prepared,ingest,BASE,PREFIX
from tests.test_m34_continuous import worker_for


def test_m35_checkpoint_cas_rejects_stale_valid_state(client,prepared):
    ingest(client)
    with worker_for(client,prepared) as worker:
        definition,state=worker._load();original=canonical_json(state)
        worker.tick()
        with pytest.raises(ContinuousShadowError,match='COMPARE_AND_SWAP'):
            worker._write(definition,state,expected_data=original)
        assert worker.status()['ticks_committed']==1


def test_m35_history_commit_and_checkpoint_commit_are_distinct_observations(client,prepared):
    ingest(client)
    def fail(stage):
        if stage=='AFTER_HISTORY_COMMIT':raise RuntimeError('SYNTHETIC interruption')
    worker=worker_for(client,prepared,fault_hook=fail)
    with worker:
        with pytest.raises(RuntimeError):worker.tick()
        status=worker.status()
        assert status['ticks_committed']==0 and status['progress']['stage']=='FINDINGS_COMMITTED'
        assert status['progress']['last_completed_evaluation']==status['progress']['pending_run_id']
        assert status['progress']['transition_count']==1
        assert status['queue_depth']==1
        worker._fault=lambda stage:None
        done=worker.tick()
        assert done['progress']['stage']=='CHECKPOINT_COMMITTED' and done['queue_depth']==0
        assert done['progress']['transition_count']==2
        assert [x['stage'] for x in done['progress']['transition_tail']]==['PENDING_COMMITTED','CHECKPOINT_COMMITTED']


def test_m35_operations_exposes_unsealed_recovery_then_completed_checkpoint(client,prepared):
    ingest(client);service=client.app.state.shadow_history_service;worker=worker_for(client,prepared)
    with worker:
        def fail(stage):
            if stage=='AFTER_RUN_BEGIN':raise RuntimeError('SYNTHETIC interruption')
        service._fault=fail
        with pytest.raises(ShadowStoreError):worker.tick()
        service._fault=lambda stage:None
        client.app.state.continuous_shadow_workers=[worker]
        report=client.get('/api/v1/collection/sources')
        assert report.status_code==200
        status=report.json()['detection_workers'][0]
        assert status['progress']['stage']=='RECOVERY_REQUIRED'
        assert status['progress']['snapshot_state']=='UNSEALED'
        assert status['progress']['unsealed_intent_present']
        worker.tick()
        assert client.get('/api/v1/collection/sources').json()['detection_workers'][0]['progress']['stage']=='CHECKPOINT_COMMITTED'


def test_m35_late_inside_overlap_produces_new_pattern_without_claiming_complete(client,prepared):
    ingest(client,[win(35010+i,BASE+timedelta(seconds=i*10),'4625') for i in range(3)])
    with worker_for(client,prepared) as worker:
        assert not worker.tick()['last_finding_ids']
        ingest(client,[win(35013,BASE+timedelta(seconds=35),'4624')])
        result=worker.tick()
        assert len(result['last_finding_ids'])==1 and result['late_observed']==1
        assert result['late_outside_overlap']==0 and result['progress']['window_completeness']=='UNPROVEN'


def test_m35_retention_gap_preserves_metadata_and_does_not_advance(client,prepared):
    ids=ingest(client)
    with worker_for(client,prepared) as worker:
        result=worker.tick();finding=result['last_finding_ids'][0]
        with closing(sqlite3.connect(prepared[1].source)) as c:
            c.execute('DELETE FROM security_events WHERE event_id=?',(ids[0],));c.commit()
        with pytest.raises(ContinuousShadowError,match='SOURCE_RETENTION_GAP'):worker.tick()
        status=worker.status()
        assert status['ticks_committed']==1 and status['progress']['observed_gap']=='RETENTION_GAP'
        detail=client.get(PREFIX+'/findings/'+finding).json()
        assert detail['current_evidence_availability'][ids[0]]=='MISSING'
        assert detail['state']=='SHADOW_CANDIDATE' and detail['history']


def test_m35_checkpoint_busy_is_typed_and_later_recovers(client,prepared):
    ingest(client)
    with worker_for(client,prepared) as worker:
        with closing(sqlite3.connect(worker.path)) as c:
            c.execute('BEGIN IMMEDIATE')
            with pytest.raises(ContinuousShadowError,match='CHECKPOINT_BUSY'):worker.tick()
            c.rollback()
        assert worker.status()['ticks_committed']==0
        assert worker.tick()['ticks_committed']==1


def test_m35_queue_cancellation_join_and_resume_keeps_pending_intent(client,prepared):
    ingest(client);entered=threading.Event();release=threading.Event();stop=threading.Event();results=[]
    service=client.app.state.shadow_history_service
    def pause(stage):
        if stage=='AFTER_SNAPSHOT_COMMIT':
            entered.set()
            if not release.wait(5):raise RuntimeError('SYNTHETIC bounded wait expired')
    service._fault=pause
    worker=worker_for(client,prepared)
    with worker:
        def run():
            try:results.append(worker.run(stop,poll_seconds=.05))
            except BaseException as exc:results.append(exc)
        thread=threading.Thread(target=run,name='SYNTHETIC-M35-owned-cancellation');thread.start()
        try:
            assert entered.wait(5)
            with pytest.raises(ContinuousShadowError,match='BACKPRESSURE'):worker.tick()
            with pytest.raises(ContinuousShadowError,match='SHUTDOWN_PENDING'):worker.close()
        finally:stop.set();release.set();thread.join(5);service._fault=lambda stage:None
        assert not thread.is_alive() and isinstance(results[0],dict)
        assert worker.status()['ticks_committed']==0 and worker.status()['pending_evaluation']
        result=worker.tick()
        assert result['ticks_committed']==1 and len(result['last_finding_ids'])==1


@pytest.mark.parametrize('kind',['tick-capacity','invalid-counter','audit-capacity'])
def test_m35_checkpoint_limits_cannot_be_silently_raised_or_bypassed(client,prepared,kind):
    worker=worker_for(client,prepared)
    with closing(sqlite3.connect(worker.path)) as c:
        row=c.execute('SELECT definition,data FROM checkpoint').fetchone();definition,state=map(json.loads,row)
        if kind=='tick-capacity':
            state['sequence']=MAX_TICKS
            from datetime import datetime
            state['last_end']=(datetime.fromisoformat(definition['first_end'])+timedelta(seconds=(MAX_TICKS-1)*definition['stride_seconds'])).isoformat()
        if kind=='invalid-counter':state['sequence']=True
        if kind=='audit-capacity':state['transition_tail']=[{}]*33
        c.execute('UPDATE checkpoint SET data=?,state_sha=?',(canonical_json(state),sha([definition,state])));c.commit()
    with pytest.raises(ContinuousShadowError,match='CAPACITY|INVALID'):
        with worker:worker.tick()


@pytest.mark.parametrize('kind',['rows','bytes'])
def test_m35_source_observation_capacity_is_fail_closed_before_pending_write(client,prepared,kind):
    ingest(client)
    with worker_for(client,prepared) as worker:
        with closing(sqlite3.connect(prepared[1].source)) as c:
            if kind=='bytes':
                c.execute('UPDATE security_events SET raw_event_json=? WHERE rowid=(SELECT MIN(rowid) FROM security_events)',
                          (json.dumps({'SYNTHETIC_padding':'x'*(8*1024*1024+1)}),))
            else:
                columns=[row[1] for row in c.execute('PRAGMA table_info(security_events)')]
                original=list(c.execute('SELECT * FROM security_events LIMIT 1').fetchone())
                for i in range(998):
                    row=list(original);row[columns.index('event_id')]='EVT-'+f'{i+350000:024X}'
                    row[columns.index('deduplication_id')]=f'{i+350000:064x}'
                    c.execute('INSERT INTO security_events ('+','.join(columns)+') VALUES ('+','.join('?' for _ in columns)+')',row)
            c.commit()
        with pytest.raises((ContinuousShadowError,ShadowResourceLimitError)) as raised:worker.tick()
        assert 'CAPACITY' in str(raised.value) or 'MAX_INPUT_BYTES' in str(raised.value)
        status=worker.status()
        assert status['ticks_committed']==0 and not status['pending_evaluation'] and status['queue_depth']==0


@pytest.mark.parametrize('kind',['rule','boundary','late-counter','policy'])
def test_m35_checksum_valid_pending_intent_still_requires_semantic_binding(client,prepared,kind):
    ingest(client)
    def fail(stage):
        if stage=='AFTER_PENDING_COMMIT':raise RuntimeError('SYNTHETIC pause')
    worker=worker_for(client,prepared,fault_hook=fail)
    with worker:
        with pytest.raises(RuntimeError):worker.tick()
    with closing(sqlite3.connect(worker.path)) as c:
        definition,state=map(json.loads,c.execute('SELECT definition,data FROM checkpoint').fetchone())
        if kind=='rule':state['pending']['request']['simulation']['rule']['title']='SYNTHETIC changed rule'
        if kind=='boundary':state['pending']['end']=(BASE+timedelta(seconds=90)).isoformat()
        if kind=='late-counter':state['pending']['late']=1
        if kind=='policy':state['pending']['request']['identity_policy']['minimum']='VERIFIED'
        c.execute('UPDATE checkpoint SET data=?,state_sha=?',(canonical_json(state),sha([definition,state])));c.commit()
    with pytest.raises(ContinuousShadowError,match='PENDING_MISMATCH'):
        with ContinuousShadowWorker(worker.path,worker.service,worker.rule,disposable_only=True):pass


def test_m35_real_query_slot_overload_keeps_pending_then_recovers(client,prepared):
    ingest(client);query=client.app.state.shadow_history_service.query_repository
    acquired=0
    with worker_for(client,prepared) as worker:
        try:
            while query._slots.acquire(blocking=False):acquired+=1
            with pytest.raises(CQQLQueryBusyError):worker.tick()
            assert worker.status()['ticks_committed']==0 and worker.status()['queue_depth']==1
        finally:
            for _ in range(acquired):query._slots.release()
        assert worker.tick()['ticks_committed']==1
