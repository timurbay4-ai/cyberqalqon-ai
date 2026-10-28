from __future__ import annotations
from contextlib import closing
from datetime import datetime,timedelta,timezone
import hashlib
import json
from pathlib import Path
import random
import sqlite3
import threading
import pytest
from app.db.alerts import AlertRepository
from app.db.cqql import CQQLSearchRepository,CQQLQueryCancelledError,InvalidCQQLCursorError,CQQLExecutionError
from app.db.fts_rowid import install,rollback,verify,content_digest,file_sha
from app.db.shadow_history import ShadowHistoryRepository,ShadowStoreError
from app.services.cqql import compile_cqql
from app.services.shadow_backup import capture_pair,validate_backup,restore_offline,inspect_pair
from tests.test_m31_history import prepared,client,ingest,evaluate,payload,BASE,PREFIX
from scripts.benchmark_cqql import INSERT_SQL,INSERT_COLUMNS,synthetic_row
from scripts.m30_synthetic import auth


@pytest.fixture
def fts(tmp_path):
    path=tmp_path/'SYNTHETIC-m32.db';base=datetime.now(timezone.utc)
    AlertRepository(f'sqlite:///{path.as_posix()}',migration_target_version=17).initialize()
    words=['alpha beta','CAFÉ naïve','\u1ed9 unicode','日本語','alpha','nothing','beta alpha','a OR b']
    with closing(sqlite3.connect(path)) as c:
        rows=[]
        for index in range(81):
            row=list(synthetic_row(index,base));row[INSERT_COLUMNS.index('search_text')]=words[index%len(words)]
            # Deliberate timestamp ties for deterministic cursor ordering.
            row[INSERT_COLUMNS.index('occurred_at')]=(base-timedelta(seconds=index//3)).isoformat();rows.append(row)
        random.Random(32001).shuffle(rows);c.executemany(INSERT_SQL,rows);c.commit()
    backup=tmp_path/'pre-index.db';manifest=install(path,backup,disposable_only=True)
    return path,base,backup,manifest


@pytest.mark.parametrize('text',['alpha','CAFÉ','naive','\u1ed9','日本語','alpha beta','absent','a OR b'])
@pytest.mark.parametrize('sort',['newest','oldest'])
def test_fts_independent_membership_order_and_cursor(fts,text,sort):
    path,base,_,_=fts;compiled=compile_cqql('text CONTAINS '+json.dumps(text,ensure_ascii=False))
    # Independent reference uses legacy tokenizer MATCH and Python time/order,
    # not the optimized compiler or candidate SQL path.
    tokens=__import__('re').findall(r'[\w.@:/\\-]+',text.casefold())
    match=' AND '.join('"'+token+'"' for token in tokens)
    with closing(sqlite3.connect(path)) as c:
        matches={r[0] for r in c.execute('SELECT event_id FROM security_events_fts WHERE security_events_fts MATCH ?',(match,))}
        all_rows=list(c.execute('SELECT event_id,occurred_at FROM security_events'))
    start,end=base-timedelta(seconds=22),base+timedelta(seconds=1)
    expected=[r[0] for r in sorted((r for r in all_rows if r[0] in matches and start.isoformat()<=r[1]<=end.isoformat()),key=lambda r:(r[1],r[0]),reverse=sort=='newest')]
    repo=CQQLSearchRepository(path,fts_strategy='m32_rowid');actual=[];cursor=None
    while True:
        result=repo.search(compiled,start_time=start,end_time=end,sort=sort,limit=7,cursor=cursor)
        actual.extend(item.event_id for item in result.items);cursor=result.next_cursor
        if not cursor:break
    assert actual==expected and len(actual)==len(set(actual))


@pytest.mark.parametrize('query',[
    'text CONTAINS "alpha" AND event.severity >= 7',
    'text CONTAINS "alpha" OR event.code = "4624"',
    'NOT text CONTAINS "beta"','(text CONTAINS "alpha" OR text CONTAINS "cafe") AND NOT host.name = "absent"',
    'text CONTAINS "alpha" AND source.ip != "192.0.2.7"'])
def test_fts_nested_full_predicate_equivalence(fts,query):
    path,base,_,_=fts;args=dict(start_time=base-timedelta(days=8),end_time=base+timedelta(hours=1),sort='oldest',limit=100,cursor=None)
    old=CQQLSearchRepository(path).search(compile_cqql(query),**args)
    new=CQQLSearchRepository(path,fts_strategy='m32_rowid').search(compile_cqql(query),**args)
    assert [item.event_id for item in old.items]==[item.event_id for item in new.items]


def test_index_migration_backup_repeated_install_and_rollback(fts):
    path,base,backup,manifest=fts
    assert file_sha(backup)==manifest['backup_sha256']
    with closing(sqlite3.connect(path)) as c:before=content_digest(c);verify(c,integrity=True)
    assert install(path,backup,disposable_only=True)['version']=='m32-fts-rowid-v1'
    with pytest.raises(ValueError,match='DISPOSABLE'):rollback(path)
    rollback(path,disposable_only=True)
    with closing(sqlite3.connect(path)) as c:
        assert before==content_digest(c) and c.execute('PRAGMA user_version').fetchone()[0]==17
        assert not c.execute("SELECT 1 FROM sqlite_master WHERE name='m32_events_fts'").fetchone()
    with pytest.raises(CQQLExecutionError):CQQLSearchRepository(path,fts_strategy='m32_rowid').search(compile_cqql('text CONTAINS "alpha"'),start_time=base-timedelta(days=1),end_time=base+timedelta(days=1),sort='newest',limit=10,cursor=None)


def test_index_install_interruption_rolls_back_all_ddl(tmp_path):
    path=tmp_path/'source.db';AlertRepository(f'sqlite:///{path.as_posix()}',migration_target_version=17).initialize()
    def fail(stage):raise RuntimeError('SYNTHETIC interruption')
    with pytest.raises(RuntimeError):install(path,tmp_path/'backup.db',disposable_only=True,fault_hook=fail)
    with closing(sqlite3.connect(path)) as c:assert not c.execute("SELECT 1 FROM sqlite_master WHERE name LIKE 'm32_%'").fetchone()
    install(path,tmp_path/'retry-backup.db',disposable_only=True)


def test_index_triggers_update_delete_rollback_and_integrity(fts):
    path,_,_,_=fts
    with closing(sqlite3.connect(path)) as c:
        c.execute('BEGIN');c.execute("UPDATE security_events SET search_text='rollbackword'");c.rollback()
        assert c.execute("SELECT COUNT(*) FROM m32_events_fts WHERE m32_events_fts MATCH 'rollbackword'").fetchone()[0]==0
        event=c.execute('SELECT event_id FROM security_events LIMIT 1').fetchone()[0]
        c.execute('UPDATE security_events SET search_text=? WHERE event_id=?',('changedword',event));c.commit()
        assert c.execute("SELECT COUNT(*) FROM m32_events_fts WHERE m32_events_fts MATCH 'changedword'").fetchone()[0]==1
        c.execute('DELETE FROM security_events WHERE event_id=?',(event,));c.commit();verify(c,integrity=True)
        assert c.execute("SELECT COUNT(*) FROM m32_events_fts WHERE m32_events_fts MATCH 'changedword'").fetchone()[0]==0
        c.execute("INSERT INTO m32_events_fts(m32_events_fts,rank) VALUES('merge',2)");verify(c,integrity=True)


def test_fts_cancel_and_query_bound_cursor(fts):
    path,base,_,_=fts;repo=CQQLSearchRepository(path,fts_strategy='m32_rowid');cancel=threading.Event();cancel.set()
    args=dict(start_time=base-timedelta(days=8),end_time=base+timedelta(days=1),sort='newest',limit=1,cursor=None)
    with pytest.raises(CQQLQueryCancelledError):repo.search(compile_cqql('text CONTAINS "alpha"'),cancel_event=cancel,**args)
    page=repo.search(compile_cqql('text CONTAINS "alpha"'),**args);args['cursor']=page.next_cursor
    with pytest.raises(InvalidCQQLCursorError):repo.search(compile_cqql('text CONTAINS "beta"'),**args)
    acquired=[repo._slots.acquire(blocking=False) for _ in range(4)];assert all(acquired)
    for _ in acquired:repo._slots.release()


@pytest.mark.parametrize('change,expected',[('none','AVAILABLE'),('delete','MISSING'),('normalized','CHANGED'),('raw','CHANGED')])
def test_reconciliation_readonly_and_retention_gaps(client,prepared,change,expected):
    ids=ingest(client);evaluate(client);store=prepared[1]
    with closing(sqlite3.connect(store.source)) as c:
        if change=='delete':c.execute('DELETE FROM security_events WHERE event_id=?',(ids[0],))
        if change=='normalized':c.execute('UPDATE security_events SET hostname=? WHERE event_id=?',('SYNTHETIC-CHANGED',ids[0]))
        if change=='raw':c.execute('UPDATE security_events SET raw_event_json=? WHERE event_id=?',('{}',ids[0]))
        c.commit()
    with closing(sqlite3.connect(store.path)) as c:before=c.execute('SELECT COUNT(*) FROM security_audit_events').fetchone()[0]
    response=client.get(PREFIX+'/reconciliation');assert response.status_code==200,response.text
    report=response.json();assert report['counts'][expected]>=1 and report['history_modified'] is False and report['cross_database_atomic'] is False
    with closing(sqlite3.connect(store.path)) as c:assert c.execute('SELECT COUNT(*) FROM security_audit_events').fetchone()[0]==before


def test_reconciliation_detects_corrupted_reference_hash(client,prepared):
    ingest(client);evaluate(client)
    with closing(sqlite3.connect(prepared[1].path)) as c:c.execute('UPDATE shadow_evidence SET row_sha=?',('f'*64,));c.commit()
    response=client.get(PREFIX+'/reconciliation');assert response.status_code==503 and response.json()['detail']['code']=='SHADOW_STORE_CORRUPT'


def test_reconciliation_empty_source_without_findings_not_invented(client):
    ingest(client);report=client.get(PREFIX+'/reconciliation').json()
    assert report['revisions']==[] and report['counts']=={}
    assert client.get(PREFIX+'/reconciliation?limit=51').status_code==422
    assert client.get(PREFIX+'/reconciliation?cursor=invalid').status_code==422


@pytest.mark.parametrize('order',['quiescent','source_first','sidecar_first'])
def test_backup_restore_pair_preserves_binding_and_history(client,prepared,tmp_path,order):
    ingest(client);evaluate(client);service=client.app.state.shadow_history_service
    result=capture_pair(service,tmp_path/'pair',disposable_only=True,order=order)
    assert result['manifest']['writer_guards']==(order=='quiescent')
    assert validate_backup(tmp_path/'pair',result['manifest_sha256'])['pair']['consistency']=='REFERENCE_VALID'
    restored=restore_offline(tmp_path/'pair',tmp_path/'restored',result['manifest_sha256'],disposable_only=True)
    assert restored['status']=='OFFLINE_RESTORE_VALIDATED' and restored['runtime_activation']=='BLOCKED_BINDING_APPROVAL_REQUIRED'
    assert restored['pair']['history_digest']==result['manifest']['pair']['history_digest']
    with pytest.raises(ShadowStoreError):ShadowHistoryRepository(tmp_path/'restored/sidecar.db',tmp_path/'restored/source.db')


@pytest.mark.parametrize('target',['source.db','sidecar.db','manifest.json'])
def test_backup_substitution_rejected(client,tmp_path,target):
    ingest(client);evaluate(client);result=capture_pair(client.app.state.shadow_history_service,tmp_path/'pair',disposable_only=True)
    with (tmp_path/'pair'/target).open('ab') as out:out.write(b'SYNTHETIC-corruption')
    with pytest.raises(ValueError,match='CHECKSUM'):validate_backup(tmp_path/'pair',result['manifest_sha256'])


@pytest.mark.parametrize('phase',['AFTER_SOURCE_BACKUP','AFTER_SIDECAR_BACKUP','BEFORE_PUBLICATION'])
def test_interrupted_backup_never_publishes_success(client,tmp_path,phase):
    ingest(client);evaluate(client)
    def fail(stage):
        if stage==phase:raise RuntimeError('SYNTHETIC interruption')
    with pytest.raises(RuntimeError):capture_pair(client.app.state.shadow_history_service,tmp_path/'pair',disposable_only=True,fault_hook=fail)
    assert not (tmp_path/'pair').exists()
    assert client.app.state.shadow_history_service.scheduler.snapshot()['inflight']==0


@pytest.mark.parametrize('phase',['AFTER_SOURCE_RESTORE','AFTER_SIDECAR_RESTORE','BEFORE_PUBLICATION'])
def test_interrupted_restore_never_publishes_or_overwrites(client,tmp_path,phase):
    ingest(client);evaluate(client);result=capture_pair(client.app.state.shadow_history_service,tmp_path/'pair',disposable_only=True)
    def fail(stage):
        if stage==phase:raise RuntimeError('SYNTHETIC interruption')
    with pytest.raises(RuntimeError):restore_offline(tmp_path/'pair',tmp_path/'restored',result['manifest_sha256'],disposable_only=True,fault_hook=fail)
    assert not (tmp_path/'restored').exists();validate_backup(tmp_path/'pair',result['manifest_sha256'])


def test_noncoordinated_capture_exposes_retention_race(client,prepared,tmp_path):
    ids=ingest(client);evaluate(client)
    def remove(stage):
        if stage=='AFTER_SIDECAR_BACKUP':
            with closing(sqlite3.connect(prepared[1].source)) as c:c.execute('DELETE FROM security_events WHERE event_id=?',(ids[0],));c.commit()
    result=capture_pair(client.app.state.shadow_history_service,tmp_path/'pair',disposable_only=True,order='sidecar_first',fault_hook=remove)
    assert result['manifest']['pair']['consistency']=='EVIDENCE_GAPS_RETAINED'
    assert result['manifest']['pair']['availability']['MISSING']==1


def test_backup_wrong_receipt_manifest_paths_and_existing_target(client,tmp_path):
    ingest(client);evaluate(client);result=capture_pair(client.app.state.shadow_history_service,tmp_path/'pair',disposable_only=True)
    with pytest.raises(ValueError):validate_backup(tmp_path/'pair','f'*64)
    with pytest.raises(ValueError):restore_offline(tmp_path/'pair',tmp_path/'pair',result['manifest_sha256'],disposable_only=True)
    file=tmp_path/'pair/manifest.json';data=json.loads(file.read_text());data['source_path']='../../outside.db';file.write_text(json.dumps(data))
    with pytest.raises(ValueError,match='INVALID_BACKUP_MANIFEST'):validate_backup(tmp_path/'pair',file_sha(file))


def test_reconciliation_keyset_pages_and_authentication(client):
    ingest(client);ingest(client,auth(BASE,offset=32000,ip='192.0.2.32'));evaluate(client)
    first=client.get(PREFIX+'/reconciliation?limit=1').json();assert len(first['revisions'])==1 and first['next_cursor']
    second=client.get(PREFIX+'/reconciliation',params={'limit':1,'cursor':first['next_cursor']}).json()
    assert len(second['revisions'])==1 and second['next_cursor'] is None
    assert first['revisions'][0]['finding_id']!=second['revisions'][0]['finding_id']
    client.cookies.clear();assert client.get(PREFIX+'/reconciliation').status_code==401


def test_partial_restore_and_rollback_receipt_are_explicit(client,prepared,tmp_path):
    ingest(client);evaluate(client);service=client.app.state.shadow_history_service
    old=capture_pair(service,tmp_path/'old',disposable_only=True)
    ingest(client,auth(BASE,offset=33000,ip='192.0.2.33'));evaluate(client)
    new=capture_pair(service,tmp_path/'new',disposable_only=True)
    source_only=inspect_pair(tmp_path/'old/source.db',tmp_path/'new/sidecar.db',expected_binding=service.store.binding)
    assert source_only['availability']['MISSING']==4 and source_only['consistency']=='EVIDENCE_GAPS_RETAINED'
    sidecar_only=inspect_pair(tmp_path/'new/source.db',tmp_path/'old/sidecar.db',expected_binding=service.store.binding)
    assert sidecar_only['sidecar_runs']<new['manifest']['pair']['sidecar_runs']
    with pytest.raises(ValueError,match='MANIFEST_CHECKSUM'):validate_backup(tmp_path/'old',new['manifest_sha256'])
    # Old receipt remains useful for OFFLINE forensics, never active rollback.
    assert restore_offline(tmp_path/'old',tmp_path/'old-view',old['manifest_sha256'],disposable_only=True)['runtime_activation']=='BLOCKED_BINDING_APPROVAL_REQUIRED'


def test_global_backup_audit_detects_missing_completed_links(client,prepared,tmp_path):
    ingest(client);evaluate(client)
    with closing(sqlite3.connect(prepared[1].path)) as c:c.execute('DELETE FROM shadow_run_findings');c.commit()
    with pytest.raises((ValueError,ShadowStoreError)):
        capture_pair(client.app.state.shadow_history_service,tmp_path/'invalid',disposable_only=True)
    assert not (tmp_path/'invalid').exists()


@pytest.mark.parametrize('alias',['rowid','_rowid_','oid'])
def test_rowid_change_is_blocked_and_index_keeps_integrity(fts,alias):
    path,_,_,_=fts
    with closing(sqlite3.connect(path)) as c:
        with pytest.raises(sqlite3.IntegrityError,match='rowid change'):c.execute('UPDATE security_events SET '+alias+'='+alias+'+10000')
        c.rollback();verify(c,integrity=True)


def test_metadata_cancellation_remains_cancel_not_corrupt_index(fts):
    path,_,_,_=fts;repo=CQQLSearchRepository(path,fts_strategy='m32_rowid');cancel=threading.Event();cancel.set()
    with closing(sqlite3.connect(path)) as c:
        c.set_progress_handler(lambda:1,1)
        with pytest.raises(sqlite3.OperationalError) as caught:repo._predicate(c,compile_cqql('text CONTAINS "alpha"'))
        assert isinstance(repo._translate_sqlite(caught.value,cancel),CQQLQueryCancelledError)


def test_m29_locator_coexists_and_survives_m32_rollback(fts):
    from app.db.fts_locator_proposal import install as install_locator,verify_fts_content
    path,_,_,_=fts
    with closing(sqlite3.connect(path)) as c:install_locator(c,disposable_only=True);verify(c,integrity=True)
    rollback(path,disposable_only=True)
    with closing(sqlite3.connect(path)) as c:verify_fts_content(c,locator=True)


def test_experimental_fts_analytics_export_and_cursor_interchange(fts):
    path,base,_,_=fts;compiled=compile_cqql('text CONTAINS "alpha"');old=CQQLSearchRepository(path);new=CQQLSearchRepository(path,fts_strategy='m32_rowid')
    interval=dict(start_time=base-timedelta(days=8),end_time=base+timedelta(days=1))
    for repository in (old,new):
        output=repository.export(compiled,**interval,sort='newest',limit=100)
        if repository is old:expected=[v.event_id for v in output.items]
        else:assert [v.event_id for v in output.items]==expected
    before=old.analytics(compiled,**interval,group_by=['event.provider'],top_n=10,interval='day')
    after=new.analytics(compiled,**interval,group_by=['event.provider'],top_n=10,interval='day')
    assert before.matching_events==after.matching_events and before.groups==after.groups and before.time_series==after.time_series
    page=old.search(compiled,**interval,sort='newest',limit=7,cursor=None)
    continuation=new.search(compiled,**interval,sort='newest',limit=100,cursor=page.next_cursor)
    assert [v.event_id for v in continuation.items]==expected[7:]


def test_legacy_audit_interrupt_is_explicit_budget_rejection(client,monkeypatch):
    ingest(client)
    def interrupted(**kwargs):
        error=sqlite3.OperationalError('SYNTHETIC-private-audit-context')
        error.sqlite_errorcode=sqlite3.SQLITE_INTERRUPT
        raise error
    monkeypatch.setattr(client.app.state.shadow_audit_repository,'append',interrupted)
    response=client.post(PREFIX+'/simulate',json=payload()['simulation'])
    assert response.status_code==503 and response.json()['detail']['reason_code']=='AUDIT_BUDGET_EXPIRED'
    assert response.headers['retry-after']=='1' and 'private-audit-context' not in response.text
