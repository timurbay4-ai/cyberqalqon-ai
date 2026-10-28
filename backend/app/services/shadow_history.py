"""Request-owned durable finite evaluation. Recovery never reads forward cursors."""
from __future__ import annotations
import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from app.db.shadow_history import ShadowHistoryRepository,ShadowStoreError,sha
from app.db.cqql import CQQLQueryCancelledError,CQQLQueryBusyError,CQQLQueryTimeoutError
from app.schemas.shadow_history import DurableEvaluationRequest,FindingTransition
from app.services.identity_resolution import IdentityResolver
from app.services.shadow_detection import read_snapshot,finish_snapshot,snapshot_columns,check_budget,ShadowResourceLimitError
from app.services.shadow_scheduling import ShadowScheduler,ShadowAdmissionError
from app.services.wazuh_normalizer import canonical_json


class ShadowHistoryService:
    def __init__(self,store:ShadowHistoryRepository,query_repository,*,resolver=None,fault_hook=None):
        self.store=store;self.query_repository=query_repository
        self.resolver=resolver or IdentityResolver();self.scheduler=ShadowScheduler()
        self._fault=fault_hook or (lambda stage:None)
        self._owner_file=None;self._cancel_events=set();self._lock=threading.Lock()
        self._readers=threading.BoundedSemaphore(4)
        self._active_runs=set()

    def open(self):
        stream=self.store.path.with_suffix(self.store.path.suffix+'.owner.lock').open('a+b')
        try:
            if stream.seek(0,2)==0:stream.write(b'0');stream.flush();os.fsync(stream.fileno())
            stream.seek(0)
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:
            stream.close();raise ShadowStoreError('SHADOW_OWNER_LOCKED') from None
        self._owner_file=stream

    def close(self):
        self.scheduler.close()
        with self._lock:
            for event in self._cancel_events:event.set()
        deadline=time.perf_counter()+5
        while self.scheduler.snapshot()['inflight'] and time.perf_counter()<deadline:time.sleep(.01)
        if self.scheduler.snapshot()['inflight']:raise ShadowStoreError('SHADOW_SHUTDOWN_INCOMPLETE')
        if self._owner_file is not None:self._owner_file.close();self._owner_file=None

    def summary(self,run_id,*,cancel_event=None):
        with self.reader(cancel_event):return self._summary(run_id)

    def _summary(self,run_id):
        value=self.store.run(run_id)
        result=json.loads(value['result_json']) if value['result_json'] else None
        intent=value['recovery_intent']
        return {'run_id':run_id,'status':value['status'],'attempts':value['attempts'],
            'recovery_state':('NOT_REQUIRED' if value['status']=='COMPLETED' else 'IN_PROGRESS' if run_id in self._active_runs
                else 'ATTEMPTS_EXHAUSTED' if value['attempts']>=3 else 'EXPLICIT_RESUME_REQUIRED' if value['snapshot_json']
                else 'UNSEALED_VERIFICATION_REQUIRED' if intent else 'UNSEALED_BLOCKED'),
            'recovery_intent':None if intent is None else {**{key:intent[key] for key in ('version','manifest_sha256','candidate_rows','candidate_truncated')},
                'scope':'BOUNDED_CANDIDATES_NOT_GLOBAL_COMPLETENESS','verification':'SEALED' if value['snapshot_json'] else 'RECHECK_REQUIRED'},
            'error_code':value['error_code'],'checkpoint':'SEALED' if value['snapshot_json'] else 'UNSEALED',
            'snapshot_sha256':value['snapshot_sha'],'result':result,'production_active':False,
            'scope':'DISPOSABLE_DURABLE_SHADOW','historical_continuity':'UNPROVEN'}

    def evaluate(self,request:DurableEvaluationRequest,actor,*,cancel_event=None,resume_run=None):
        if self._owner_file is None:raise ShadowStoreError('SHADOW_OWNER_NOT_ACQUIRED')
        cancel_event=cancel_event or threading.Event()
        with self._lock:self._cancel_events.add(cancel_event)
        run_id=None
        try:
            with self.scheduler.admit(cancel_event):
                if resume_run is None:
                    if request.simulation.rule.status!='SHADOW_ONLY':raise ShadowStoreError('RULE_DISABLED')
                    previous=self.store.find_request(request,self.resolver.authority_sha256)
                    if previous is not None:
                        run_id=previous['run_id']
                        if previous['status']=='COMPLETED':return self.summary(run_id)
                        raise ShadowStoreError('RUN_REQUIRES_EXPLICIT_RESUME')
                    self._fault('BEFORE_SNAPSHOT_CAPTURE')
                    snapshot=read_snapshot(request.simulation,self.query_repository,cancel_event=cancel_event,include_raw=True)
                    self._fault('AFTER_SNAPSHOT_CAPTURE')
                    row,created=self.store.begin(request,actor,self.resolver.authority_sha256,self.resolver.authority_document(),manifest=snapshot.manifest);run_id=row['run_id']
                    if not created:
                        if row['status']=='COMPLETED':return self.summary(run_id)
                        raise ShadowStoreError('RUN_REQUIRES_EXPLICIT_RESUME')
                    with self._lock:self._active_runs.add(run_id)
                    self._fault('AFTER_RUN_BEGIN')
                    self._fault('BEFORE_SNAPSHOT_SEAL')
                    self.store.seal(run_id,snapshot.manifest,actor)
                else:
                    run_id=resume_run;row=self.store.run(run_id);request=row['request']
                    if row['authority_sha']!=self.resolver.authority_sha256:raise ShadowStoreError('AUTHORITY_VERSION_CHANGED')
                    if row['status']=='COMPLETED':return self.summary(run_id)
                    if row['attempts']>=3:raise ShadowStoreError('RUN_ATTEMPTS_EXHAUSTED')
                    with self._lock:self._active_runs.add(run_id)
                    if row['snapshot_json'] is None:
                        if row['recovery_intent'] is None:raise ShadowStoreError('UNSEALED_RECOVERY_BLOCKED')
                        self._fault('BEFORE_UNSEALED_RECONCILE')
                        snapshot=read_snapshot(request.simulation,self.query_repository,cancel_event=cancel_event,include_raw=True)
                        self._fault('AFTER_UNSEALED_READ')
                        if self.store.binding!=row['recovery_intent']['source_binding'] or sha(snapshot.manifest)!=row['recovery_intent']['manifest_sha256']:
                            raise ShadowStoreError('UNSEALED_SOURCE_SET_CHANGED')
                        self._fault('BEFORE_UNSEALED_CLAIM')
                        if not self.store.claim(run_id,actor,manifest=snapshot.manifest,expected_attempts=row['attempts']):return self.summary(run_id)
                        self._fault('AFTER_UNSEALED_CLAIM')
                    else:
                        if not self.store.claim(run_id,actor,expected_attempts=row['attempts']):return self.summary(run_id)
                        snapshot=read_snapshot(request.simulation,self.query_repository,cancel_event=cancel_event,
                            include_raw=True,sealed=json.loads(row['snapshot_json']))
                self._fault('AFTER_SNAPSHOT_COMMIT')
                result=finish_snapshot(request.simulation,snapshot,cancel_event=cancel_event)
                records={record['id']:record for record in snapshot.records}
                assessments=[self.resolver.assess([records[item.event_id] for item in finding.evidence],
                    request.simulation.rule,request.identity_policy) for finding in result.findings]
                if cancel_event.is_set():raise CQQLQueryCancelledError('Shadow evaluation cancelled before commit')
                self._fault('BEFORE_FINDING_COMMIT')
                self.store.complete(run_id,request,result,assessments,actor)
                self._fault('AFTER_FINDING_COMMIT')
                return self.summary(run_id)
        except Exception as exc:
            if run_id:
                code=str(exc) if isinstance(exc,(ShadowStoreError,ShadowResourceLimitError)) else type(exc).__name__
                try:self.store.fail(run_id,code,cancelled=isinstance(exc,CQQLQueryCancelledError))
                except ShadowStoreError:pass  # The last committed RUNNING snapshot remains recoverable.
            if not isinstance(exc,(ShadowStoreError,ShadowAdmissionError,ShadowResourceLimitError,CQQLQueryBusyError,CQQLQueryTimeoutError,CQQLQueryCancelledError)):
                raise ShadowStoreError('SHADOW_WORKER_EXCEPTION',run_id=run_id) from None
            if run_id:exc.run_id=run_id
            raise
        finally:
            with self._lock:self._cancel_events.discard(cancel_event);self._active_runs.discard(run_id)

    def resume(self,run_id,actor,*,cancel_event=None):
        return self.evaluate(self.store.run(run_id)['request'],actor,cancel_event=cancel_event,resume_run=run_id)

    @contextmanager
    def reader(self,cancel_event):
        if not self._readers.acquire(blocking=False):raise ShadowAdmissionError('SHADOW_HISTORY_BUSY')
        try:
            if cancel_event is not None and cancel_event.is_set():raise CQQLQueryCancelledError('History read cancelled')
            yield
        finally:self._readers.release()

    def page(self,limit,cursor,*,cancel_event=None):
        with self.reader(cancel_event):return self.store.page(limit=limit,cursor=cursor)

    def reconcile(self,limit=20,cursor=None,*,cancel_event=None):
        from app.services.evidence_consistency import reconcile
        with self.reader(cancel_event):
            return reconcile(self.store,self.query_repository,limit=limit,cursor=cursor,cancel_event=cancel_event)

    def status(self,*,cancel_event=None):
        with self.reader(cancel_event):
            return {'enabled':True,'scope':'DISPOSABLE_DURABLE_SHADOW','production_active':False,'schema_version':1,
                'resource_state':self.scheduler.snapshot(),'recovery_runs':self.store.recovery_headers()}

    def detail(self,finding_id,revision=None,*,cancel_event=None):
        with self.reader(cancel_event):return self._detail(finding_id,revision,cancel_event=cancel_event)

    def _detail(self,finding_id,revision=None,*,cancel_event=None):
        result=self.store.detail(finding_id,revision);references=result['evidence_references']
        from app.services.evidence_consistency import revision_references
        from contextlib import closing
        with closing(self.store._connect()) as sidecar:
            self.query_repository._install_deadline(sidecar,time.perf_counter()+1.5,cancel_event)
            try:
                if revision_references(sidecar,finding_id,result['revision'])!=references:
                    raise ShadowStoreError('SHADOW_STORE_CORRUPT')
            except sqlite3.OperationalError as exc:
                raise self.query_repository._translate_sqlite(exc,cancel_event) from None
            finally:sidecar.set_progress_handler(None,0)
        expected={item['event_id']:item for item in references};availability={key:'MISSING' for key in expected}
        connection=None;acquired=False
        try:
            self.query_repository._acquire_slot(cancel_event);acquired=True
            connection=self.query_repository._connect();deadline=time.perf_counter()+1.5
            self.query_repository._install_deadline(connection,deadline,cancel_event)
            rows=connection.execute(f'SELECT {snapshot_columns()} FROM security_events WHERE event_id IN ('+
                ','.join('?' for _ in expected)+')',tuple(expected)) if expected else ()
            for row in rows:
                check_budget(deadline,cancel_event)
                availability[row['event_id']]='AVAILABLE' if sha(dict(row))==expected[row['event_id']]['row_sha'] else 'CHANGED'
        except (CQQLQueryBusyError,CQQLQueryTimeoutError):availability={key:'UNKNOWN' for key in expected}
        except sqlite3.OperationalError as exc:
            error=self.query_repository._translate_sqlite(exc,cancel_event)
            if isinstance(error,(CQQLQueryBusyError,CQQLQueryTimeoutError)):availability={key:'UNKNOWN' for key in expected}
            else:raise error from None
        finally:
            if connection is not None:connection.set_progress_handler(None,0);connection.close()
            if acquired:self.query_repository._slots.release()
        return {**result,'current_evidence_availability':availability,
            'identity_context':'AT_ORIGINAL_EVALUATION_NOT_CURRENT_SOURCE_ATTESTATION'}

    def transition(self,finding_id,change:FindingTransition,actor,*,cancel_event=None):
        with self.scheduler.admit(cancel_event):
            detail=self.detail(finding_id,cancel_event=cancel_event)
            available=all(value=='AVAILABLE' for value in detail['current_evidence_availability'].values())
            self.store.transition(finding_id,change,actor,evidence_available=available)
            return self.detail(finding_id,cancel_event=cancel_event)
