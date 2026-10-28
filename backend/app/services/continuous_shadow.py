"""Owned, checkpointed isolated evaluation loop over the existing durable evaluator.

No app startup task, delivery checkpoint, archive reader or production activation.
Finding and checkpoint commits are separate. A persisted pending request makes the
completed-history/checkpoint crash window retryable without moving a cursor back.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.db.shadow_history import ShadowStoreError, sha, source_binding
from app.db.cqql import CQQLQueryCancelledError
from app.schemas.shadow_history import DurableEvaluationRequest
from app.services.shadow_detection import _bounded_rows, snapshot_columns
from app.services.wazuh_normalizer import canonical_json

NAMESPACE = 'cq-m34-continuous-shadow-v1'
MAX_TICKS = 2048
MAX_STATE_BYTES = 768 * 1024


class ContinuousShadowError(RuntimeError):
    pass


def _connect(path):
    connection = sqlite3.connect(path, timeout=.1, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA synchronous=FULL')
    return connection


def prepare(path: Path, service, rule, *, first_end: datetime, stride_seconds=30, disposable_only=False):
    path = Path(path)
    if disposable_only is not True or rule.status != 'SHADOW_ONLY':
        raise ContinuousShadowError('EXPLICIT_DISPOSABLE_SHADOW_REQUIRED')
    if (path.exists() or path.is_symlink() or path.parent.resolve() != service.store.path.parent
            or type(stride_seconds) is not int or not 1 <= stride_seconds <= 300):
        raise ContinuousShadowError('NEW_ISOLATED_CHECKPOINT_REQUIRED')
    if first_end.tzinfo is None or first_end.utcoffset() is None or first_end > datetime.now(timezone.utc):
        raise ContinuousShadowError('INVALID_FIRST_BOUNDARY')
    service.store.verify()
    definition = {
        'namespace': NAMESPACE, 'source_binding': service.store.binding, 'store_id': service.store.store_id,
        'rule': rule.model_dump(mode='json'), 'rule_version': rule.rule_version,
        'authority_sha256': service.resolver.authority_sha256,
        'first_end': first_end.astimezone(timezone.utc).isoformat(), 'stride_seconds': stride_seconds,
    }
    state = {'sequence': 0, 'last_end': None, 'ledger': {}, 'late_observed': 0,
             'late_outside_overlap': 0, 'pending': None, 'last_run_id': None, 'last_finding_ids': []}
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.close(descriptor)
    with closing(_connect(path)) as connection:
        connection.execute('PRAGMA journal_mode=WAL')
        connection.execute('BEGIN IMMEDIATE')
        connection.execute('PRAGMA user_version=1')
        connection.execute('CREATE TABLE checkpoint(singleton INTEGER PRIMARY KEY CHECK(singleton=1),definition TEXT NOT NULL,definition_sha TEXT NOT NULL,data TEXT NOT NULL,state_sha TEXT NOT NULL)')
        connection.execute('INSERT INTO checkpoint VALUES(1,?,?,?,?)',
                           (canonical_json(definition), sha(definition), canonical_json(state), sha([definition, state])))
        connection.commit()
        connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    return {'namespace': NAMESPACE, 'production_active': False, 'source_schema': 17,
            'checkpoint_schema': 1, 'directory_fsync': False if os.name == 'nt' else 'NOT_CLAIMED'}


class ContinuousShadowWorker:
    def __init__(self, path: Path, service, rule, *, disposable_only=False, fault_hook=None):
        if disposable_only is not True or rule.status != 'SHADOW_ONLY':
            raise ContinuousShadowError('EXPLICIT_DISPOSABLE_SHADOW_REQUIRED')
        if Path(path).is_symlink():
            raise ContinuousShadowError('INVALID_CHECKPOINT_PATH')
        self.path = Path(path).resolve(strict=True)
        if self.path.parent != service.store.path.parent:
            raise ContinuousShadowError('INVALID_CHECKPOINT_PATH')
        self.service, self.rule = service, rule
        self._identity = (self.path.stat().st_dev, self.path.stat().st_ino)
        self._lock = threading.Lock()
        self._owner = None
        self._error = None
        self._fault = fault_hook or (lambda stage: None)

    def open(self):
        if self._owner is not None:
            raise ContinuousShadowError('WORKER_ALREADY_OPEN')
        owner = self.path.with_suffix(self.path.suffix + '.owner.lock')
        if owner.is_symlink():
            raise ContinuousShadowError('INVALID_OWNER_PATH')
        descriptor = os.open(owner, os.O_CREAT | os.O_RDWR, 0o600)
        stream = os.fdopen(descriptor, 'r+b')
        try:
            if stream.seek(0, 2) == 0:
                stream.write(b'0');stream.flush();os.fsync(stream.fileno())
            stream.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._load()
        except BaseException:
            stream.close()
            raise
        self._owner = stream
        return self

    def close(self):
        if not self._lock.acquire(blocking=False):
            raise ContinuousShadowError('WORKER_SHUTDOWN_PENDING')
        try:
            if self._owner is not None:
                self._owner.close();self._owner = None
        finally:
            self._lock.release()

    def __enter__(self):
        return self.open()

    def __exit__(self, *_):
        self.close()

    def _load(self):
        try:
            return self._load_checked()
        except (sqlite3.Error, ValueError, KeyError, TypeError, OSError, RecursionError):
            raise ContinuousShadowError('CHECKPOINT_UNAVAILABLE') from None

    def _load_checked(self):
        if self.path.is_symlink() or (self.path.stat().st_dev, self.path.stat().st_ino) != self._identity:
            raise ContinuousShadowError('CHECKPOINT_REPLACED')
        if self.path.stat().st_size > 8 * 1024 * 1024:
            raise ContinuousShadowError('CHECKPOINT_CAPACITY_EXCEEDED')
        wal = self.path.with_name(self.path.name + '-wal')
        if wal.exists() and wal.stat().st_size > 8 * 1024 * 1024:
            raise ContinuousShadowError('CHECKPOINT_CAPACITY_EXCEEDED')
        with closing(_connect(self.path)) as connection:
            if connection.execute('PRAGMA user_version').fetchone()[0] != 1:
                raise ContinuousShadowError('CHECKPOINT_SCHEMA_MISMATCH')
            if connection.execute('PRAGMA journal_mode').fetchone()[0] != 'wal' or connection.execute('PRAGMA synchronous').fetchone()[0] != 2:
                raise ContinuousShadowError('CHECKPOINT_DURABILITY_POLICY_MISMATCH')
            row = connection.execute('SELECT * FROM checkpoint WHERE singleton=1').fetchone()
        if row is None or len(row['data']) > MAX_STATE_BYTES:
            raise ContinuousShadowError('CHECKPOINT_INVALID')
        definition, state = json.loads(row['definition']), json.loads(row['data'])
        for key in ('sequence','late_observed','late_outside_overlap','transitions_seen'):
            value=state.get(key,0)
            if type(value) is not int or not 0<=value<=MAX_TICKS*1000:
                raise ContinuousShadowError('CHECKPOINT_INVALID_COUNTER')
        for ledger in (state['ledger'],state['pending']['observed'] if state['pending'] else {}):
            if not isinstance(ledger,dict) or len(ledger)>1000:
                raise ContinuousShadowError('CHECKPOINT_INVALID_LEDGER')
            for key,value in ledger.items():
                if (not isinstance(key,str) or len(key)>128 or not isinstance(value,list) or len(value)!=2
                        or not isinstance(value[0],str) or re.fullmatch(r'[a-f0-9]{64}',value[0]) is None
                        or not isinstance(value[1],str) or len(value[1])>40):
                    raise ContinuousShadowError('CHECKPOINT_INVALID_LEDGER')
                if datetime.fromisoformat(value[1]).utcoffset() is None:
                    raise ContinuousShadowError('CHECKPOINT_INVALID_LEDGER')
        tail=state.get('transition_tail',[])
        if not isinstance(tail,list) or len(tail)>32:
            raise ContinuousShadowError('CHECKPOINT_INVALID_TRANSITIONS')
        for entry in tail:
            if (not isinstance(entry,dict) or set(entry)!={'tick','stage','run_id'}
                    or type(entry['tick']) is not int or not 1<=entry['tick']<=MAX_TICKS
                    or entry['stage'] not in {'PENDING_COMMITTED','CHECKPOINT_COMMITTED'}
                    or (entry['stage']=='PENDING_COMMITTED')!=(entry['run_id'] is None)
                    or entry['run_id'] is not None and (not isinstance(entry['run_id'],str) or re.fullmatch(r'RUN-[a-f0-9]{32}',entry['run_id']) is None)):
                raise ContinuousShadowError('CHECKPOINT_INVALID_TRANSITIONS')
        if (sha(definition) != row['definition_sha'] or sha([definition, state]) != row['state_sha']
                or definition['namespace'] != NAMESPACE or definition['rule_version'] != self.rule.rule_version
                or definition['rule'] != self.rule.model_dump(mode='json')
                or definition['source_binding'] != source_binding(self.service.store.source)
                or definition['store_id'] != self.service.store.store_id
                or definition['authority_sha256'] != self.service.resolver.authority_sha256
                or not 0 <= state['sequence'] <= MAX_TICKS or len(state['ledger']) > 1000):
            raise ContinuousShadowError('CHECKPOINT_BINDING_MISMATCH')
        boundary=datetime.fromisoformat(definition['first_end'])+timedelta(seconds=state['sequence']*definition['stride_seconds'])
        previous=boundary-timedelta(seconds=definition['stride_seconds']) if state['sequence'] else None
        if (None if previous is None else previous.isoformat())!=state['last_end']:
            raise ContinuousShadowError('CHECKPOINT_BOUNDARY_MISMATCH')
        if state['pending'] is not None:
            pending=state['pending']
            if set(pending)!={'request','observed','end','late','outside'}:
                raise ContinuousShadowError('CHECKPOINT_PENDING_MISMATCH')
            request=DurableEvaluationRequest.model_validate(pending['request'])
            start=boundary-timedelta(seconds=self.rule.window_seconds+self.rule.allowed_lateness)
            if (request.simulation.rule.model_dump(mode='json')!=definition['rule']
                    or request.identity_policy.minimum!='PARTIAL' or request.simulation.end_time!=boundary
                    or request.simulation.start_time!=start or pending['end']!=boundary.isoformat()
                    or any(type(pending[key]) is not int or not 0<=pending[key]<=1000 for key in ('late','outside'))):
                raise ContinuousShadowError('CHECKPOINT_PENDING_MISMATCH')
            self._continuity(state['ledger'],pending['observed'])
            stamps=[datetime.fromisoformat(value[1]) for key,value in pending['observed'].items() if key not in state['ledger']]
            if (pending['late']!=sum(previous is not None and stamp<=previous for stamp in stamps)
                    or pending['outside']!=sum(previous is not None and stamp<start for stamp in stamps)):
                raise ContinuousShadowError('CHECKPOINT_PENDING_MISMATCH')
        self.service.store.verify()
        return definition, state

    def _write(self, definition, state, *, expected_data, final=False):
        encoded = canonical_json(state)
        if len(encoded.encode()) > MAX_STATE_BYTES:
            raise ContinuousShadowError('CHECKPOINT_CAPACITY_EXCEEDED')
        with closing(_connect(self.path)) as connection:
            try:
                connection.execute('BEGIN IMMEDIATE')
                changed=connection.execute('UPDATE checkpoint SET data=?,state_sha=? WHERE singleton=1 AND data=? AND state_sha=? AND definition_sha=?',
                                   (encoded, sha([definition, state]),expected_data,
                                    sha([definition,json.loads(expected_data)]),sha(definition)))
                if changed.rowcount!=1:raise ContinuousShadowError('CHECKPOINT_COMPARE_AND_SWAP_FAILED')
                if final:
                    self._fault('BEFORE_CHECKPOINT_COMMIT')
                connection.commit()
                if final:self._fault('AFTER_CHECKPOINT_COMMIT')
            except sqlite3.OperationalError as exc:
                connection.rollback()
                if getattr(exc,'sqlite_errorcode',0)&255 in (sqlite3.SQLITE_BUSY,sqlite3.SQLITE_LOCKED):
                    raise ContinuousShadowError('CHECKPOINT_BUSY') from None
                raise ContinuousShadowError('CHECKPOINT_WRITE_FAILED') from None
            except BaseException:
                connection.rollback();raise

    @staticmethod
    def _transition(state,stage,*,run_id=None):
        tail=state.get('transition_tail',[])
        if not isinstance(tail,list) or len(tail)>32:
            raise ContinuousShadowError('CHECKPOINT_INVALID_TRANSITIONS')
        state['transition_tail']=(tail+[{'tick':state['sequence']+(stage=='PENDING_COMMITTED'),
                                      'stage':stage,'run_id':run_id}])[-32:]
        state['transitions_seen']=state.get('transitions_seen',0)+1

    def _capture(self, cutoff):
        deadline = time.perf_counter() + 1.5
        with closing(sqlite3.connect(self.service.store.source.as_uri() + '?mode=ro', uri=True, timeout=.1)) as source:
            source.row_factory = sqlite3.Row
            source.execute('PRAGMA query_only=ON')
            source.set_progress_handler(lambda: int(time.perf_counter() >= deadline), 1000)
            if source.execute('PRAGMA user_version').fetchone()[0] != 17:
                raise ContinuousShadowError('SOURCE_SCHEMA_MISMATCH')
            rows, truncated = _bounded_rows(source.execute(
                'SELECT * FROM security_events ORDER BY occurred_at,event_id LIMIT 1001'),
                deadline, None)
        if truncated:
            raise ContinuousShadowError('SOURCE_OBSERVATION_CAPACITY_EXCEEDED')
        return {row['event_id']: [sha(dict(row)), row['occurred_at']] for row in rows
                if datetime.fromisoformat(row['ingested_at']) <= cutoff}

    @staticmethod
    def _continuity(previous, current):
        if previous.keys() - current.keys():
            raise ContinuousShadowError('SOURCE_RETENTION_GAP')
        if any(current[key] != value for key, value in previous.items()):
            raise ContinuousShadowError('SOURCE_CONTENT_CHANGED')

    def tick(self, *, now=None, cancel_event=None):
        if self._owner is None:
            raise ContinuousShadowError('WORKER_OWNER_REQUIRED')
        if not self._lock.acquire(blocking=False):
            raise ContinuousShadowError('WORKER_BACKPRESSURE')
        try:
            if cancel_event is not None and cancel_event.is_set():
                raise ContinuousShadowError('WORKER_CANCELLED')
            now = now or datetime.now(timezone.utc)
            if now.tzinfo is None or now.utcoffset() is None:
                raise ContinuousShadowError('UTC_OFFSET_REQUIRED')
            definition, state = self._load()
            expected_data=canonical_json(state)
            if state['sequence'] >= MAX_TICKS:
                raise ContinuousShadowError('CHECKPOINT_CAPACITY_EXCEEDED')
            end = datetime.fromisoformat(definition['first_end']) + timedelta(seconds=state['sequence'] * definition['stride_seconds'])
            if state['pending'] is None:
                if now < end + timedelta(seconds=self.rule.allowed_lateness):
                    return self._status(state, 'NOT_DUE')
                observed = self._capture(now)
                self._continuity(state['ledger'], observed)
                start = end - timedelta(seconds=self.rule.window_seconds + self.rule.allowed_lateness)
                prior = datetime.fromisoformat(state['last_end']) if state['last_end'] else None
                new_times = [datetime.fromisoformat(value[1]) for key, value in observed.items() if key not in state['ledger']]
                state['pending'] = {
                    'request': DurableEvaluationRequest.model_validate({'simulation': {
                        'rule': definition['rule'], 'start_time': start, 'end_time': end, 'evaluation_time': now,
                    }}).model_dump(mode='json'),
                    'observed': observed, 'end': end.isoformat(),
                    'late': sum(prior is not None and stamp <= prior for stamp in new_times),
                    'outside': sum(prior is not None and stamp < start for stamp in new_times),
                }
                self._transition(state,'PENDING_COMMITTED')
                self._write(definition, state, expected_data=expected_data)
                expected_data=canonical_json(state)
                self._fault('AFTER_PENDING_COMMIT')
            pending = state['pending']
            request = DurableEvaluationRequest.model_validate(pending['request'])
            self._continuity(pending['observed'], self._capture(request.simulation.evaluation_time))
            try:
                result = self.service.evaluate(request, 'M34 isolated continuous shadow', cancel_event=cancel_event)
            except ShadowStoreError as exc:
                if str(exc) != 'RUN_REQUIRES_EXPLICIT_RESUME' or not exc.run_id:
                    raise
                # Existing M31 unsealed snapshots remain fail-closed. No bypass.
                result = self.service.resume(exc.run_id, 'M34 isolated recovery', cancel_event=cancel_event)
            self._fault('AFTER_HISTORY_COMMIT')
            if result['status'] != 'COMPLETED':
                raise ContinuousShadowError('EVALUATION_NOT_DURABLE')
            self._continuity(pending['observed'], self._capture(request.simulation.evaluation_time))
            state.update(sequence=state['sequence']+1, last_end=pending['end'], ledger=pending['observed'],
                         late_observed=state['late_observed']+pending['late'],
                         late_outside_overlap=state['late_outside_overlap']+pending['outside'],
                         pending=None, last_run_id=result['run_id'], last_finding_ids=result['result']['finding_ids'])
            self._transition(state,'CHECKPOINT_COMMITTED',run_id=result['run_id'])
            self._write(definition, state, expected_data=expected_data, final=True)
            self._error = None
            return self._status(state, 'COMMITTED')
        except Exception as exc:
            self._error = str(exc) if isinstance(exc, (ContinuousShadowError, ShadowStoreError)) else type(exc).__name__
            raise
        finally:
            self._lock.release()

    def run(self, stop_event: threading.Event, *, poll_seconds=.1, max_ticks=None):
        """Foreground caller owns cancellation and joins; never spawns a task/thread."""
        if not .05 <= poll_seconds <= 5 or (max_ticks is not None and (type(max_ticks) is not int or not 1 <= max_ticks <= MAX_TICKS)):
            raise ContinuousShadowError('INVALID_LOOP_BUDGET')
        committed = 0
        while not stop_event.is_set() and (max_ticks is None or committed < max_ticks):
            try:result = self.tick(cancel_event=stop_event)
            except CQQLQueryCancelledError:
                if not stop_event.is_set():raise
                break
            committed += int(result['state'] == 'COMMITTED')
            stop_event.wait(poll_seconds)
        return self.status()

    def status(self):
        _, state = self._load()
        return self._status(state, 'PENDING_RECOVERY' if state['pending'] else 'OWNED' if self._owner else 'STOPPED')

    def _status(self, state, status):
        pending=state['pending'];row=None
        if pending:
            request=DurableEvaluationRequest.model_validate(pending['request'])
            row=self.service.store.find_request(request,self.service.resolver.authority_sha256)
        stage=('FINDINGS_COMMITTED' if row and row['status']=='COMPLETED' else
               'RECOVERY_REQUIRED' if row and row['status']!='COMPLETED' else 'PENDING' if pending else
               'CHECKPOINT_COMMITTED' if state['sequence'] else 'CREATED')
        if self._error and stage not in {'FINDINGS_COMMITTED','RECOVERY_REQUIRED'}:stage='BLOCKED'
        gap=('RETENTION_GAP' if self._error=='SOURCE_RETENTION_GAP' else
             'SOURCE_GAP' if self._error in {'SOURCE_CONTENT_CHANGED','SOURCE_DATABASE_REPLACED','SOURCE_BINDING_MISMATCH'} else
             'PARTIAL' if state['late_outside_overlap'] else 'UNPROVEN')
        progress={'contract':'cq-shadow-progress-v1','stage':stage,'observed_gap':gap,
                  'pending_run_id':row['run_id'] if row else None,
                  'run_status':row['status'] if row else None,
                  'snapshot_state':('SEALED' if row['snapshot_json'] else 'UNSEALED') if row else None,
                  'unsealed_intent_present':bool(row and row['recovery_intent']),
                  'last_completed_evaluation':row['run_id'] if row and row['status']=='COMPLETED' else state['last_run_id'],
                  'transition_count':state.get('transitions_seen',0),'audit_scope':'M35_ONLY_LEGACY_NOT_BACKFILLED',
                  'transition_tail':state.get('transition_tail',[]),'window_completeness':'UNPROVEN'}
        return {'contract': 'cq-continuous-shadow-v1', 'namespace': NAMESPACE,
                'progress':progress,
                'state': 'DEGRADED' if self._error else status, 'reason': self._error,
                'rule_id': self.rule.rule_id, 'rule_version': self.rule.rule_version,
                'ticks_committed': state['sequence'], 'last_end': state['last_end'],
                'pending_evaluation': state['pending'] is not None,
                'last_run_id': state['last_run_id'], 'last_finding_ids': state['last_finding_ids'],
                'observed_records': len(state['ledger']), 'late_observed': state['late_observed'],
                'late_outside_overlap': state['late_outside_overlap'],
                'gap_status': 'UNPROVEN', 'historical_continuity': 'UNPROVEN',
                'production_active': False, 'scope': 'DISPOSABLE_SHADOW_ONLY',
                'source_checkpoint_reused': False, 'cross_database_atomicity': False,
                'queue_capacity': 1, 'queue_depth': int(state['pending'] is not None),
                'late_counter_scope': 'ALL_RETAINED_SOURCE_OBSERVATIONS',
                'source_event_capacity': 1000, 'tick_capacity': MAX_TICKS}
