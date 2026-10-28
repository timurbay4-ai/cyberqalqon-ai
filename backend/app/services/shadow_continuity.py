"""Bounded disposable scheduling slice over the existing M31 evaluator.

No startup hook, live path CLI, ingest callback, or production scheduler. The
separate checkpoint transaction is deliberately NOT atomic with M31 history.
Deterministic requests make the completed-run/checkpoint crash window retryable.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.db.shadow_history import ShadowStoreError, sha, source_binding
from app.schemas.shadow_history import DurableEvaluationRequest
from app.services.shadow_detection import snapshot_columns
from app.services.wazuh_normalizer import canonical_json

NAMESPACE = 'm33-disposable-shadow-schedule-v1'
MAX_EVENTS = 1000
MAX_TICKS = 128


class ShadowContinuityError(RuntimeError):
    pass


def _connection(path):
    connection = sqlite3.connect(path, timeout=.1, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA synchronous=FULL')
    connection.execute('PRAGMA foreign_keys=ON')
    return connection


def _state_sha(connection):
    state = connection.execute('SELECT definition_sha,next_tick,late_count FROM schedule WHERE singleton=1').fetchone()
    observed = connection.execute('SELECT * FROM observed ORDER BY event_id LIMIT ?', (MAX_EVENTS + 1,)).fetchall()
    completed = connection.execute('SELECT * FROM completions ORDER BY tick LIMIT ?', (MAX_TICKS + 1,)).fetchall()
    if len(observed) > MAX_EVENTS or len(completed) > MAX_TICKS:
        raise ShadowContinuityError('CHECKPOINT_CAPACITY_EXCEEDED')
    return sha([list(state), [list(row) for row in observed], [list(row) for row in completed]])


def prepare(path: Path, service, rule, *, first_end: datetime, ticks: int,
            stride_seconds: int = 60, disposable_only: bool = False):
    """Create ONLY a new independent finite schedule; never overwrite a cursor."""
    if disposable_only is not True:
        raise ShadowContinuityError('DISPOSABLE_SCHEDULE_REQUIRED')
    path = Path(path)
    if path.is_symlink() or path.exists() or path.parent.resolve() != service.store.path.parent:
        raise ShadowContinuityError('NEW_ISOLATED_CHECKPOINT_REQUIRED')
    if (type(ticks) is not int or not 1 <= ticks <= MAX_TICKS
            or type(stride_seconds) is not int or not 1 <= stride_seconds <= 300
            or first_end.tzinfo is None or rule.status != 'SHADOW_ONLY'):
        raise ShadowContinuityError('INVALID_SCHEDULE')
    first_end = first_end.astimezone(timezone.utc)
    last = first_end + timedelta(seconds=(ticks - 1) * stride_seconds + rule.allowed_lateness)
    if last > datetime.now(timezone.utc):
        raise ShadowContinuityError('FINITE_PAST_HORIZON_REQUIRED')
    service.store.verify()
    document = dict(namespace=NAMESPACE, source_binding=service.store.binding,
                    store_id=service.store.store_id, rule=rule.model_dump(mode='json'),
                    rule_version=rule.rule_version, first_end=first_end.isoformat(),
                    observation_cutoff=datetime.now(timezone.utc).isoformat(),
                    authority_sha256=service.resolver.authority_sha256,
                    ticks=ticks, stride_seconds=stride_seconds)
    # Exclusive OS creation also prevents two initializers from sharing a file.
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.close(descriptor)
    with closing(_connection(path)) as connection:
        connection.execute('PRAGMA journal_mode=WAL')
        connection.execute('BEGIN IMMEDIATE')
        connection.execute('PRAGMA user_version=1')
        connection.execute('CREATE TABLE schedule(singleton INTEGER PRIMARY KEY CHECK(singleton=1), definition TEXT NOT NULL, definition_sha TEXT NOT NULL, next_tick INTEGER NOT NULL, late_count INTEGER NOT NULL, state_sha TEXT NOT NULL)')
        connection.execute('CREATE TABLE observed(event_id TEXT PRIMARY KEY, row_sha TEXT NOT NULL, occurred_at TEXT NOT NULL)')
        connection.execute('CREATE TABLE completions(tick INTEGER PRIMARY KEY, request_json TEXT NOT NULL, run_id TEXT NOT NULL, snapshot_sha TEXT NOT NULL, late_count INTEGER NOT NULL)')
        connection.execute("INSERT INTO schedule VALUES(1,?,?,0,0,'')", (canonical_json(document), sha(document)))
        connection.execute('UPDATE schedule SET state_sha=?', (_state_sha(connection),))
        connection.commit()
        connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    # SQLite FULL handles transaction durability; directory durability is explicit
    # best effort on Windows, not a claimed power-loss guarantee.
    directory_fsync = False
    if os.name != 'nt':
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
            directory_fsync = True
        finally:
            os.close(descriptor)
    return {'namespace': NAMESPACE, 'ticks': ticks, 'directory_fsync': directory_fsync,
            'scope': 'DISPOSABLE_FINITE_VERTICAL_SLICE', 'production_active': False}


class ShadowContinuityWorker:
    """One explicit tick per call; no detached task and no automatic catch-up."""

    def __init__(self, path: Path, service, rule, *, disposable_only=False, fault_hook=None):
        if disposable_only is not True:
            raise ShadowContinuityError('DISPOSABLE_SCHEDULE_REQUIRED')
        self.path = Path(path).resolve(strict=True)
        if Path(path).is_symlink() or self.path.parent != service.store.path.parent:
            raise ShadowContinuityError('INVALID_CHECKPOINT_PATH')
        self.service, self.rule = service, rule
        self.fault = fault_hook or (lambda stage: None)

    def _definition(self, connection):
        if connection.execute('PRAGMA user_version').fetchone()[0] != 1:
            raise ShadowContinuityError('CHECKPOINT_SCHEMA_MISMATCH')
        row = connection.execute('SELECT * FROM schedule WHERE singleton=1').fetchone()
        if row is None:
            raise ShadowContinuityError('CHECKPOINT_INVALID')
        document = json.loads(row['definition'])
        keys = {'namespace','source_binding','store_id','rule','rule_version','first_end','observation_cutoff','authority_sha256','ticks','stride_seconds'}
        if (set(document) != keys or sha(document) != row['definition_sha']
                or row['state_sha'] != _state_sha(connection) or document['namespace'] != NAMESPACE
                or document['source_binding'] != source_binding(self.service.store.source)
                or document['store_id'] != self.service.store.store_id
                or document['authority_sha256'] != self.service.resolver.authority_sha256
                or document['rule_version'] != self.rule.rule_version
                or document['rule'] != self.rule.model_dump(mode='json')
                or not 0 <= row['next_tick'] <= document['ticks'] <= MAX_TICKS):
            raise ShadowContinuityError('CHECKPOINT_BINDING_MISMATCH')
        self.service.store.verify()
        # Detect partial or manual checkpoint edits instead of skipping a window.
        done = connection.execute('SELECT tick FROM completions ORDER BY tick').fetchall()
        if [value[0] for value in done] != list(range(row['next_tick'])):
            raise ShadowContinuityError('CHECKPOINT_SEQUENCE_MISMATCH')
        return row, document

    def tick(self):
        if self.path.stat().st_size > 8 * 1024 * 1024:
            raise ShadowContinuityError('CHECKPOINT_CAPACITY_EXCEEDED')
        began = time.perf_counter()
        try:
            with closing(_connection(self.path)) as connection:
                connection.execute('BEGIN IMMEDIATE')  # serialize this namespace
                state, definition = self._definition(connection)
                index = state['next_tick']
                if index == definition['ticks']:
                    connection.rollback()
                    return self._status(state, definition, 'COMPLETE', None, 0)
                end = datetime.fromisoformat(definition['first_end']) + timedelta(seconds=index * definition['stride_seconds'])
                start = end - timedelta(seconds=self.rule.window_seconds + self.rule.allowed_lateness)
                # Bounded exact source observation, stable order, separate RO
                # snapshot. Never interpreted as an archive-delivery watermark.
                uri = self.service.store.source.as_uri() + '?mode=ro'
                with closing(sqlite3.connect(uri, uri=True, timeout=.1)) as source:
                    source.row_factory = sqlite3.Row
                    source.set_progress_handler(lambda: int(time.perf_counter() - began > 1.5), 1000)
                    source.execute('BEGIN')
                    if source.execute('PRAGMA user_version').fetchone()[0] != 17:
                        raise ShadowContinuityError('SOURCE_SCHEMA_MISMATCH')
                    count, size = source.execute('SELECT COUNT(*),COALESCE(SUM(length(CAST(raw_event_json AS BLOB))+length(CAST(structured_json AS BLOB))),0) FROM (SELECT raw_event_json,structured_json FROM security_events ORDER BY occurred_at,event_id LIMIT ?)', (MAX_EVENTS + 1,)).fetchone()
                    if count > MAX_EVENTS:
                        raise ShadowContinuityError('SOURCE_OBSERVATION_CAPACITY_EXCEEDED')
                    if size > 8 * 1024 * 1024:
                        raise ShadowContinuityError('SOURCE_OBSERVATION_BYTES_EXCEEDED')
                    # These column names are owned by the existing query catalog.
                    rows = source.execute(f'SELECT {snapshot_columns()} FROM security_events ORDER BY occurred_at,event_id LIMIT ?', (MAX_EVENTS + 1,)).fetchall()
                if len(rows) > MAX_EVENTS:
                    raise ShadowContinuityError('SOURCE_OBSERVATION_CAPACITY_EXCEEDED')
                current = {row['event_id']: (sha(dict(row)), row['occurred_at']) for row in rows}
                previous = {row['event_id']: (row['row_sha'], row['occurred_at'])
                            for row in connection.execute('SELECT * FROM observed')}
                if previous.keys() - current.keys():
                    raise ShadowContinuityError('SOURCE_RETENTION_GAP')
                if any(current[key] != value for key, value in previous.items()):
                    raise ShadowContinuityError('SOURCE_CONTENT_CHANGED')
                # New arrivals older than the preceding closed window are
                # accounted for even if outside the finite overlap. No replay.
                previous_end = end - timedelta(seconds=definition['stride_seconds'])
                late = sum(index > 0 and datetime.fromisoformat(value[1]) <= previous_end
                           for key, value in current.items() if key not in previous)
                request = DurableEvaluationRequest.model_validate({'simulation': {
                    'rule': definition['rule'], 'start_time': start.isoformat(), 'end_time': end.isoformat(),
                    'evaluation_time': definition['observation_cutoff']}})
                try:
                    result = self.service.evaluate(request, 'M33 isolated scheduler')
                except ShadowStoreError as exc:
                    if str(exc) != 'RUN_REQUIRES_EXPLICIT_RESUME' or not getattr(exc, 'run_id', None):
                        raise
                    result = self.service.resume(exc.run_id, 'M33 isolated scheduler recovery')
                self.fault('AFTER_HISTORY_COMMIT')
                if result['status'] != 'COMPLETED':
                    raise ShadowContinuityError('EVALUATION_INCOMPLETE')
                for key in current.keys() - previous.keys():
                    connection.execute('INSERT INTO observed VALUES(?,?,?)', (key, *current[key]))
                connection.execute('INSERT INTO completions VALUES(?,?,?,?,?)',
                                   (index, canonical_json(request.model_dump(mode='json')), result['run_id'], result['snapshot_sha256'], late))
                connection.execute('UPDATE schedule SET next_tick=next_tick+1,late_count=late_count+? WHERE singleton=1', (late,))
                connection.execute('UPDATE schedule SET state_sha=?', (_state_sha(connection),))
                self.fault('BEFORE_CHECKPOINT_COMMIT')
                connection.commit()
                return self._status(dict(next_tick=index + 1, late_count=state['late_count'] + late), definition,
                                    'COMPLETE' if index + 1 == definition['ticks'] else 'MORE', result['run_id'], late)
        except (sqlite3.Error, ValueError, KeyError, TypeError) as exc:
            raise ShadowContinuityError('CHECKPOINT_OR_SOURCE_UNAVAILABLE') from exc

    @staticmethod
    def _status(state, definition, status, run_id, late):
        return dict(namespace=NAMESPACE, status=status, next_tick=state['next_tick'],
                    remaining_ticks=definition['ticks'] - state['next_tick'], run_id=run_id,
                    late_new=late, late_total=state['late_count'], source_gap='UNPROVEN',
                    late_outside_overlap='ACCOUNTED_NOT_REPLAYED', production_active=False,
                    historical_continuity='UNPROVEN', scope='DISPOSABLE_FINITE_VERTICAL_SLICE')
