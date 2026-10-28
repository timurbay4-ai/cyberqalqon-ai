"""Offline/disposable pair custody. No active restore, rebind or production CLI."""
from __future__ import annotations
from collections import Counter
from contextlib import closing,ExitStack
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
import uuid
from app.db.shadow_history import sha,source_binding,ShadowStoreError
from app.db.fts_rowid import file_sha
from app.services.evidence_consistency import revision_references,availability
from app.services.shadow_intent import validate_intent
from app.schemas.shadow_history import DurableEvaluationRequest
from app.schemas.shadow_detection import ShadowRule

MAX_REFERENCES=50000


def _ro(path):
    c=sqlite3.connect(Path(path).resolve(strict=True).as_uri()+'?mode=ro',uri=True,timeout=.1)
    c.row_factory=sqlite3.Row;c.execute('PRAGMA query_only=ON');c.execute('PRAGMA foreign_keys=ON')
    return c


def _logical(c,tables):
    value=hashlib.sha256()
    for table in tables:
        value.update(table.encode())
        for row in c.execute('SELECT * FROM '+table+' ORDER BY 1,2'):
            value.update(json.dumps(tuple(row),ensure_ascii=False,separators=(',',':')).encode());value.update(b'\n')
    return value.hexdigest()


def inspect_pair(source_path,sidecar_path,*,expected_binding=None,expected_store=None):
    """Bounded offline reference validation, never changes the captured binding."""
    deadline=time.perf_counter()+30;counts=Counter();references=0
    with closing(_ro(source_path)) as source,closing(_ro(sidecar_path)) as sidecar:
        for c in (source,sidecar):c.set_progress_handler(lambda:int(time.perf_counter()>=deadline),1000)
        if source.execute('PRAGMA user_version').fetchone()[0]!=17 or sidecar.execute('PRAGMA user_version').fetchone()[0]!=1:raise ValueError('PAIR_SCHEMA_MISMATCH')
        meta=sidecar.execute('SELECT source_binding,store_id FROM shadow_meta WHERE singleton=1').fetchone()
        if meta is None or expected_binding and meta['source_binding']!=expected_binding or expected_store and meta['store_id']!=expected_store:
            raise ValueError('PAIR_IDENTITY_MISMATCH')
        if sidecar.execute('SELECT COUNT(*) FROM shadow_revisions').fetchone()[0]>8192:raise ValueError('CONSISTENCY_BUDGET_EXCEEDED')
        for c in (source,sidecar):
            if c.execute('PRAGMA quick_check').fetchone()[0]!='ok' or c.execute('PRAGMA foreign_key_check').fetchone():raise ValueError('PAIR_INTEGRITY_FAILED')
        for row in sidecar.execute('SELECT finding_id,revision FROM shadow_revisions ORDER BY finding_id,revision'):
            refs=revision_references(sidecar,row['finding_id'],row['revision']);references+=len(refs)
            if references>MAX_REFERENCES:raise ValueError('CONSISTENCY_BUDGET_EXCEEDED')
            counts.update(availability(source,refs,deadline=deadline).values())
        for row in sidecar.execute('SELECT rule_version,definition FROM shadow_rules'):
            if ShadowRule.model_validate_json(row['definition']).rule_version!=row['rule_version']:raise ValueError('RULE_VERSION_MISMATCH')
        for row in sidecar.execute('SELECT * FROM shadow_runs'):
            request=json.loads(row['request_json']);DurableEvaluationRequest.model_validate(request['payload'])
            base={'payload':request['payload'],'authority_sha':request['authority_sha']}
            if set(request)-{'payload','authority_sha','recovery_intent'} or sha([meta['store_id'],base])!=row['request_key']:
                raise ValueError('RUN_REQUEST_CHECKSUM_MISMATCH')
            intent=request.get('recovery_intent')
            if intent is not None:validate_intent(meta['store_id'],meta['source_binding'],base,intent)
            if row['snapshot_json'] is not None and sha(json.loads(row['snapshot_json']))!=row['snapshot_sha']:raise ValueError('RUN_SNAPSHOT_CHECKSUM_MISMATCH')
            if row['snapshot_json'] is not None and intent is not None and row['snapshot_sha']!=intent['manifest_sha256']:
                raise ValueError('RUN_INTENT_SNAPSHOT_MISMATCH')
            if row['status']=='COMPLETED':
                if not row['result_json'] or sha(json.loads(row['result_json']))!=row['result_sha']:raise ValueError('RUN_CHECKSUM_MISMATCH')
                expected=set(json.loads(row['result_json'])['finding_ids'])
                linked={r[0] for r in sidecar.execute('SELECT finding_id FROM shadow_run_findings WHERE run_id=?',(row['run_id'],))}
                if expected!=linked:raise ValueError('RUN_FINDING_LINK_MISMATCH')
        return {'source_schema':17,'sidecar_schema':1,'source_binding':meta['source_binding'],'store_id':meta['store_id'],
            'source_count':source.execute('SELECT COUNT(*) FROM security_events').fetchone()[0],
            'sidecar_runs':sidecar.execute('SELECT COUNT(*) FROM shadow_runs').fetchone()[0],
            'sidecar_revisions':sidecar.execute('SELECT COUNT(*) FROM shadow_revisions').fetchone()[0],
            'availability':dict(counts),'references':references,'quick_check':'ok','foreign_keys':0,
            'source_digest':_logical(source,('security_events',)),
            'history_digest':_logical(sidecar,('shadow_meta','shadow_rules','shadow_authorities','shadow_runs','shadow_findings','shadow_revisions','shadow_evidence','shadow_run_findings','shadow_transitions','security_audit_events')),
            'consistency':'REFERENCE_VALID' if not any(counts[key] for key in ('MISSING','CHANGED','UNKNOWN')) else 'EVIDENCE_GAPS_RETAINED',
            'cross_database_atomic':False,'runtime_binding':'OFFLINE_ONLY_ORIGINAL_BINDING_PRESERVED'}


def _sync(path):
    # Windows _commit requires a writable descriptor for FlushFileBuffers.
    with Path(path).open('r+b') as stream:stream.flush();os.fsync(stream.fileno())


def _sync_parent(path):
    try:
        descriptor=os.open(path,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
        return True
    except OSError:return False  # Windows directory handles need another API; no power-loss claim.


def capture_pair(service,destination:Path,*,disposable_only=False,order='quiescent',fault_hook=None):
    if disposable_only is not True:raise ValueError('DISPOSABLE_BACKUP_REQUIRED')
    if order not in {'quiescent','source_first','sidecar_first'}:raise ValueError('INVALID_BACKUP_ORDER')
    if service._owner_file is None:raise ShadowStoreError('SHADOW_OWNER_NOT_ACQUIRED')
    destination=Path(destination)
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():raise ValueError('BACKUP_DESTINATION_MUST_BE_NEW')
    staging=destination.with_name(destination.name+'.partial-'+uuid.uuid4().hex);staging.mkdir()
    fault_hook=fault_hook or (lambda stage:None)
    with service.scheduler.admit(),ExitStack() as stack:
        if order=='quiescent':
            # Writer guards in TWO distinct files, held while separate read-only
            # backup connections copy. No claim that their transactions commit together.
            guard=stack.enter_context(closing(sqlite3.connect(service.store.source,timeout=.1)))
            guard.execute('BEGIN IMMEDIATE')
            other=stack.enter_context(closing(service.store._connect()));other.execute('BEGIN IMMEDIATE')
        binding=source_binding(service.store.source)
        before=inspect_pair(service.store.source,service.store.path,expected_binding=binding,expected_store=service.store.store_id)
        roles=['sidecar','source'] if order=='sidecar_first' else ['source','sidecar']
        for index,role in enumerate(roles):
            original=service.store.source if role=='source' else service.store.path
            with closing(_ro(original)) as source,closing(sqlite3.connect(staging/(role+'.db'))) as target:
                source.backup(target,pages=128,sleep=.005)
            _sync(staging/(role+'.db'));fault_hook('AFTER_'+role.upper()+'_BACKUP')
        result=inspect_pair(staging/'source.db',staging/'sidecar.db',expected_binding=binding,expected_store=service.store.store_id)
        if order=='quiescent' and (before['source_digest']!=result['source_digest'] or before['history_digest']!=result['history_digest']):
            raise ValueError('QUIESCENT_SNAPSHOT_CHANGED')
        manifest={'version':'m32-shadow-pair-v1','captured_at':datetime.now(timezone.utc).isoformat(),
            'order':order,'writer_guards':order=='quiescent','application_contract':'schema17-sidecar1-m31-shadow-v1',
            'source_sha256':file_sha(staging/'source.db'),'sidecar_sha256':file_sha(staging/'sidecar.db'),
            'source_binding':binding,'store_id':service.store.store_id,'pair':result,
            'durability':'FILES_FSYNC_ATOMIC_DIRECTORY_PUBLICATION_PARENT_BEST_EFFORT',
            'historical_continuity':'UNPROVEN','activation':'OFFLINE_RESTORE_ONLY_NO_REBIND'}
        body=json.dumps(manifest,sort_keys=True,indent=2)+'\n'
        with (staging/'manifest.json').open('x',encoding='utf-8') as out:out.write(body);out.flush();os.fsync(out.fileno())
        receipt=file_sha(staging/'manifest.json');fault_hook('BEFORE_PUBLICATION')
        staging.rename(destination);parent_synced=_sync_parent(destination.parent)
    return {'manifest_sha256':receipt,'directory':str(destination),'manifest':manifest,'parent_fsync':parent_synced}


def validate_backup(directory:Path,expected_manifest_sha256:str):
    directory=Path(directory)
    if directory.is_symlink():raise ValueError('INVALID_BACKUP_DIRECTORY')
    if len(expected_manifest_sha256)!=64 or any(x not in '0123456789abcdef' for x in expected_manifest_sha256):raise ValueError('INVALID_TRUSTED_RECEIPT')
    for name in ('source.db','sidecar.db','manifest.json'):
        path=directory/name
        if path.is_symlink() or not path.is_file():raise ValueError('INVALID_BACKUP_FILE')
    if file_sha(directory/'manifest.json')!=expected_manifest_sha256:raise ValueError('MANIFEST_CHECKSUM_MISMATCH')
    if (directory/'manifest.json').stat().st_size>32768:raise ValueError('MANIFEST_TOO_LARGE')
    value=json.loads((directory/'manifest.json').read_text())
    keys={'version','captured_at','order','writer_guards','application_contract','source_sha256','sidecar_sha256','source_binding','store_id','pair','durability','historical_continuity','activation'}
    if set(value)!=keys or value['version']!='m32-shadow-pair-v1' or value['activation']!='OFFLINE_RESTORE_ONLY_NO_REBIND':raise ValueError('INVALID_BACKUP_MANIFEST')
    # File names are fixed, never read from potentially hostile manifest paths.
    for role in ('source','sidecar'):
        if file_sha(directory/(role+'.db'))!=value[role+'_sha256']:raise ValueError('BACKUP_FILE_CHECKSUM_MISMATCH')
    actual=inspect_pair(directory/'source.db',directory/'sidecar.db',expected_binding=value['source_binding'],expected_store=value['store_id'])
    if actual!=value['pair']:raise ValueError('BACKUP_PAIR_RECONCILIATION_MISMATCH')
    return value


def restore_offline(directory:Path,destination:Path,expected_manifest_sha256:str,*,disposable_only=False,fault_hook=None):
    if disposable_only is not True:raise ValueError('DISPOSABLE_RESTORE_REQUIRED')
    manifest=validate_backup(directory,expected_manifest_sha256);destination=Path(destination)
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():raise ValueError('RESTORE_DESTINATION_MUST_BE_NEW')
    staging=destination.with_name(destination.name+'.partial-'+uuid.uuid4().hex);staging.mkdir()
    fault_hook=fault_hook or (lambda stage:None)
    for role in ('source','sidecar'):
        with closing(_ro(Path(directory)/(role+'.db'))) as source,closing(sqlite3.connect(staging/(role+'.db'))) as target:source.backup(target)
        _sync(staging/(role+'.db'));fault_hook('AFTER_'+role.upper()+'_RESTORE')
    actual=inspect_pair(staging/'source.db',staging/'sidecar.db',expected_binding=manifest['source_binding'],expected_store=manifest['store_id'])
    if actual!=manifest['pair']:raise ValueError('RESTORE_RECONCILIATION_MISMATCH')
    fault_hook('BEFORE_PUBLICATION');staging.rename(destination);_sync_parent(destination.parent)
    return {'status':'OFFLINE_RESTORE_VALIDATED','runtime_activation':'BLOCKED_BINDING_APPROVAL_REQUIRED',
        'manifest_sha256':expected_manifest_sha256,'pair':actual,'historical_continuity':'UNPROVEN'}
