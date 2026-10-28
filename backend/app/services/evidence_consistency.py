"""Bounded snapshot reconciliation. Returns an audit, does not rewrite history."""
from __future__ import annotations
import base64
import binascii
from collections import Counter
from contextlib import closing
from datetime import datetime,timezone
import json
import sqlite3
import time
from app.db.shadow_history import ShadowStoreError,sha
from app.db.cqql import CQQLQueryBusyError,CQQLQueryTimeoutError,CQQLQueryCancelledError
from app.services.shadow_detection import snapshot_columns,check_budget


def revision_references(c,finding_id,revision):
    try:return _revision_references(c,finding_id,revision)
    except (ValueError,TypeError,KeyError,IndexError):raise ShadowStoreError('SHADOW_STORE_CORRUPT') from None


def _revision_references(c,finding_id,revision):
    row=c.execute('SELECT match_json,identity_json,content_sha FROM shadow_revisions WHERE finding_id=? AND revision=?',(finding_id,revision)).fetchone()
    if row is None:raise ShadowStoreError('SHADOW_STORE_CORRUPT')
    match,identity=json.loads(row['match_json']),json.loads(row['identity_json'])
    if sha([match,identity])!=row['content_sha']:raise ShadowStoreError('SHADOW_STORE_CORRUPT')
    references=[dict(r) for r in c.execute('SELECT event_id,envelope_sha,row_sha FROM shadow_evidence WHERE finding_id=? AND revision=? ORDER BY event_id LIMIT 33',(finding_id,revision))]
    expected={v['event_id']:v['stored_envelope_sha256'] for v in match['evidence']}
    if not expected or len(expected)>32 or len(references)>32 or expected!={v['event_id']:v['envelope_sha'] for v in references}:raise ShadowStoreError('SHADOW_STORE_CORRUPT')
    sealed=c.execute('SELECT r.snapshot_json,r.snapshot_sha FROM shadow_runs r JOIN shadow_run_findings f ON r.run_id=f.run_id WHERE f.finding_id=? AND f.revision=? LIMIT 1',(finding_id,revision)).fetchone()
    if sealed is None:raise ShadowStoreError('SHADOW_STORE_CORRUPT')
    snapshot=json.loads(sealed['snapshot_json'])
    if sha(snapshot)!=sealed['snapshot_sha']:raise ShadowStoreError('SHADOW_STORE_CORRUPT')
    bound={entry['event_id']:entry['row_sha256'] for entry in snapshot['entries']}
    if any(bound.get(v['event_id'])!=v['row_sha'] for v in references):raise ShadowStoreError('SHADOW_STORE_CORRUPT')
    return references


def availability(source,references,*,deadline,cancel_event=None):
    expected={r['event_id']:r for r in references};states={key:'MISSING' for key in expected}
    if not expected:return states
    for row in source.execute('SELECT '+snapshot_columns()+' FROM security_events WHERE event_id IN ('+','.join('?' for _ in expected)+')',tuple(expected)):
        check_budget(deadline,cancel_event)
        states[row['event_id']]='AVAILABLE' if sha(dict(row))==expected[row['event_id']]['row_sha'] else 'CHANGED'
    return states


def reconcile(store,queries,*,limit=20,cursor=None,cancel_event=None):
    if type(limit) is not int or not 1<=limit<=50:raise ShadowStoreError('INVALID_LIMIT')
    after=None
    if cursor:
        try:
            if len(cursor)>512:raise ValueError()
            body=json.loads(base64.b64decode(cursor+'='*(-len(cursor)%4),altchars=b'-_',validate=True))
            if set(body)!={'store','source','finding','revision','checksum'}:raise ValueError()
            checksum=body.pop('checksum')
            if sha(body)!=checksum or body['store']!=store.store_id or body['source']!=store.binding:raise ValueError()
            if not isinstance(body['finding'],str) or type(body['revision']) is not int or not 1<=body['revision']<=8192:raise ValueError()
            after=(body['finding'],body['revision'])
        except (ValueError,TypeError,binascii.Error):raise ShadowStoreError('INVALID_CURSOR') from None
    revisions=[];next_cursor=None;counts=Counter();source=None;acquired=False
    deadline=time.perf_counter()+1.5
    with closing(store._connect()) as sidecar:
        sidecar.set_progress_handler(lambda:int(time.perf_counter()>=deadline or cancel_event is not None and cancel_event.is_set()),1000)
        sidecar.execute('BEGIN')
        predicate='WHERE (finding_id,revision)>(?,?)' if after else ''
        selected=sidecar.execute('SELECT finding_id,revision FROM shadow_revisions '+predicate+' ORDER BY finding_id,revision LIMIT ?',(*(after or ()),limit+1)).fetchall()
        try:
            queries._acquire_slot(cancel_event);acquired=True;source=queries._connect()
            queries._install_deadline(source,deadline,cancel_event);source.execute('BEGIN')
            for row in selected[:limit]:
                check_budget(deadline,cancel_event);refs=revision_references(sidecar,row['finding_id'],row['revision'])
                states=availability(source,refs,deadline=deadline,cancel_event=cancel_event);counts.update(states.values())
                revisions.append({'finding_id':row['finding_id'],'revision':row['revision'],'availability':states,'reference_sha256':sha(refs)})
        except (CQQLQueryBusyError,CQQLQueryTimeoutError):
            revisions=[];counts=Counter()
            for row in selected[:limit]:
                refs=revision_references(sidecar,row['finding_id'],row['revision']);states={r['event_id']:'UNKNOWN' for r in refs};counts.update(states.values())
                revisions.append({'finding_id':row['finding_id'],'revision':row['revision'],'availability':states,'reference_sha256':sha(refs)})
        except sqlite3.OperationalError as exc:
            raise queries._translate_sqlite(exc,cancel_event) from None
        finally:
            if source is not None:source.set_progress_handler(None,0);source.close()
            if acquired:queries._slots.release()
        if len(selected)>limit and revisions:
            row=selected[limit-1];body={'store':store.store_id,'source':store.binding,'finding':row['finding_id'],'revision':row['revision']}
            body['checksum']=sha(body);next_cursor=base64.urlsafe_b64encode(json.dumps(body,separators=(',',':')).encode()).decode().rstrip('=')
    return {'version':'m32-reconciliation-v1','source_binding':store.binding,'store_id':store.store_id,
        'observed_at':datetime.now(timezone.utc),'revisions':revisions,'counts':dict(counts),'next_cursor':next_cursor,
        'scope':'READ_ONLY_POINT_IN_TIME_PER_PAGE','history_modified':False,'automatic_evidence_pins':False,
        'cross_database_atomic':False,'historical_continuity':'UNPROVEN'}
