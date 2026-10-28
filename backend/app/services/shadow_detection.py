"""Bounded CDRC v2 simulation used by AdvancedDetectionEngine, never ingestion.

No queues, background tasks, checkpoint files, migrations or finding persistence.
Structured CQQL semantics are interpreted from its existing typed AST. SQLite
reads use the SAME query semaphore/deadline/cancellation as ordinary CQQL.
"""
from __future__ import annotations

import hashlib
import json
import ntpath
import re
import sqlite3
import threading
import time
import uuid
from collections import Counter, deque
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime,timedelta,timezone
from typing import Mapping

from app.db.cqql import CQQLSearchRepository,CQQLQueryBusyError,CQQLQueryCancelledError,CQQLQueryTimeoutError
from app.schemas.cuse import CUSEMetadata
from app.schemas.shadow_detection import (ShadowRule,ShadowSimulationRequest,ShadowSimulationResult,
    ShadowFinding,FindingEvidence,MitreContext,ChainEdge)
from app.services.cqql import FIELD_CATALOG,Comparison,BooleanExpression,Negation,parse_cqql,compile_cqql
from app.services.wazuh_normalizer import canonical_json

MAX_EVENTS = 1000
MAX_INPUT_BYTES = 8_388_608
MAX_GROUPS = 256
MAX_EVENTS_PER_GROUP = 64
MAX_FINDINGS = 100
MAX_GRAPH_NODES = 128
MAX_GRAPH_EDGES = 256
EVALUATION_SECONDS = 1.0
ASCII_NOCASE = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')


class ShadowResourceLimitError(RuntimeError):
    """Static error codes only; no queries or evidence in diagnostic logs."""


class ShadowEventError(ValueError):
    """Typed static event diagnostic; never a raw payload or parser exception."""


def check_budget(deadline: float,cancel_event: threading.Event | None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise CQQLQueryCancelledError('Shadow simulation cancelled')
    if time.perf_counter() >= deadline:
        raise CQQLQueryTimeoutError('Shadow simulation exceeded its evaluation budget')


def compare(expression,values: Mapping[str,object],*,two_valued=False) -> bool | None:
    """SQLite-compatible three-valued structured CQQL, including ASCII NOCASE."""
    if isinstance(expression,Negation):
        result = compare(expression.expression,values,two_valued=two_valued)
        return None if result is None else not result
    if isinstance(expression,BooleanExpression):
        left,right = compare(expression.left,values,two_valued=two_valued),compare(expression.right,values,two_valued=two_valued)
        if expression.operator == 'AND':
            return False if left is False or right is False else None if left is None or right is None else True
        return True if left is True or right is True else None if left is None or right is None else False
    if not isinstance(expression,Comparison): raise ValueError('unsupported AST')
    definition = FIELD_CATALOG[expression.field]
    left,right = values.get(expression.field),expression.value
    if expression.field == 'mitre.id':
        found = right in (left or ())
        return found if expression.operator == '=' else not found
    if left is None: return False if two_valued else None
    if definition.case_insensitive:
        left,right = str(left).translate(ASCII_NOCASE),str(right).translate(ASCII_NOCASE)
    operations = {'=':lambda:left == right,'!=':lambda:left != right,'>':lambda:left > right,
                  '>=':lambda:left >= right,'<':lambda:left < right,'<=':lambda:left <= right,
                  'CONTAINS':lambda:right in left,'STARTSWITH':lambda:left.startswith(right)}
    return operations[expression.operator]()


def _aware(value: str) -> datetime:
    try: result = datetime.fromisoformat(value)
    except ValueError as exc: raise ShadowEventError('INVALID_TIME') from exc
    if result.tzinfo is None or result.utcoffset() is None: raise ShadowEventError('INVALID_TIME')
    return result.astimezone(timezone.utc)


def _record(row: Mapping,*,include_raw=False) -> dict:
    cuse = CUSEMetadata.model_validate(json.loads(row['structured_json'])['_cuse'])
    occurred,ingested = _aware(row['occurred_at']),_aware(row['ingested_at'])
    if cuse.timestamp_basis != 'SOURCE_EVENT_TIME': raise ShadowEventError('UNKNOWN_TIME')
    if cuse.source_event_time != occurred: raise ShadowEventError('CONFLICTING_TIME')
    if any(warning in cuse.warnings for warning in ('YEARLESS_TIME_UNRESOLVED','SOURCE_TIME_CONTEXT_INFERRED')):
        raise ShadowEventError('UNKNOWN_TIME')
    if not cuse.transport_authenticated: raise ShadowEventError('UNVERIFIED_TRANSPORT')
    if cuse.normalization_status == 'UNSUPPORTED_SOURCE': raise ShadowEventError('UNSUPPORTED_SOURCE')
    raw = json.loads(row['raw_event_json'])
    if not isinstance(raw,dict): raise ValueError('invalid stored envelope')
    fingerprint = hashlib.sha256(canonical_json(raw).encode()).hexdigest()
    if fingerprint != row['deduplication_id'] or fingerprint != cuse.content_fingerprint:
        raise ShadowEventError('INVALID_EVIDENCE')
    if cuse.idempotency_contract == 'REGISTERED_SOURCE_RECORD_SHA256':
        from app.services.network_telemetry import source_record_identity
        if row['event_id'] != source_record_identity(raw) or raw['data']['source_generation'] != cuse.source_generation:
            raise ShadowEventError('INVALID_EVIDENCE')
    elif row['event_id'] != 'EVT-'+fingerprint[:24].upper():
        raise ShadowEventError('INVALID_EVIDENCE')
    values = {name:(cuse.attributes.get(definition.attribute_key) if definition.attribute_key
                   else row.get(definition.column[2:]))
              for name,definition in FIELD_CATALOG.items() if definition.column}
    values['mitre.id'] = json.loads(row['mitre_ids_json'])
    if (not isinstance(values['mitre.id'],list) or len(values['mitre.id']) > 20
            or any(not isinstance(item,str) for item in values['mitre.id'])):
        raise ValueError('invalid MITRE evidence')
    account_sids = set()
    if cuse.source_family == 'WINDOWS_EVENTCHANNEL':
        data = raw.get('data',{})
        if not isinstance(data,dict) or not isinstance(data.get('win'),dict): raise ValueError('invalid Windows evidence')
        data = data['win'].get('eventdata',{})
        if not isinstance(data,dict): raise ValueError('invalid Windows identity')
        for principal,attribute in (('targetUserName','target_user_sid'),('subjectUserName','subject_user_sid')):
            sid = cuse.attributes.get(attribute)
            if sid and str(data.get(principal,'')).translate(ASCII_NOCASE) == str(values.get('user.name') or '').translate(ASCII_NOCASE):
                if not re.fullmatch(r'S-\d+(?:-\d+){1,15}',str(sid),re.IGNORECASE):
                    raise ValueError('invalid account SID')
                if str(sid).upper() not in {'S-1-0-0'}: account_sids.add(str(sid).upper())
    if len(account_sids) > 1: raise ValueError('conflicting account SID')
    values['user.sid'] = next(iter(account_sids),None)
    for field,attribute in (('process.guid','process_guid'),('process.parent.guid','parent_process_guid')):
        original = cuse.attributes.get(attribute)
        values[field] = str(uuid.UUID(str(original))) if original else None
    scope = (str(row.get('manager_identity') or '').strip(),str(row.get('agent_id') or '').strip(),
             str(row.get('hostname') or '').strip().translate(ASCII_NOCASE))
    if not all(scope): raise ShadowEventError('UNRESOLVED_IDENTITY')
    source_key = None
    if cuse.source_family in {'WINDOWS_EVENTCHANNEL','SYSMON'} and cuse.attributes.get('event_record_id'):
        source_key = ['WINDOWS_RECORD',scope,str(values.get('event.provider') or '').translate(ASCII_NOCASE),
            str(values.get('event.channel') or '').translate(ASCII_NOCASE),cuse.attributes['event_record_id'],occurred.isoformat()]
    elif cuse.attributes.get('boot_id') and cuse.attributes.get('journal_record_cursor'):
        source_key = ['JOURNAL_RECORD',scope,cuse.attributes['boot_id'],cuse.attributes['journal_record_cursor'],occurred.isoformat()]
    source_key = hashlib.sha256(canonical_json(source_key).encode()).hexdigest() if source_key else None
    semantic = hashlib.sha256(canonical_json({'values':{key:value for key,value in values.items() if key!='event.id'},
                                             'attributes':cuse.attributes}).encode()).hexdigest()
    return {'id':row['event_id'],'time':occurred,'ingested':ingested,'family':cuse.source_family,
        'values':values,'scope':scope,'cuse':cuse,'sha':fingerprint,'source_key':source_key,'semantic':semantic,
        **({'raw':raw} if include_raw else {})}


def _matches(step,expression,values,*,two_valued=False):
    return compare(expression,values,two_valued=two_valued) is True and all(
        not expected or ntpath.basename(str(values.get(field) or '')).translate(ASCII_NOCASE)==expected.translate(ASCII_NOCASE)
        for field,expected in (('process.name',step.process_basename_equals),('process.parent.name',step.parent_basename_equals)))


def _sequence(events,steps,expressions,*,two_valued=False):
    selected,stage,count,last_time = [],0,0,None
    for event in events:
        if last_time is not None and count == 0 and event['time'] <= last_time: continue
        if not _matches(steps[stage],expressions[stage],event['values'],two_valued=two_valued): continue
        selected.append(event)
        count += 1
        if count == steps[stage].threshold:
            last_time = event['time']
            stage,count = stage+1,0
            if stage == len(steps): return selected
    return None


def _unordered(events,rule,expressions,deadline,cancel_event):
    """Bounded bipartite assignment, unique event per required step/count slot."""
    slots = [index for index,step in enumerate(rule.steps) for _ in range(step.threshold)]
    options = [[index for index,event in enumerate(events)
                if _matches(rule.steps[step],expressions[step],event['values'],two_valued=rule.predicate_semantics=='SIGMA_2VL')]
               for step in slots]
    assigned = {}
    def assign(slot,visited):
        check_budget(deadline,cancel_event)
        for event in options[slot]:
            if event in visited:continue
            visited.add(event)
            if event not in assigned or assign(assigned[event],visited):
                assigned[event]=slot;return True
        return False
    if not all(assign(slot,set()) for slot in range(len(slots))):return None
    return sorted((events[index] for index in assigned),key=lambda event:(event['time'],event['id']))


def evaluate_records(rule: ShadowRule,records: list[dict],*,cancel_event=None,deadline=None):
    """Finite simulation, not a durable streaming checkpoint or global watermark."""
    from app.services.shadow_rules import validate_mitre
    from app.services.advanced_detection import MITRE_TECHNIQUES
    validate_mitre(rule)
    if rule.status != 'SHADOW_ONLY': return [],Counter({'RULE_DISABLED':1})
    if len(records) > MAX_EVENTS: raise ShadowResourceLimitError('MAX_EVENTS')
    deadline = deadline if deadline is not None else time.perf_counter()+EVALUATION_SECONDS
    check_budget(deadline,cancel_event)
    if min(rule.confidence,40) < rule.minimum_confidence:
        return [],Counter({'BELOW_MINIMUM_CONFIDENCE':1})
    expressions = [parse_cqql(step.query).expression for step in rule.steps]
    two_valued = rule.predicate_semantics == 'SIGMA_2VL'
    diagnostics = Counter()
    accepted,seen,watermarks,source_seen = [],{},{},{}
    for event in sorted(records,key=lambda event:(event['ingested'],event['id'])):
        check_budget(deadline,cancel_event)
        if event['id'] in seen:
            if seen[event['id']] != event['sha']: raise ShadowResourceLimitError('EVENT_IDENTITY_CONFLICT')
            diagnostics['DUPLICATE_INPUT'] += 1
            continue
        seen[event['id']] = event['sha']
        source_key = event.get('source_key')
        if source_key:
            if source_key in source_seen:
                if source_seen[source_key] != event['semantic']:
                    raise ShadowResourceLimitError('SOURCE_RECORD_CONFLICT')
                diagnostics['DUPLICATE_SOURCE_RECORD'] += 1
                continue
            source_seen[source_key] = event['semantic']
        if event['family'] not in rule.source_families:
            diagnostics['UNSUPPORTED_SOURCE'] += 1
            continue
        if not any(compare(expression,event['values'],two_valued=two_valued) is True for expression in expressions):
            diagnostics['NO_MATCH'] += 1
            continue
        if any(event['values'].get(field) in (None,'') for field in rule.required_fields):
            diagnostics['UNSUPPORTED_FIELDS'] += 1
            continue
        if not any(_matches(step,expression,event['values'],two_valued=two_valued) for step,expression in zip(rule.steps,expressions)):
            diagnostics['NO_MATCH'] += 1
            continue
        watermark = watermarks.get(event['scope'],event['time'])
        if not two_valued and event['time'] < watermark-timedelta(seconds=rule.allowed_lateness):
            diagnostics['LATE_OUTSIDE_WINDOW'] += 1
            continue
        diagnostics['LATE_WITHIN_WINDOW' if event['time'] < watermark else 'ON_TIME'] += 1
        watermarks[event['scope']] = max(watermark,event['time'])
        if len(watermarks) > MAX_GROUPS: raise ShadowResourceLimitError('MAX_SOURCE_SCOPES')
        accepted.append(event)
    groups,findings,finding_ids = {},[],set()
    for event in sorted(accepted,key=lambda event:(event['time'],event['id'])):
        check_budget(deadline,cancel_event)
        sid = event['values'].get('user.sid') if 'user.name' in rule.group_by else None
        key = (event['scope'],tuple(str(event['values'][field]).translate(ASCII_NOCASE) for field in rule.group_by),
               ('SID',sid) if sid else ('SCOPED_NAME_ONLY',))
        if key not in groups:
            if len(groups) >= MAX_GROUPS: raise ShadowResourceLimitError('MAX_GROUPS')
            groups[key] = deque()
        queue = groups[key]
        while queue and event['time']-queue[0]['time'] > timedelta(seconds=rule.window_seconds): queue.popleft()
        if len(queue) >= MAX_EVENTS_PER_GROUP: raise ShadowResourceLimitError('MAX_EVENTS_PER_GROUP')
        queue.append(event)
        selected = (_unordered(queue,rule,expressions,deadline,cancel_event) if rule.correlation_mode=='UNORDERED'
                    else _sequence(queue,rule.steps,expressions,two_valued=two_valued))
        if not selected: continue
        confidence = min(rule.confidence,40)
        if confidence < rule.minimum_confidence:
            diagnostics['BELOW_MINIMUM_CONFIDENCE'] += 1
            continue
        evaluation_version = 'm34-shadow-v1' if rule.contract == 'cdrc-v3' else 'm30-shadow-v1'
        key_payload = [evaluation_version,rule.rule_version,key,
                       [item.get('source_key') or [item['id'],item['sha']] for item in selected]]
        identity = hashlib.sha256(canonical_json(key_payload).encode()).hexdigest()
        manifest = hashlib.sha256(canonical_json([(item['id'],item['sha']) for item in selected]).encode()).hexdigest()
        if identity in finding_ids:
            diagnostics['DUPLICATE_FINDING'] += 1
            continue
        finding_ids.add(identity)
        group = {field:str(selected[0]['values'][field]) for field in rule.group_by}
        group['account_identity_basis'] = 'SID' if sid else 'SCOPED_NAME_ONLY_OR_NOT_USED'
        findings.append(ShadowFinding(finding_id='SF-'+identity,rule_id=rule.rule_id,rule_version=rule.rule_version,
            evidence_manifest_sha256=manifest,
            rule_snapshot=rule,evaluation_version=evaluation_version,severity=rule.severity,confidence=confidence,group=group,
            window_start=selected[0]['time'],window_end=selected[-1]['time'],
            explanation=('Observed unordered rule predicates in one claimed endpoint scope. Potential suspicious activity; requires analyst validation.'
                         if rule.correlation_mode=='UNORDERED' else 'Observed ordered rule predicates in one claimed endpoint scope. Potential suspicious activity; requires analyst validation.'),
            uncertainty=('Endpoint/account ownership is not independently verified.','No global source watermark; window/historical continuity UNPROVEN.',
                'Benign retries or approved administration may explain this activity.','Evidence is not pinned; recheck availability on drill-down.'),
            evidence=tuple(FindingEvidence(event_id=item['id'],event_time=item['time'],ingestion_time=item['ingested'],
                source_family=item['family'],host=str(item['values']['host.name']),user=item['values'].get('user.name'),
                process=item['values'].get('process.name'),stored_envelope_sha256=item['sha'],
                event_code=item['values'].get('event.code'),process_guid=item['values'].get('process.guid'),
                user_sid=item['values'].get('user.sid'),
                source_identity_sha256=item['cuse'].source_identity_sha256,
                source_record_key_sha256=item.get('source_key')) for item in selected),
            mitre=tuple(MitreContext(technique_id=value,name=MITRE_TECHNIQUES[value][0],tactic=MITRE_TECHNIQUES[value][1]) for value in rule.mitre_ids)))
        # Consume contributing events; unrelated events remain bounded candidates.
        consumed = {item['id'] for item in selected}
        groups[key] = deque(item for item in queue if item['id'] not in consumed)
        if len(findings) >= MAX_FINDINGS:
            diagnostics['FINDING_LIMIT'] += 1
            break
    return findings,diagnostics


def _graph(findings):
    edges,nodes = [],set()
    for finding in findings:
        nodes.add(finding.finding_id)
        previous = None
        for item in finding.evidence:
            nodes.add(item.event_id)
            edges.append(ChainEdge(source=finding.finding_id,target=item.event_id,relationship='FINDING_SUPPORTED_BY_EVENT'))
            if previous is not None and previous.event_time < item.event_time:
                edges.append(ChainEdge(source=previous.event_id,target=item.event_id,relationship='OBSERVED_BEFORE'))
                if (previous.source_family == item.source_family == 'SYSMON' and previous.event_code == '1'
                        and item.event_code == '3' and previous.process_guid and previous.process_guid == item.process_guid):
                    edges.append(ChainEdge(source=previous.event_id,target=item.event_id,relationship='OBSERVED_SHARED_PROCESS_GUID'))
            previous = item
            if len(nodes) > MAX_GRAPH_NODES or len(edges) > MAX_GRAPH_EDGES:
                raise ShadowResourceLimitError('MAX_GRAPH')
    return edges


@dataclass(frozen=True)
class ShadowSnapshot:
    records:tuple
    manifest:dict
    diagnostics:Counter
    truncated:bool


def snapshot_columns():
    # Derived JSON expressions are query predicates, never physical snapshot
    # columns. Keep the existing sealed row shape and its evidence hashes stable.
    return ','.join(sorted({definition.column[2:] for definition in FIELD_CATALOG.values()
                           if definition.column and definition.attribute_key is None} |
        {'deduplication_id','structured_json','raw_event_json','ingested_at','manager_identity','mitre_ids_json'}))


def _decode_snapshot(rows,truncated,*,include_raw,deadline,cancel_event):
    diagnostics,records,entries,total=Counter(),[],[],0
    for row in rows:
        check_budget(deadline,cancel_event)
        row=dict(row);diagnostics['CANDIDATE_ROWS']+=1
        entries.append({'event_id':row['event_id'],'row_sha256':hashlib.sha256(canonical_json(row).encode()).hexdigest()})
        if not isinstance(row['structured_json'],str) or not isinstance(row['raw_event_json'],str):
            diagnostics['INVALID_EVENT_OR_PROVENANCE']+=1;continue
        total+=len(row['structured_json'].encode())+len(row['raw_event_json'].encode())
        if total>MAX_INPUT_BYTES:raise ShadowResourceLimitError('MAX_INPUT_BYTES')
        try:records.append(_record(row,include_raw=include_raw))
        except ShadowEventError as exc:
            diagnostics[str(exc)]+=1;diagnostics['INVALID_EVENT_OR_PROVENANCE']+=1
        except (ValueError,KeyError,TypeError,RecursionError):diagnostics['INVALID_EVENT_OR_PROVENANCE']+=1
    return ShadowSnapshot(tuple(records),{'version':'m31-bounded-snapshot-v1','entries':entries,'truncated':truncated},diagnostics,truncated)


def _bounded_rows(cursor,deadline,cancel_event):
    rows=[];total=0
    for row in cursor:
        check_budget(deadline,cancel_event)
        if len(rows)==MAX_EVENTS:return rows,True
        total+=sum(len(row[key].encode()) for key in ('structured_json','raw_event_json') if isinstance(row[key],str))
        if total>MAX_INPUT_BYTES:raise ShadowResourceLimitError('MAX_INPUT_BYTES')
        rows.append(row)
    return rows,False


def read_snapshot(payload,repository,*,cancel_event=None,include_raw=False,sealed=None):
    """Reuse original bounded query or validate every row of a sealed recovery set."""
    repository._acquire_slot(cancel_event);connection=None
    try:
        deadline=time.perf_counter()+1.5
        connection=repository._connect();repository._install_deadline(connection,deadline,cancel_event)
        columns=snapshot_columns()
        if sealed is None:
            clauses=[compile_cqql(step.query) for step in payload.rule.steps]
            predicates=' OR '.join('('+item.sql+')' for item in clauses)
            parameters = tuple(value for item in clauses for value in item.parameters)
            if payload.rule.predicate_semantics == 'SIGMA_2VL':
                # SQL NULL/NOT differs from Sigma false-on-missing. Do not lose
                # eligible rows to an unsafe three-valued prefilter. Same bounds.
                predicates,parameters = '1=1',()
            params=(payload.start_time.isoformat(),payload.end_time.isoformat(),payload.evaluation_time.isoformat(),
                *parameters,MAX_EVENTS+1)
            cursor=connection.execute(f'SELECT {columns} FROM security_events WHERE event_id IN ('
                'SELECT e.event_id FROM security_events e INDEXED BY idx_security_events_occurred_id '
                f'WHERE e.occurred_at BETWEEN ? AND ? AND e.ingested_at<=? AND ({predicates}) '
                'ORDER BY e.occurred_at,e.event_id LIMIT ?) ORDER BY ingested_at,event_id',params)
            rows,truncated=_bounded_rows(cursor,deadline,cancel_event)
        else:
            if sealed.get('version')!='m31-bounded-snapshot-v1' or type(sealed.get('truncated')) is not bool:
                raise ShadowResourceLimitError('INVALID_RECOVERY_SNAPSHOT')
            entries=sealed.get('entries',[])
            if len(entries)>MAX_EVENTS:raise ShadowResourceLimitError('MAX_EVENTS')
            expected={entry['event_id']:entry['row_sha256'] for entry in entries}
            if len(expected)!=len(entries):raise ShadowResourceLimitError('INVALID_RECOVERY_SNAPSHOT')
            rows,_=_bounded_rows(connection.execute(f'SELECT {columns} FROM security_events WHERE event_id IN ('+
                ','.join('?' for _ in expected)+') ORDER BY ingested_at,event_id',tuple(expected)),deadline,cancel_event) if expected else ([],False)
            if len(rows)!=len(expected) or any(hashlib.sha256(canonical_json(dict(row)).encode()).hexdigest()!=expected[row['event_id']] for row in rows):
                raise ShadowResourceLimitError('RECOVERY_EVIDENCE_GAP_OR_CHANGE')
            truncated=sealed['truncated']
        return _decode_snapshot(rows,truncated,include_raw=include_raw,deadline=deadline,cancel_event=cancel_event)
    except sqlite3.OperationalError as exc:raise repository._translate_sqlite(exc,cancel_event) from exc
    finally:
        if connection is not None:connection.set_progress_handler(None,0);connection.close()
        repository._slots.release()


def finish_snapshot(payload,snapshot,*,cancel_event=None,started=None):
    started=started if started is not None else time.perf_counter()
    findings,counts=evaluate_records(payload.rule,list(snapshot.records),cancel_event=cancel_event)
    diagnostics=snapshot.diagnostics.copy();diagnostics.update(counts)
    edges=_graph(findings)
    partial=snapshot.truncated or any(diagnostics[key] for key in ('INVALID_EVENT_OR_PROVENANCE','UNSUPPORTED_FIELDS',
        'UNSUPPORTED_SOURCE','LATE_OUTSIDE_WINDOW','FINDING_LIMIT'))
    outcome=('MATCH' if findings else 'UNSUPPORTED_FIELDS' if diagnostics['UNSUPPORTED_FIELDS'] else
        'INVALID_EVENT' if diagnostics['INVALID_EVENT_OR_PROVENANCE'] else 'NO_MATCH')
    return ShadowSimulationResult(status='COMPLETE',outcome=outcome,rule_version=payload.rule.rule_version,findings=tuple(findings),
        graph_edges=tuple(edges),diagnostics=dict(diagnostics),candidate_truncated=snapshot.truncated,
        coverage='PARTIAL' if partial else 'BOUNDED_CANDIDATE_SLICE',execution_ms=round((time.perf_counter()-started)*1000,3))


def simulate(payload:ShadowSimulationRequest,query_repository:CQQLSearchRepository,slots:threading.BoundedSemaphore,*,cancel_event=None):
    from app.services.shadow_rules import validate_mitre
    validate_mitre(payload.rule);started=time.perf_counter()
    if not slots.acquire(blocking=False):raise CQQLQueryBusyError('Shadow evaluation capacity exceeded')
    try:
        if payload.rule.status!='SHADOW_ONLY':
            return ShadowSimulationResult(status='RULE_DISABLED',outcome='RULE_DISABLED',rule_version=payload.rule.rule_version,
                findings=(),graph_edges=(),diagnostics={'RULE_DISABLED':1},candidate_truncated=False,coverage='BOUNDED_CANDIDATE_SLICE',execution_ms=0)
        return finish_snapshot(payload,read_snapshot(payload,query_repository,cancel_event=cancel_event),cancel_event=cancel_event,started=started)
    finally:slots.release()
