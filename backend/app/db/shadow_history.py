"""Explicitly initialized M31 sidecar. NEVER migrates the source event database."""
from __future__ import annotations
import base64
import hashlib
import json
import sqlite3
import time
import uuid
from contextlib import closing,contextmanager
from datetime import datetime,timezone
from pathlib import Path
from app.schemas.shadow_detection import ShadowRule,ShadowFinding
from app.schemas.shadow_history import DurableEvaluationRequest,FindingTransition,IdentityAssessment,AuthorityInventory
from app.services.wazuh_normalizer import canonical_json
from app.services.shadow_intent import create_intent, validate_intent

MAX_RUNS=2048
MAX_FINDINGS=2048
MAX_REVISIONS=8192
MAX_DB_BYTES=268435456
SCHEMA=(
 'CREATE TABLE shadow_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL CHECK(version=1),store_id TEXT NOT NULL,source_binding TEXT NOT NULL)',
 'CREATE TABLE shadow_rules(rule_version TEXT PRIMARY KEY,rule_id TEXT NOT NULL,definition TEXT NOT NULL CHECK(length(definition)<=24000))',
 'CREATE TABLE shadow_authorities(authority_sha TEXT PRIMARY KEY,document TEXT NOT NULL CHECK(length(document)<=270000))',
 "CREATE TABLE shadow_runs(run_id TEXT PRIMARY KEY,request_key TEXT NOT NULL UNIQUE,request_json TEXT NOT NULL CHECK(length(request_json)<=30000),owner TEXT,status TEXT NOT NULL CHECK(status IN ('RUNNING','COMPLETED','FAILED','CANCELLED')),attempts INTEGER NOT NULL CHECK(attempts BETWEEN 1 AND 3),snapshot_json TEXT,snapshot_sha TEXT,result_json TEXT,result_sha TEXT,error_code TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)",
 'CREATE INDEX shadow_runs_order ON shadow_runs(created_at DESC,run_id DESC)',
 "CREATE TABLE shadow_findings(finding_id TEXT PRIMARY KEY,matching_id TEXT NOT NULL,rule_version TEXT NOT NULL REFERENCES shadow_rules(rule_version),policy_sha TEXT NOT NULL,current_revision INTEGER NOT NULL,state TEXT NOT NULL CHECK(state IN ('SHADOW_CANDIDATE','SHADOW_CONFIRMED_MATCH','INCOMPLETE_EVIDENCE','SUPERSEDED','EXPIRED','INVALIDATED')),created_at TEXT NOT NULL,last_observed_at TEXT NOT NULL)",
 'CREATE INDEX shadow_findings_order ON shadow_findings(created_at DESC,finding_id DESC)',
 'CREATE TABLE shadow_revisions(finding_id TEXT NOT NULL REFERENCES shadow_findings(finding_id),revision INTEGER NOT NULL,match_json TEXT NOT NULL,identity_json TEXT NOT NULL,content_sha TEXT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(finding_id,revision))',
 'CREATE TABLE shadow_evidence(finding_id TEXT NOT NULL,revision INTEGER NOT NULL,event_id TEXT NOT NULL,envelope_sha TEXT NOT NULL,row_sha TEXT NOT NULL,PRIMARY KEY(finding_id,revision,event_id),FOREIGN KEY(finding_id,revision) REFERENCES shadow_revisions(finding_id,revision))',
 'CREATE TABLE shadow_run_findings(run_id TEXT NOT NULL REFERENCES shadow_runs(run_id),finding_id TEXT NOT NULL REFERENCES shadow_findings(finding_id),revision INTEGER NOT NULL,PRIMARY KEY(run_id,finding_id),FOREIGN KEY(finding_id,revision) REFERENCES shadow_revisions(finding_id,revision))',
 'CREATE TABLE shadow_transitions(sequence INTEGER PRIMARY KEY,finding_id TEXT NOT NULL,revision INTEGER NOT NULL,previous_state TEXT,target_state TEXT NOT NULL,reason TEXT NOT NULL,actor TEXT NOT NULL,occurred_at TEXT NOT NULL,superseded_by TEXT REFERENCES shadow_findings(finding_id),FOREIGN KEY(finding_id,revision) REFERENCES shadow_revisions(finding_id,revision))',
 'CREATE INDEX shadow_transition_lookup ON shadow_transitions(finding_id,sequence)',
 'CREATE TABLE security_audit_events(audit_id TEXT PRIMARY KEY,action TEXT NOT NULL,actor_id TEXT,actor_display TEXT NOT NULL,target_type TEXT NOT NULL,target_id TEXT,outcome TEXT NOT NULL,occurred_at TEXT NOT NULL,details_json TEXT NOT NULL)',
 'CREATE INDEX shadow_audit_order ON security_audit_events(occurred_at DESC,audit_id DESC)',
)


class ShadowStoreError(RuntimeError):
    def __init__(self,code,*,run_id=None):super().__init__(code);self.run_id=run_id


def sha(value):return hashlib.sha256(canonical_json(value).encode()).hexdigest()
def now():return datetime.now(timezone.utc).isoformat()


def source_binding(path:Path):
    try:path=path.resolve(strict=True);stat=path.stat()
    except OSError:raise ShadowStoreError('SOURCE_DATABASE_UNAVAILABLE') from None
    return sha([str(path),stat.st_dev,stat.st_ino])


def initialize(path:Path,source:Path,*,disposable_only:bool=False):
    if disposable_only is not True:raise ShadowStoreError('DISPOSABLE_MIGRATION_REQUIRED')
    if Path(path).is_symlink():raise ShadowStoreError('INVALID_SIDECAR_PATH')
    path,source=Path(path).resolve(),Path(source).resolve(strict=True)
    if path==source or path.exists() and path.samefile(source):raise ShadowStoreError('INVALID_SIDECAR_PATH')
    binding=source_binding(source)
    with closing(sqlite3.connect(source.as_uri()+'?mode=ro',uri=True)) as event_db:
        if event_db.execute('PRAGMA user_version').fetchone()[0]!=17:raise ShadowStoreError('SOURCE_SCHEMA_NOT_17')
    with closing(sqlite3.connect(path)) as connection:
        existing=connection.execute('PRAGMA user_version').fetchone()[0]
        if existing==1:
            ShadowHistoryRepository(path,source).verify();return
        if existing or connection.execute("SELECT 1 FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchone():
            raise ShadowStoreError('UNRECOGNIZED_SIDECAR')
        connection.execute('PRAGMA journal_mode=WAL');connection.execute('PRAGMA synchronous=FULL')
        try:
            connection.execute('BEGIN IMMEDIATE')
            for statement in SCHEMA:connection.execute(statement)
            connection.execute('INSERT INTO shadow_meta VALUES(1,1,?,?)',(uuid.uuid4().hex,binding))
            connection.execute('PRAGMA user_version=1');connection.commit()
        except BaseException:connection.rollback();raise
    path.chmod(0o600)
    ShadowHistoryRepository(path,source).verify()


class ShadowHistoryRepository:
    def __init__(self,path:Path,source:Path):
        self.path,self.source=Path(path).resolve(strict=True),Path(source).resolve(strict=True)
        if self.path==self.source:raise ShadowStoreError('INVALID_SIDECAR_PATH')
        self.binding=source_binding(self.source)
        self.owner=uuid.uuid4().hex
        self.verify()

    def _connect(self):
        if source_binding(self.source)!=self.binding:raise ShadowStoreError('SOURCE_DATABASE_REPLACED')
        connection=sqlite3.connect(self.path,timeout=.1)
        try:
            connection.row_factory=sqlite3.Row
            connection.execute('PRAGMA foreign_keys=ON');connection.execute('PRAGMA busy_timeout=100')
            connection.execute('PRAGMA synchronous=FULL')
            row=connection.execute('SELECT store_id,source_binding FROM shadow_meta WHERE singleton=1').fetchone()
            if row is None or row['source_binding']!=self.binding:raise ShadowStoreError('SOURCE_BINDING_MISMATCH')
            if hasattr(self,'store_id') and row['store_id']!=self.store_id:raise ShadowStoreError('SIDECAR_REPLACED')
            return connection
        except BaseException:connection.close();raise

    def verify(self):
        with closing(self._connect()) as c:
            if c.execute('PRAGMA user_version').fetchone()[0]!=1:raise ShadowStoreError('SHADOW_SCHEMA_MISMATCH')
            row=c.execute('SELECT * FROM shadow_meta WHERE singleton=1').fetchone()
            if row is None or row['source_binding']!=self.binding:raise ShadowStoreError('SOURCE_BINDING_MISMATCH')
            expected={statement.split()[2].split('(')[0]:' '.join(statement.split()).lower() for statement in SCHEMA}
            actual={row['name']:' '.join(row['sql'].split()).lower() for row in c.execute("SELECT name,sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'")}
            if actual!=expected:raise ShadowStoreError('SHADOW_SCHEMA_MISMATCH')
            self.store_id=row['store_id']

    @contextmanager
    def transaction(self):
        try:
            with closing(self._connect()) as c,c:
                deadline=time.perf_counter()+.25
                c.set_progress_handler(lambda:int(time.perf_counter()>=deadline),1000)
                c.execute('BEGIN IMMEDIATE')
                yield c
        except sqlite3.Error as exc:
            code='SHADOW_STORE_BUSY' if getattr(exc,'sqlite_errorcode',None) in (sqlite3.SQLITE_BUSY,sqlite3.SQLITE_LOCKED) else 'SHADOW_STORE_WRITE_FAILED'
            raise ShadowStoreError(code) from exc

    @staticmethod
    def _capacity(c,*,run=False,finding=False,revision=False):
        for table,limit,adding in (('shadow_runs',MAX_RUNS,run),('shadow_findings',MAX_FINDINGS,finding),('shadow_revisions',MAX_REVISIONS,revision)):
            if c.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]+int(adding)>limit:raise ShadowStoreError('SHADOW_CAPACITY_EXCEEDED')
        if c.execute('PRAGMA page_count').fetchone()[0]*c.execute('PRAGMA page_size').fetchone()[0]>MAX_DB_BYTES:
            raise ShadowStoreError('SHADOW_CAPACITY_EXCEEDED')

    @staticmethod
    def _audit(c,actor,action,target,code):
        c.execute('INSERT INTO security_audit_events VALUES(?,?,?,?,?,?,?,?,?)',
            (uuid.uuid4().hex,action,None,actor[:128],'shadow_run',target,'SUCCESS',now(),canonical_json({'reason_code':code})))
        c.execute('DELETE FROM security_audit_events WHERE audit_id IN (SELECT audit_id FROM security_audit_events ORDER BY occurred_at DESC,audit_id DESC LIMIT -1 OFFSET 10000)')

    def find_request(self,request,authority_sha):
        key=sha([self.store_id,{'payload':request.model_dump(mode='json'),'authority_sha':authority_sha}])
        with closing(self._connect()) as c:
            row=c.execute('SELECT run_id FROM shadow_runs WHERE request_key=?',(key,)).fetchone()
        return self.run(row['run_id']) if row else None

    def begin(self,request:DurableEvaluationRequest,actor:str,authority_sha=None,authority_document=None,*,manifest=None):
        body={'payload':request.model_dump(mode='json'),'authority_sha':authority_sha};key=sha([self.store_id,body]);stamp=now()
        if manifest is not None:
            body={**body,'recovery_intent':create_intent(self.store_id,self.binding,body,manifest)}
        encoded=canonical_json(body)
        if len(encoded)>30000:raise ShadowStoreError('SHADOW_REQUEST_TOO_LARGE')
        with self.transaction() as c:
            row=c.execute('SELECT * FROM shadow_runs WHERE request_key=?',(key,)).fetchone()
            if row is not None:return dict(row),False
            self._capacity(c,run=True)
            if authority_sha:
                if authority_document is None or sha(authority_document['inventory'])!=authority_sha:raise ShadowStoreError('INVALID_AUTHORITY_DOCUMENT')
                if not c.execute('SELECT 1 FROM shadow_authorities WHERE authority_sha=?',(authority_sha,)).fetchone():
                    if c.execute('SELECT COUNT(*) FROM shadow_authorities').fetchone()[0]>=64:raise ShadowStoreError('SHADOW_CAPACITY_EXCEEDED')
                    c.execute('INSERT INTO shadow_authorities VALUES(?,?)',(authority_sha,canonical_json(authority_document)))
            run_id='RUN-'+uuid.uuid4().hex
            c.execute('INSERT INTO shadow_runs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (run_id,key,encoded,self.owner,'RUNNING',1,None,None,None,None,None,stamp,stamp))
            self._audit(c,actor,'SHADOW_RUN_BEGIN',run_id,'RUNNING')
            if manifest is not None:self._audit(c,actor,'SHADOW_INTENT_COMMIT',run_id,'BOUNDED_SNAPSHOT_WITNESS')
            self._capacity(c)
            return dict(c.execute('SELECT * FROM shadow_runs WHERE run_id=?',(run_id,)).fetchone()),True

    def run(self,run_id):
        with closing(self._connect()) as c:
            row=c.execute('SELECT * FROM shadow_runs WHERE run_id=?',(run_id,)).fetchone()
            if row is None:raise ShadowStoreError('RUN_NOT_FOUND')
            value=dict(row)
            try:
                stored=json.loads(value['request_json']);request=DurableEvaluationRequest.model_validate(stored['payload'])
                base={'payload':stored['payload'],'authority_sha':stored['authority_sha']}
                if set(stored)-{'payload','authority_sha','recovery_intent'}:raise ValueError()
                if sha([self.store_id,base])!=value['request_key']:raise ValueError()
                intent=stored.get('recovery_intent')
                if intent is not None:validate_intent(self.store_id,self.binding,base,intent)
                if value['snapshot_json'] is not None and sha(json.loads(value['snapshot_json']))!=value['snapshot_sha']:raise ValueError()
                if value['snapshot_json'] is not None and intent is not None and value['snapshot_sha']!=intent['manifest_sha256']:raise ValueError()
                if value['result_json'] is not None and sha(json.loads(value['result_json']))!=value['result_sha']:raise ValueError()
                value['request']=request;value['authority_sha']=stored['authority_sha'];value['recovery_intent']=intent
            except (ValueError,TypeError):raise ShadowStoreError('SHADOW_STORE_CORRUPT') from None
            return value

    def claim(self,run_id,actor,*,manifest=None,expected_attempts=None):
        with self.transaction() as c:
            row=c.execute('SELECT * FROM shadow_runs WHERE run_id=?',(run_id,)).fetchone()
            if row is None:raise ShadowStoreError('RUN_NOT_FOUND')
            if row['status']=='COMPLETED':return False
            # The caller holds the OS-exclusive owner lock AND serialized mutation
            # admission. A prior request may have failed before recording FAILED.
            if expected_attempts is not None and row['attempts']!=expected_attempts:raise ShadowStoreError('RUN_STATE_CONFLICT')
            unsealed=row['snapshot_json'] is None
            if unsealed:
                try:
                    stored=json.loads(row['request_json']);base={'payload':stored['payload'],'authority_sha':stored['authority_sha']}
                    if sha([self.store_id,base])!=row['request_key']:raise ValueError('request binding')
                    intent=validate_intent(self.store_id,self.binding,base,stored.get('recovery_intent'))
                except (ValueError,TypeError,KeyError):raise ShadowStoreError('UNSEALED_RECOVERY_BLOCKED') from None
                if manifest is None:raise ShadowStoreError('UNSEALED_VERIFICATION_REQUIRED')
                if sha(manifest)!=intent['manifest_sha256']:raise ShadowStoreError('UNSEALED_SOURCE_SET_CHANGED')
            elif manifest is not None:raise ShadowStoreError('RUN_STATE_CONFLICT')
            if row['attempts']>=3:raise ShadowStoreError('RUN_ATTEMPTS_EXHAUSTED')
            snapshot=canonical_json(manifest) if unsealed else row['snapshot_json']
            if len(snapshot.encode())>262144:raise ShadowStoreError('SNAPSHOT_TOO_LARGE')
            changed=c.execute("UPDATE shadow_runs SET owner=?,status='RUNNING',attempts=attempts+1,error_code=NULL,updated_at=?,snapshot_json=?,snapshot_sha=? WHERE run_id=? AND attempts=? AND status=? AND snapshot_sha IS ?",
                (self.owner,now(),snapshot,sha(manifest) if unsealed else row['snapshot_sha'],run_id,row['attempts'],row['status'],row['snapshot_sha']))
            if changed.rowcount!=1:raise ShadowStoreError('RUN_STATE_CONFLICT')
            self._audit(c,actor,'SHADOW_RUN_RESUME',run_id,'VERIFIED_UNSEALED_INTENT' if unsealed else 'SEALED_SNAPSHOT_REEVALUATION')
            return True

    def recovery_headers(self):
        with closing(self._connect()) as c:
            return [dict(row) for row in c.execute("SELECT run_id,status,attempts,error_code,created_at,snapshot_json IS NOT NULL AS sealed,json_extract(request_json,'$.recovery_intent.version') IS NOT NULL AS has_recovery_intent FROM shadow_runs WHERE status!='COMPLETED' ORDER BY created_at DESC,run_id DESC LIMIT 20")]

    def seal(self,run_id,manifest,actor='shadow owner'):
        body=canonical_json(manifest)
        if len(body.encode())>262144:raise ShadowStoreError('SNAPSHOT_TOO_LARGE')
        with self.transaction() as c:
            row=c.execute('SELECT request_json FROM shadow_runs WHERE run_id=?',(run_id,)).fetchone()
            if row is None:raise ShadowStoreError('RUN_NOT_FOUND')
            stored=json.loads(row['request_json']);intent=stored.get('recovery_intent')
            if intent is not None:
                try:validate_intent(self.store_id,self.binding,{'payload':stored['payload'],'authority_sha':stored['authority_sha']},intent)
                except (ValueError,TypeError):raise ShadowStoreError('SHADOW_STORE_CORRUPT') from None
                if sha(manifest)!=intent['manifest_sha256']:raise ShadowStoreError('UNSEALED_SOURCE_SET_CHANGED')
            result=c.execute("UPDATE shadow_runs SET snapshot_json=?,snapshot_sha=?,updated_at=? WHERE run_id=? AND owner=? AND status='RUNNING' AND snapshot_json IS NULL",
                (body,sha(manifest),now(),run_id,self.owner))
            if result.rowcount!=1:raise ShadowStoreError('RUN_STATE_CONFLICT')
            self._audit(c,actor,'SHADOW_SNAPSHOT_SEAL',run_id,'SEALED_BOUND_CANDIDATES')

    def fail(self,run_id,code,*,cancelled=False):
        with self.transaction() as c:
            c.execute("UPDATE shadow_runs SET status=?,error_code=?,updated_at=? WHERE run_id=? AND owner=? AND status='RUNNING'",
                ('CANCELLED' if cancelled else 'FAILED',code[:128],now(),run_id,self.owner))

    def complete(self,run_id,request,result,assessments,actor):
        if len(result.findings)!=len(assessments):raise ShadowStoreError('ASSESSMENT_COUNT_MISMATCH')
        stamp=now();ids=[];node_map={};allowed_events=set()
        with self.transaction() as c:
            row=c.execute('SELECT * FROM shadow_runs WHERE run_id=?',(run_id,)).fetchone()
            if row is None or row['owner']!=self.owner or row['status']!='RUNNING':raise ShadowStoreError('RUN_STATE_CONFLICT')
            manifest=json.loads(row['snapshot_json']);rows={entry['event_id']:entry['row_sha256'] for entry in manifest['entries']}
            rule=request.simulation.rule
            c.execute('INSERT OR IGNORE INTO shadow_rules VALUES(?,?,?)',(rule.rule_version,rule.rule_id,canonical_json(rule.model_dump(mode='json'))))
            for finding,assessment in zip(result.findings,assessments):
                if not assessment.satisfied:continue
                policy_sha=sha([assessment.policy.model_dump(mode='json'),
                    sorted({entity.authority_sha256 for entity in assessment.entities if entity.authority_sha256})])
                finding_id='DSF-'+sha(['m31-shadow-v1',self.store_id,finding.finding_id,policy_sha])
                identity=assessment.model_dump(mode='json');match=finding.model_dump(mode='json');match.pop('rule_snapshot')
                content_sha=sha([match,identity])
                old=c.execute('SELECT * FROM shadow_findings WHERE finding_id=?',(finding_id,)).fetchone()
                revision=1 if old is None else old['current_revision']
                previous=None if old is None else c.execute('SELECT content_sha FROM shadow_revisions WHERE finding_id=? AND revision=?',(finding_id,revision)).fetchone()[0]
                if old is None:
                    self._capacity(c,finding=True,revision=True)
                    c.execute('INSERT INTO shadow_findings VALUES(?,?,?,?,?,?,?,?)',
                        (finding_id,finding.finding_id,rule.rule_version,policy_sha,1,'SHADOW_CANDIDATE',stamp,stamp))
                if previous!=content_sha:
                    if old is not None:revision+=1;self._capacity(c,revision=True)
                    c.execute('INSERT INTO shadow_revisions VALUES(?,?,?,?,?,?)',
                        (finding_id,revision,canonical_json(match),canonical_json(identity),content_sha,stamp))
                    for evidence in finding.evidence:
                        c.execute('INSERT INTO shadow_evidence VALUES(?,?,?,?,?)',
                            (finding_id,revision,evidence.event_id,evidence.stored_envelope_sha256,rows[evidence.event_id]))
                    state='SHADOW_CANDIDATE' if old is None else old['state']
                    c.execute('INSERT INTO shadow_transitions VALUES(NULL,?,?,?,?,?,?,?,NULL)',
                        (finding_id,revision,None if old is None else state,state,'INITIAL_MATCH' if old is None else 'EVIDENCE_REVISION',actor[:128],stamp))
                c.execute('UPDATE shadow_findings SET current_revision=?,last_observed_at=? WHERE finding_id=?',(revision,stamp,finding_id))
                c.execute('INSERT INTO shadow_run_findings VALUES(?,?,?)',(run_id,finding_id,revision));ids.append(finding_id)
                node_map[finding.finding_id]=finding_id;allowed_events.update(item.event_id for item in finding.evidence)
            summary={'finding_ids':ids,'diagnostics':result.diagnostics,'coverage':result.coverage,
                'identity_rejected':sum(not assessment.satisfied for assessment in assessments),
                'candidate_count':len(result.findings),'historical_continuity':'UNPROVEN','window_completeness':'UNPROVEN',
                'evaluation_version':'m31-shadow-v1','graph_edges':[
                    {**edge.model_dump(),'source':node_map.get(edge.source,edge.source),'target':node_map.get(edge.target,edge.target)}
                    for edge in result.graph_edges if edge.source in node_map.keys()|allowed_events and edge.target in node_map.keys()|allowed_events]}
            c.execute("UPDATE shadow_runs SET status='COMPLETED',result_json=?,result_sha=?,updated_at=? WHERE run_id=?",(canonical_json(summary),sha(summary),stamp,run_id))
            self._audit(c,actor,'SHADOW_RUN_COMPLETE',run_id,'DURABLE_COMMIT')
            self._capacity(c)
        return summary

    def page(self,*,limit=20,cursor=None):
        if type(limit) is not int or not 1<=limit<=50:raise ShadowStoreError('INVALID_LIMIT')
        params=[];predicate=''
        if cursor:
            try:
                if len(cursor)>512:raise ValueError()
                decoded=json.loads(base64.urlsafe_b64decode(cursor+'='*(-len(cursor)%4)))
                if len(decoded)!=3 or decoded[0]!=self.store_id or not all(isinstance(x,str) for x in decoded):raise ValueError()
                predicate='WHERE (created_at,finding_id)<(?,?)';params=decoded[1:]
            except (ValueError,TypeError):raise ShadowStoreError('INVALID_CURSOR') from None
        with closing(self._connect()) as c:
            rows=[dict(row) for row in c.execute('SELECT * FROM shadow_findings '+predicate+' ORDER BY created_at DESC,finding_id DESC LIMIT ?',(*params,limit+1))]
        more=len(rows)>limit;rows=rows[:limit]
        token=base64.urlsafe_b64encode(canonical_json([self.store_id,rows[-1]['created_at'],rows[-1]['finding_id']]).encode()).decode().rstrip('=') if more else None
        return {'items':rows,'next_cursor':token,'scope':'DISPOSABLE_DURABLE_SHADOW','production_active':False}

    def detail(self,finding_id,revision=None):
        with closing(self._connect()) as c:
            header=c.execute('SELECT * FROM shadow_findings WHERE finding_id=?',(finding_id,)).fetchone()
            if header is None:raise ShadowStoreError('FINDING_NOT_FOUND')
            revision=revision or header['current_revision']
            row=c.execute('SELECT * FROM shadow_revisions WHERE finding_id=? AND revision=?',(finding_id,revision)).fetchone()
            if row is None:raise ShadowStoreError('REVISION_NOT_FOUND')
            try:
                rule=ShadowRule.model_validate_json(c.execute('SELECT definition FROM shadow_rules WHERE rule_version=?',(header['rule_version'],)).fetchone()[0])
                match=json.loads(row['match_json']);identity=json.loads(row['identity_json']);IdentityAssessment.model_validate(identity)
                if rule.rule_version!=header['rule_version'] or sha([match,identity])!=row['content_sha']:raise ValueError()
                match['rule_snapshot']=rule.model_dump(mode='json');ShadowFinding.model_validate(match)
                if 'DSF-'+sha(['m31-shadow-v1',self.store_id,match['finding_id'],header['policy_sha']])!=finding_id:raise ValueError()
            except (ValueError,TypeError):raise ShadowStoreError('SHADOW_STORE_CORRUPT') from None
            evidence=[dict(value) for value in c.execute('SELECT event_id,envelope_sha,row_sha FROM shadow_evidence WHERE finding_id=? AND revision=? ORDER BY event_id',(finding_id,revision))]
            if ({value['event_id']:value['envelope_sha'] for value in evidence}!=
                    {value['event_id']:value['stored_envelope_sha256'] for value in match['evidence']} or header['matching_id']!=match['finding_id']):
                raise ShadowStoreError('SHADOW_STORE_CORRUPT')
            history=[dict(value) for value in c.execute('SELECT * FROM shadow_transitions WHERE finding_id=? ORDER BY sequence DESC LIMIT 51',(finding_id,))]
            authorities=[]
            for authority_sha in sorted({entity['authority_sha256'] for entity in identity['entities'] if entity['authority_sha256']}):
                document_row=c.execute('SELECT document FROM shadow_authorities WHERE authority_sha=?',(authority_sha,)).fetchone()
                if document_row is None:raise ShadowStoreError('SHADOW_STORE_CORRUPT')
                document=json.loads(document_row[0]);AuthorityInventory.model_validate(document['inventory'])
                if sha(document['inventory'])!=authority_sha:raise ShadowStoreError('SHADOW_STORE_CORRUPT')
                authorities.append(document)
            return {**dict(header),'revision':revision,'matching_evidence':match,'identity':identity,
                'authority_documents':authorities,'first_observed_at':header['created_at'],
                'evidence_references':evidence,'history':history[:50],'history_truncated':len(history)>50,
                'historical_continuity':'UNPROVEN','production_active':False,'scope':'DISPOSABLE_DURABLE_SHADOW',
                'evidence_retention':'REFERENCES_NOT_AUTOMATIC_PINS'}

    def transition(self,finding_id,change:FindingTransition,actor,*,evidence_available=False):
        allowed={'SHADOW_CANDIDATE':{'SHADOW_CONFIRMED_MATCH','INCOMPLETE_EVIDENCE','SUPERSEDED','EXPIRED','INVALIDATED'},
            'SHADOW_CONFIRMED_MATCH':{'INCOMPLETE_EVIDENCE','SUPERSEDED','EXPIRED','INVALIDATED'},
            'INCOMPLETE_EVIDENCE':{'SHADOW_CONFIRMED_MATCH','SUPERSEDED','EXPIRED','INVALIDATED'}}
        with self.transaction() as c:
            row=c.execute('SELECT * FROM shadow_findings WHERE finding_id=?',(finding_id,)).fetchone()
            if row is None:raise ShadowStoreError('FINDING_NOT_FOUND')
            if row['current_revision']!=change.expected_revision or row['state']!=change.expected_state:raise ShadowStoreError('REVISION_CONFLICT')
            if change.target not in allowed.get(row['state'],set()):raise ShadowStoreError('INVALID_STATE_TRANSITION')
            if change.target=='SHADOW_CONFIRMED_MATCH' and not evidence_available:raise ShadowStoreError('EVIDENCE_UNAVAILABLE')
            if change.target=='SUPERSEDED':
                other=c.execute('SELECT f.rule_version,f.state,r.rule_id FROM shadow_findings f JOIN shadow_rules r USING(rule_version) WHERE finding_id=?',(change.superseded_by,)).fetchone()
                own_rule=c.execute('SELECT rule_id FROM shadow_rules WHERE rule_version=?',(row['rule_version'],)).fetchone()[0]
                if (other is None or change.superseded_by==finding_id or other['rule_version']==row['rule_version']
                        or other['rule_id']!=own_rule or other['state'] not in allowed):raise ShadowStoreError('INVALID_SUPERSESSION')
            c.execute('UPDATE shadow_findings SET state=? WHERE finding_id=?',(change.target,finding_id))
            c.execute('INSERT INTO shadow_transitions VALUES(NULL,?,?,?,?,?,?,?,?)',
                (finding_id,row['current_revision'],row['state'],change.target,change.reason,actor[:128],now(),change.superseded_by))
            self._audit(c,actor,'SHADOW_FINDING_TRANSITION',finding_id,change.target)
        return self.detail(finding_id)


def rollback_empty(path:Path,source:Path,*,disposable_only=False):
    if disposable_only is not True:raise ShadowStoreError('DISPOSABLE_MIGRATION_REQUIRED')
    repo=ShadowHistoryRepository(path,source)
    with repo.transaction() as c:
        if c.execute('SELECT COUNT(*) FROM shadow_runs').fetchone()[0]:raise ShadowStoreError('ACKNOWLEDGED_HISTORY_ROLLBACK_BLOCKED')
        for name in ('shadow_audit_order','shadow_transition_lookup','shadow_findings_order','shadow_runs_order'):c.execute('DROP INDEX '+name)
        for name in ('shadow_transitions','shadow_run_findings','shadow_evidence','shadow_revisions','shadow_findings','shadow_runs','shadow_rules','shadow_authorities','security_audit_events','shadow_meta'):
            c.execute('DROP TABLE '+name)
        c.execute('PRAGMA user_version=0')
