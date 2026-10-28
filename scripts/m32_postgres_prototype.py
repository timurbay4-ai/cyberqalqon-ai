"""Linux/WSL existing PostgreSQL only. Own disposable cluster, Unix socket, no TCP.

Transaction proof of concept, NOT a second SIEM backend or full CQQL implementation.
Optional psycopg2/FastAPI are supplied by the existing test environment, not installed.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime,timezone,timedelta
import getpass
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import secrets
import statistics
import subprocess
import sys
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'backend'),str(ROOT/'scripts')]
DDL='''
CREATE TABLE identities(envelope_sha text PRIMARY KEY,event_id text NOT NULL UNIQUE,UNIQUE(event_id,envelope_sha));
CREATE TABLE events(event_id text PRIMARY KEY,envelope_sha text NOT NULL UNIQUE,occurred_at timestamptz NOT NULL,provider text,severity integer NOT NULL CHECK(severity BETWEEN 0 AND 16),normalized jsonb NOT NULL,protected boolean NOT NULL DEFAULT false,FOREIGN KEY(event_id,envelope_sha) REFERENCES identities(event_id,envelope_sha));
CREATE INDEX events_time ON events(occurred_at,event_id);
CREATE TABLE rules(rule_version text PRIMARY KEY,definition jsonb NOT NULL);
CREATE TABLE findings(finding_id text PRIMARY KEY,rule_version text NOT NULL REFERENCES rules(rule_version),revision integer NOT NULL,state text NOT NULL CHECK(state='SHADOW_CANDIDATE'));
CREATE TABLE revisions(finding_id text REFERENCES findings(finding_id),revision integer NOT NULL,content jsonb NOT NULL,PRIMARY KEY(finding_id,revision));
CREATE TABLE evidence(finding_id text NOT NULL,revision integer NOT NULL,event_id text REFERENCES events(event_id) ON DELETE SET NULL,original_event_id text NOT NULL,envelope_sha text NOT NULL,PRIMARY KEY(finding_id,revision,original_event_id),FOREIGN KEY(finding_id,revision) REFERENCES revisions(finding_id,revision),FOREIGN KEY(original_event_id,envelope_sha) REFERENCES identities(event_id,envelope_sha),CHECK(event_id IS NULL OR event_id=original_event_id));
CREATE TABLE audit(sequence bigserial PRIMARY KEY,finding_id text NOT NULL REFERENCES findings(finding_id),reason text NOT NULL);
CREATE TABLE checkpoints(generation text PRIMARY KEY,event_id text NOT NULL REFERENCES identities(event_id));
CREATE FUNCTION protect_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.protected THEN RAISE EXCEPTION 'protected evidence' USING ERRCODE='23514'; END IF; RETURN OLD; END $$;
CREATE TRIGGER protect_delete BEFORE DELETE ON events FOR EACH ROW EXECUTE FUNCTION protect_event();
'''


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);parser.add_argument('--bin',type=Path,default=Path('/usr/lib/postgresql/18/bin'));args=parser.parse_args()
    if os.name!='posix' or os.geteuid()==0:raise RuntimeError('requires existing non-root Linux test user')
    if args.output.exists():raise RuntimeError('OUTPUT_MUST_BE_NEW')
    import psycopg2
    from psycopg2.extras import Json,execute_values
    from fastapi import FastAPI,Header,HTTPException
    from fastapi.testclient import TestClient
    from app.services.wazuh_normalizer import canonical_json
    from app.services.event_normalizer import normalize_wazuh_event
    from m30_synthetic import win
    checks=[];durations=[];started=time.perf_counter();cpu=time.process_time()
    def check(name,value):
        if not value:raise AssertionError(name)
        checks.append(name)
    with tempfile.TemporaryDirectory(prefix='cq-m32-pg-') as raw:
        root=Path(raw);data=root/'data';socket=root/'socket';socket.mkdir(mode=0o700)
        binary=args.bin;server_started=False
        def command(name,*extra):
            return subprocess.run([str(binary/name),*map(str,extra)],check=True,capture_output=True,text=True,timeout=30)
        command('initdb','-D',data,'--auth-local=trust','--auth-host=reject','--encoding=UTF8','--no-locale')
        options=f"-c listen_addresses='' -c unix_socket_directories='{socket}' -c unix_socket_permissions=0700 -c max_connections=12 -c shared_buffers=16MB -c fsync=on -c synchronous_commit=on -c statement_timeout=3000 -c idle_in_transaction_session_timeout=10000"
        def start():command('pg_ctl','-D',data,'-l',root/'server.log','-o',options,'-w','start')
        dsn={'host':str(socket),'dbname':'postgres','user':getpass.getuser(),'connect_timeout':3}
        def connect():return psycopg2.connect(**dsn)
        try:
            start();server_started=True
            with closing(connect()) as c,c:
                with c.cursor() as q:
                    q.execute(DDL);q.execute('SHOW server_version');version=q.fetchone()[0]
                    q.execute('SHOW listen_addresses');check('unix_socket_only_no_tcp',q.fetchone()[0]=='')
                    q.execute('SHOW transaction_isolation');isolation=q.fetchone()[0]
            key=secrets.token_urlsafe(32);app=FastAPI();rule={'id':'SYNTHETIC-PRESENCE-V1','scope':'TRANSACTION_POC_NOT_DETECTION_ENGINE'}
            rule_sha=hashlib.sha256(canonical_json(rule).encode()).hexdigest()
            def authorize(value):
                if not value or not hmac.compare_digest(value,key):raise HTTPException(401,'Invalid test machine key')
            def persist(event,*,failure=False):
                finding='PG-SF-'+hashlib.sha256((rule_sha+event.event_id).encode()).hexdigest()
                with closing(connect()) as c,c:
                    with c.cursor() as q:
                        q.execute('INSERT INTO identities VALUES(%s,%s) ON CONFLICT(envelope_sha) DO NOTHING RETURNING event_id',(event.deduplication_id,event.event_id));new=q.fetchone() is not None
                        if new:
                            q.execute('SELECT COUNT(*) FROM identities');
                            if q.fetchone()[0]>10000:raise RuntimeError('prototype capacity reached')
                            q.execute('INSERT INTO events(event_id,envelope_sha,occurred_at,provider,severity,normalized) VALUES(%s,%s,%s,%s,%s,%s)',(event.event_id,event.deduplication_id,event.timestamp,event.event_provider,event.severity,Json(event.model_dump(mode='json'))))
                            q.execute('INSERT INTO rules VALUES(%s,%s) ON CONFLICT DO NOTHING',(rule_sha,Json(rule)))
                            q.execute('INSERT INTO findings VALUES(%s,%s,1,%s)',(finding,rule_sha,'SHADOW_CANDIDATE'))
                            q.execute('INSERT INTO revisions VALUES(%s,1,%s)',(finding,Json({'identity':'UNVERIFIED','scope':'SYNTHETIC_TRANSACTION_TEST'})))
                            q.execute('INSERT INTO evidence VALUES(%s,1,%s,%s,%s)',(finding,event.event_id,event.event_id,event.deduplication_id))
                            if failure:raise RuntimeError('SYNTHETIC transaction failure before audit')
                            q.execute('INSERT INTO audit(finding_id,reason) VALUES(%s,%s)',(finding,'ATOMIC_SYNTHETIC_COMMIT'))
                            q.execute('INSERT INTO checkpoints VALUES(%s,%s) ON CONFLICT(generation) DO UPDATE SET event_id=EXCLUDED.event_id',('SYNTHETIC-PG-GENERATION',event.event_id))
                        else:
                            q.execute('SELECT event_id FROM identities WHERE envelope_sha=%s',(event.deduplication_id,));check_id=q.fetchone()[0]
                            if check_id!=event.event_id:raise RuntimeError('identity collision')
                        q.execute('SELECT normalized FROM events WHERE event_id=%s',(event.event_id,));retained=q.fetchone() is not None
                return {'event_id':event.event_id,'finding_id':finding,'inserted':new,'availability':'AVAILABLE' if retained else 'MISSING'}
            @app.post('/test/events')
            def ingest_test(body:dict,x_test_key:str|None=Header(None)):
                authorize(x_test_key);event=normalize_wazuh_event(body)
                began=time.perf_counter();value=persist(event);durations.append((time.perf_counter()-began)*1000)
                from fastapi.responses import JSONResponse
                return JSONResponse(value,status_code=201 if value['inserted'] else 200)
            @app.get('/test/findings/{finding_id}')
            def detail(finding_id:str,x_test_key:str|None=Header(None)):
                authorize(x_test_key)
                with closing(connect()) as c,c:
                    with c.cursor() as q:
                        q.execute('SELECT f.state,f.revision,e.original_event_id,e.event_id IS NOT NULL FROM findings f JOIN evidence e USING(finding_id) WHERE f.finding_id=%s ORDER BY e.revision DESC',(finding_id,))
                        rows=q.fetchall()
                if not rows:raise HTTPException(404,'Finding unavailable')
                return {'scope':'SYNTHETIC_SHADOW_POC','rows':rows}
            base=datetime.now(timezone.utc)-timedelta(minutes=3)
            with TestClient(app) as client:
                raw_event=win(320000,base)
                check('authentication_required',client.post('/test/events',json=raw_event).status_code==401)
                first=client.post('/test/events',json=raw_event,headers={'X-Test-Key':key});check('new_201_after_transaction',first.status_code==201)
                duplicate=client.post('/test/events',json=raw_event,headers={'X-Test-Key':key});check('duplicate_200_same_identity',duplicate.status_code==200 and first.json()['event_id']==duplicate.json()['event_id'])
                check('retrieval_and_evidence',client.get('/test/findings/'+first.json()['finding_id'],headers={'X-Test-Key':key}).json()['rows'][0][3] is True)
                same=win(320001,base)
                with ThreadPoolExecutor(max_workers=4) as pool:statuses=list(pool.map(lambda _:client.post('/test/events',json=same,headers={'X-Test-Key':key}).status_code,range(8)))
                check('concurrent_duplicate_suppression',statuses.count(201)==1 and statuses.count(200)==7)
                for index in range(2,22):check('ingest_'+str(index),client.post('/test/events',json=win(320000+index,base+timedelta(seconds=index)),headers={'X-Test-Key':key}).status_code==201)
            failed=normalize_wazuh_event(win(329999,base))
            try:persist(failed,failure=True)
            except RuntimeError:pass
            with closing(connect()) as c,c:
                with c.cursor() as q:
                    q.execute('SELECT COUNT(*) FROM identities WHERE event_id=%s',(failed.event_id,));check('all_table_rollback_no_false_ack',q.fetchone()[0]==0)
                    q.execute('SELECT COUNT(*) FROM events');count=q.fetchone()[0];check('exact_committed_row_count',count==22)
                    q.execute('SELECT COUNT(*) FROM evidence e JOIN events v ON e.event_id=v.event_id WHERE e.envelope_sha!=v.envelope_sha');check('evidence_fingerprints',q.fetchone()[0]==0)
                    # Structured ordering/NULL/time semantics, not a full CQQL port.
                    q.execute('SELECT event_id FROM events WHERE severity>=0 AND occurred_at BETWEEN %s AND %s ORDER BY occurred_at,event_id',(base-timedelta(seconds=1),base+timedelta(minutes=2)));ordered=[r[0] for r in q.fetchall()]
                    check('structured_time_order',len(ordered)==22)
                    q.execute('SELECT event_id FROM events WHERE (occurred_at,event_id)>(SELECT occurred_at,event_id FROM events WHERE event_id=%s) ORDER BY occurred_at,event_id',(ordered[0],));check('keyset_order',len(q.fetchall())==21)
                    q.execute('SELECT COUNT(*) FROM events WHERE provider=NULL');check('sql_null_not_equal',q.fetchone()[0]==0)
                    q.execute('UPDATE events SET protected=true WHERE event_id=%s',(first.json()['event_id'],))
            try:
                with closing(connect()) as c,c:
                    with c.cursor() as q:q.execute('DELETE FROM events WHERE event_id=%s',(first.json()['event_id'],))
            except psycopg2.errors.CheckViolation:checks.append('protected_evidence_delete_blocked')
            else:raise AssertionError('protection missing')
            with closing(connect()) as c,c:
                with c.cursor() as q:
                    q.execute('DELETE FROM events WHERE NOT protected AND event_id=%s',(ordered[-1],))
                    q.execute('SELECT COUNT(*) FROM evidence WHERE event_id IS NULL');check('unpinned_retention_metadata_survives',q.fetchone()[0]==1)
            # Real database deadlock resolution; no blind retry in the HTTP path.
            barrier=threading.Barrier(2)
            def lock_pair(order):
                try:
                    with closing(connect()) as c,c:
                        with c.cursor() as q:
                            q.execute("SET LOCAL lock_timeout='3s'")
                            q.execute('SELECT event_id FROM identities WHERE event_id=%s FOR UPDATE',(order[0],));barrier.wait(timeout=5)
                            q.execute('SELECT event_id FROM identities WHERE event_id=%s FOR UPDATE',(order[1],))
                    return 'COMMITTED'
                except psycopg2.errors.DeadlockDetected:return '40P01_RETRY_ELIGIBLE'
            with ThreadPoolExecutor(max_workers=2) as pool:
                locks=list(pool.map(lock_pair,[(ordered[0],ordered[1]),(ordered[1],ordered[0])]))
            check('deadlock_resolution_and_transaction_cleanup',sorted(locks)==['40P01_RETRY_ELIGIBLE','COMMITTED'])
            # Failed revision does not replace old evidence/history.
            finding=first.json()['finding_id']
            try:
                with closing(connect()) as c,c:
                    with c.cursor() as q:
                        q.execute('UPDATE findings SET revision=2 WHERE finding_id=%s AND revision=1',(finding,))
                        q.execute('INSERT INTO revisions VALUES(%s,2,%s)',(finding,Json({'scope':'SYNTHETIC-FAILED-REVISION'})))
                        raise RuntimeError('SYNTHETIC revision abort')
            except RuntimeError:pass
            with closing(connect()) as c,c:
                with c.cursor() as q:
                    q.execute('SELECT revision FROM findings WHERE finding_id=%s',(finding,));check('revision_rollback_preserves_history',q.fetchone()[0]==1)
                    q.execute('UPDATE findings SET revision=2 WHERE finding_id=%s AND revision=1 RETURNING revision',(finding,));check('revision_cas',q.fetchone()[0]==2)
                    q.execute('INSERT INTO revisions VALUES(%s,2,%s)',(finding,Json({'scope':'SYNTHETIC-REVIEWED-REVISION'})))
                    q.execute('INSERT INTO evidence SELECT finding_id,2,event_id,original_event_id,envelope_sha FROM evidence WHERE finding_id=%s AND revision=1',(finding,))
                    q.execute('INSERT INTO audit(finding_id,reason) VALUES(%s,%s)',(finding,'SYNTHETIC_REVISION'))
            # Real logical backup/restore into another database of this own cluster.
            dump=root/'authority.dump';command('pg_dump','-h',socket,'-U',getpass.getuser(),'-d','postgres','-Fc','-f',dump)
            command('createdb','-h',socket,'-U',getpass.getuser(),'restored')
            command('pg_restore','-h',socket,'-U',getpass.getuser(),'-d','restored','--exit-on-error',dump)
            with closing(psycopg2.connect(**{**dsn,'dbname':'restored'})) as c,c:
                with c.cursor() as q:q.execute('SELECT COUNT(*) FROM identities');check('logical_restore_ack_ledger',q.fetchone()[0]==22)
            pending=connect()
            with pending.cursor() as q:q.execute('INSERT INTO identities VALUES(%s,%s)',('SYNTHETIC-UNCOMMITTED','SYNTHETIC-UNCOMMITTED'))
            command('pg_ctl','-D',data,'-m','immediate','-w','stop');server_started=False;pending.close();start();server_started=True
            with closing(connect()) as c,c:
                with c.cursor() as q:
                    q.execute('SELECT COUNT(*) FROM identities');check('server_crash_recovery_committed_acks',q.fetchone()[0]==22)
                    q.execute('SELECT COUNT(*) FROM identities WHERE event_id=%s',('SYNTHETIC-UNCOMMITTED',));check('server_crash_rolls_back_inflight',q.fetchone()[0]==0)
            server_pid=int((data/'postmaster.pid').read_text().splitlines()[0])
            master_rss=int(Path(f'/proc/{server_pid}/statm').read_text().split()[1])*os.sysconf('SC_PAGE_SIZE')
            report={'scope':'REAL_DISPOSABLE_POSTGRESQL_TRANSACTION_POC','production':'NOT_DEPLOYED','version':version,'driver':psycopg2.__version__,
                'isolation':isolation,'tcp_listener':False,'socket_directory_mode':'0700','checks':checks,'check_count':len(checks),
                'new_events':22,'concurrent_new_201':1,'concurrent_duplicate_200':7,'source_after_unpinned_delete':21,
                'latency_ms':{'samples':len(durations),'p50':statistics.median(durations),'p95':sorted(durations)[max(0,math.ceil(len(durations)*.95)-1)],'maximum':max(durations)},
                'wall_seconds':round(time.perf_counter()-started,3),'driver_cpu_seconds':round(time.process_time()-cpu,3),
                'cluster_disk_bytes':sum(p.stat().st_size for p in data.rglob('*') if p.is_file()),'dump_bytes':dump.stat().st_size,
                'dump_sha256':hashlib.sha256(dump.read_bytes()).hexdigest(),'server_master_rss_bytes_one_sample':master_rss,
                'memory_limit':'Master sample only; total/peak server working set NOT_MEASURED.',
                'semantics_gaps':['No full CQQL compiler','PostgreSQL text tokenizer equivalence NOT_PROVEN','No production migration/benchmark capacity claim','No continuous correlation engine','No hardware power-loss proof'],
                'resource_config':{'shared_buffers':'16MB','max_connections':12,'fsync':True,'synchronous_commit':True}}
            args.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'checks':len(checks),'postgres':version,'production':'NOT_DEPLOYED'}))
        finally:
            if server_started or (data/'postmaster.pid').exists():command('pg_ctl','-D',data,'-m','fast','-w','stop')


if __name__=='__main__':main()
