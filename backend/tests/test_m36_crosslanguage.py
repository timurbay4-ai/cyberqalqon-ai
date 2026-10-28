"""An explicit analyst handoff joins the existing synthetic collector and case APIs."""
from contextlib import closing
from datetime import datetime, timedelta, timezone
import sqlite3
from pathlib import Path

from scripts.m35_go_synthetic import Harness, body, checked, PREFIX, ROOT
from tests.test_m35_go_collector import binary


def test_go_finding_workbench_to_explicit_case_evidence_and_audit(binary):
    assert ROOT==Path(__file__).resolve().parents[2]
    with Harness(binary) as h:
        records=[body('ZEEK_JSON','dns',h.at+timedelta(seconds=i),'M36-'+str(i)) for i in range(3)]
        config=h.config('M36-explicit-analyst',records=records)
        h.command(config,'init')
        result=h.command(config,'run','--once','--max-steps','32')
        assert result['counters']['new_insert_acknowledgements']==3
        start=(h.at-timedelta(seconds=1)).isoformat();end=(h.at+timedelta(seconds=40)).isoformat()
        search=checked(h.client.post('/api/v1/siem/search',json={
            'query':'dns.question.name = "synthetic.example.test"','start_time':start,'end_time':end}))
        assert len(search['items'])==3
        preview=checked(h.client.post('/api/v1/detection-engineering/sigma/preview',json={
            'yaml':(ROOT/'examples/sigma/network-dns-repeats.yml').read_text(encoding='utf-8'),
            'profile':'CQ_ENDPOINT_SHADOW_V1'}))
        run=checked(h.client.post(PREFIX+'/runs',json={'simulation':{
            'rule':preview['rules'][0]['definition'],'start_time':start,'end_time':end,
            'evaluation_time':datetime.now(timezone.utc).isoformat()}}))
        finding=run['result']['finding_ids'][0]
        workbench=checked(h.client.post('/api/v1/investigations/workbench',json={
            'target_type':'DURABLE_SHADOW_FINDING','target_id':finding,'shadow_revision':1,
            'relative_minutes':None,'start_time':start,'end_time':end}))
        assert workbench['durable_shadow_context']['finding_id']==finding
        assert checked(h.client.get('/api/v1/cases'))['total']==0
        payload={'title':'SYNTHETIC M36 analyst handoff','severity':'HIGH','priority':'HIGH'}
        assert h.client.post('/api/v1/cases',headers={'X-CSRF-Token':''},json=payload).status_code==403
        assert checked(h.client.get('/api/v1/cases'))['total']==0
        case=checked(h.client.post('/api/v1/cases',json=payload),201)
        event_id=search['items'][0]['event_id']
        acquired=checked(h.client.post('/api/v1/cases/'+case['case_id']+'/evidence',json={
            'reference_type':'EVENT','reference_id':event_id,'expected_version':case['version'],
            'annotation':'Explicit analyst reference from the synthetic shadow investigation'}),201)
        evidence=acquired['evidence'][0]
        assert evidence['reference_id']==event_id and evidence['integrity_status']=='VERIFIED'
        assert evidence['digest_algorithm']=='SHA-256' and len(evidence['digest'])==64
        assert evidence['custody'][0]['event_type']=='ACQUIRED'
        with closing(sqlite3.connect(h.source)) as connection:
            audits=connection.execute('SELECT action,actor_id FROM security_audit_events WHERE target_id=?',(case['case_id'],)).fetchall()
            assert {'CASE_CREATED','CASE_EVIDENCE_ACQUIRED'}<={row[0] for row in audits}
            assert len({row[1] for row in audits})==1 and audits[0][1]
        assert all(v['quick_check']=='ok' and not v['foreign_key_violations'] for v in h.integrity().values())
