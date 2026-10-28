"""Strict offline validation of M33 P0 evidence. Never opens any source database."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))
from app.services.request_tracing import accounting


def main():
    parser=argparse.ArgumentParser();parser.add_argument('inputs',nargs='+',type=Path);parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args();errors=[];runs=0;requests=0;total_bytes=0;max_spans=0;http_errors=[]
    for path in args.inputs:
        data=json.loads(path.read_text(encoding='utf-8'))
        for run in data['runs']:
            runs+=1;raw=path.with_name(run['requests_path']);content=raw.read_bytes();total_bytes+=len(content)
            if hashlib.sha256(content).hexdigest()!=run['requests_sha256']:errors.append([run['run_id'],'RAW_CHECKSUM'])
            document=json.loads(content);traces=document['traces'];index={r['request_id']:r for r in traces['requests']}
            diagnostic=document.get('process_diagnostic') or {}
            if diagnostic.get('gc_overflow'):errors.append([run['run_id'],'GC_OBSERVER_OVERFLOW'])
            for event in diagnostic.get('gc_events',[]):
                if set(event)-{'start_ns','end_ns','invoking_request_id','generation','collected','uncollectable'}:
                    errors.append([run['run_id'],'GC_KEYS'])
            if traces['dropped']:errors.append([run['run_id'],'TRACE_DROPPED'])
            for trace in index.values():
                requests+=1;max_spans=max(max_spans,len(trace['spans']))
                if not re.fullmatch('[a-f0-9]{32}',trace['request_id']):errors.append([run['run_id'],'TRACE_ID'])
                if trace['incomplete'] or trace['end_ns'] is None:errors.append([run['run_id'],'TRACE_INCOMPLETE'])
                for i,span in enumerate(trace['spans']):
                    if span['id']!=i or (span['parent'] is not None and not 0<=span['parent']<i):errors.append([run['run_id'],'PARENT'])
                    if span['end_ns'] is None or not trace['start_ns']<=span['start_ns']<=span['end_ns']<=trace['end_ns']:
                        errors.append([run['run_id'],'INTERVAL'])
            for sample in document['samples']:
                if sample['status'] is not None and sample['status']>=400:http_errors.append({'run_id':run['run_id'],'status':sample['status'],'code':sample['code'],'reason':sample['reason']})
                trace=index.get(sample['request_id'])
                if trace is not None and sample.get('accounting')!=accounting(trace,sample['client_start_ns'],sample['client_end_ns']):
                    errors.append([run['run_id'],'ACCOUNTING'])
            # Strict key allowlists prevent accidental future payload/SQL export.
            for trace in index.values():
                if set(trace)-{'request_id','start_ns','end_ns','status','spans','milestones','incomplete'}:errors.append([run['run_id'],'TRACE_KEYS'])
                for span in trace['spans']:
                    if set(span)-{'id','parent','stage','start_ns','end_ns','failed','thread_cpu_ns','resource','connection_id'}:
                        errors.append([run['run_id'],'SPAN_KEYS'])
            for forbidden in (b'SYNTHETIC-M31-BENCH',b'X-API-Key',b'csrf_token',b'raw_payload',b'raw_event_json',b'Cookie',b'SELECT ',b'INSERT INTO '):
                if forbidden in content:errors.append([run['run_id'],'PRIVATE_CONTENT_PATTERN'])
            state=run['result']['integrity']
            if (state['schema']!=17 or state['quick_check']!='ok' or state['foreign_keys'] or state['identity_mismatches'] or
                state['count']!=state['counter'] or state['count']!=state['fts_count'] or state['protected_records']!=8):
                errors.append([run['run_id'],'SOURCE_INTEGRITY'])
            sidecar=run['result'].get('sidecar')
            if sidecar and (sidecar['quick_check']!='ok' or sidecar['foreign_keys']):errors.append([run['run_id'],'SIDECAR_INTEGRITY'])
            if not run['result']['query_slots_recovered']:errors.append([run['run_id'],'SLOTS'])
    report={'gate':'PASS' if not errors else 'FAIL','runs':runs,'traced_requests':requests,'raw_bytes':total_bytes,
            'max_spans_per_request':max_spans,'http_errors':http_errors,'errors':errors,
            'scope':'OFFLINE_JSON_CHECKSUM_PRIVACY_INTERVAL_ACCOUNTING_AND_DISPOSABLE_INTEGRITY_RECEIPTS_ONLY'}
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report))
    return bool(errors)


if __name__=='__main__':raise SystemExit(main())
