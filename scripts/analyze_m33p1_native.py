"""Offline native-boundary evidence checks; no database or host process access."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import statistics


def analyze(path):
    report = json.loads(path.read_text(encoding='utf-8'))
    rows = []
    for run in report['runs']:
        raw = json.loads(path.with_name(run['requests_path']).read_text(encoding='utf-8'))
        index = {r['request_id']:r for r in raw['traces']['requests']}
        probe = (raw.get('process_diagnostic') or {}).get('native_probe')
        if probe is None:
            continue
        if probe['overflow']:
            raise ValueError('Native observation is incomplete')
        calls = defaultdict(list)
        for call in probe['native_calls']:
            trace = index[call['request_id']]
            if not trace['start_ns'] <= call['start_ns'] <= call['end_ns'] <= trace['end_ns']:
                raise ValueError('Native interval outside owning trace')
            if call['counter_delta'] and any(v < 0 for v in call['counter_delta'].values()):
                raise ValueError('Non-monotonic counter evidence')
            if set(call) != {'request_id','connection_id','resource','thread_id','stage','start_ns','end_ns',
                             'failed','transaction_before','transaction_after','counter_delta'}:
                raise ValueError('Native privacy key drift')
            calls[call['request_id']].append(call)
        ingest = []
        for sample in raw['samples']:
            if sample['kind'] != 'INGEST':
                continue
            own = calls[sample['request_id']]
            stages = defaultdict(float)
            for c in own:
                stages[c['stage']] += (c['end_ns']-c['start_ns'])/1e6
            late = [max(0,(r['actual_ns']-r['expected_ns'])/1e6) for r in probe['event_loop_lateness']
                    if r['request_id'] == sample['request_id']]
            ingest.append({'request_id':sample['request_id'], 'status':sample['status'],
                           'http_ms':sample['wall_ms'], 'stage_inclusive_ms':dict(stages),
                           'max_observed_loop_lateness_ms':max(late,default=None),
                           'native_calls':own, 'fts_alone_ms':None, 'fsync_ms':None, 'exclusive_lock_wait_ms':None})
        writer = [r for r in ingest if r['status'] == 201]
        duplicate = [r for r in ingest if r['status'] == 200]
        rows.append({'run_id':run['run_id'],'size':run['size'],'mode':run['mode'],'variant':run['variant'],
                     'experiment':run['experiment'],'p95_ms':run['result']['writer'].get('p95_ms'),
                     'duplicate_p95_ms':run['result']['duplicate_http'].get('p95_ms'),
                     'native_calls':len(probe['native_calls']),
                     'slow_new':sorted(writer,key=lambda r:r['http_ms'],reverse=True)[:max(1,len(writer)//5)],
                     'fast_new':sorted(writer,key=lambda r:r['http_ms'])[:max(1,len(writer)//5)],
                     'slow_duplicate':sorted(duplicate,key=lambda r:r['http_ms'],reverse=True)[:max(1,len(duplicate)//5)],
                     'reuse':(raw.get('process_diagnostic') or {}).get('connection_reuse'),
                     'build_measurements':report.get('p1_instrumentation',{}).get('build_measurements')})
    return rows


def main():
    parser=argparse.ArgumentParser();parser.add_argument('inputs',nargs='+',type=Path)
    parser.add_argument('--output',required=True,type=Path);args=parser.parse_args()
    runs=[row for path in args.inputs for row in analyze(path)]
    result={'gate':'PASS_OBSERVATIONS_VALIDATED_NOT_CAUSAL_ACCEPTANCE','runs':runs,
            'limits':'Native wrappers include trace overhead; process I/O is shared; cycles are not milliseconds; no external lock owner, fsync syscall or scheduler switch proof.'}
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'validated_runs':len(runs),'gate':result['gate']}))


if __name__=='__main__':main()
