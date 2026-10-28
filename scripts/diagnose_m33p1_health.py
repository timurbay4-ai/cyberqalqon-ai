"""Three fixed cold/warm health controls; never replaces the failed full test."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import threading
import time

from fastapi.testclient import TestClient
from app.core.config import Settings
from app.main import create_app
from app.services.request_tracing import TraceCollector, accounting
from m30_synthetic import win
from m33_request_trace import installed
from tests.conftest import bootstrap_and_login


def run(output):
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError('New evidence path required')
    result = {'scope':'THREE_FIXED_DISPOSABLE_COLD_WARM_DIAGNOSTICS_NOT_TEST_ACCEPTANCE',
              'original_failed_health_ms':625.0, 'unchanged_test_limit_ms':500, 'runs':[]}
    for repeat in range(3):
        with tempfile.TemporaryDirectory(prefix='cyberqalqon-p1-health-') as temporary:
            collector = TraceCollector()
            app = create_app(Settings(database_url='sqlite:///'+(Path(temporary)/'SYNTHETIC.db').as_posix(),
                ai_enabled=False, correlation_enabled=False, allow_m14_schema_migration=False,
                event_batch_ingest_enabled=False, wazuh_ingest_api_key='SYNTHETIC-HEALTH-P1'),
                disposable_detection_simulation=True, disposable_request_traces=collector)
            with installed(), TestClient(app) as client:
                bootstrap_and_login(client);collector.clear_completed()
                repository = app.state.event_repository;original = repository.ingest
                entered, release = threading.Event(), threading.Event()
                def blocked(event):
                    entered.set()
                    if not release.wait(15):
                        raise RuntimeError('Owned diagnostic release deadline')
                    return original(event)
                repository.ingest = blocked
                samples = []
                try:
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        writer = pool.submit(client.post, '/api/v1/events/ingest',
                            headers={'X-API-Key':'SYNTHETIC-HEALTH-P1'},
                            json=win(996000+repeat,datetime.now(timezone.utc),'4688'))
                        if not entered.wait(10):
                            release.set()
                            raise RuntimeError('Owned worker startup deadline')
                        try:
                            for phase in ('COLD_HEALTH_ROUTE','WARM_HEALTH_ROUTE'):
                                start=time.perf_counter_ns();response=client.get('/health');end=time.perf_counter_ns()
                                samples.append({'phase':phase,'request_id':response.headers['x-perf-trace-id'],
                                    'start_ns':start,'end_ns':end,'http_ms':(end-start)/1e6,'status':response.status_code,
                                    'writer_still_blocked':not writer.done()})
                        finally:
                            release.set()
                        accepted = writer.result(timeout=15).status_code
                finally:
                    release.set();repository.ingest=original
                traces=collector.export();index={r['request_id']:r for r in traces['requests']}
                for sample in samples:
                    sample['accounting']=accounting(index[sample['request_id']],sample['start_ns'],sample['end_ns'])
                if accepted!=201 or not all(s['status']==200 and s['writer_still_blocked'] for s in samples):
                    raise RuntimeError('Health independence diagnostic failed')
                result['runs'].append({'repeat':repeat,'ingest_status':accepted,'health':samples,'traces':traces})
        output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'scope':result['scope'],'health_ms':[[s['http_ms'] for s in r['health']] for r in result['runs']]}))


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();run(args.output)
