"""Owned disposable TCP acceptance fixture for the M35 Go executable.

No live path, endpoint, authentication secret or service is accepted as input.
All source registrations are explicit synthetic constructor bindings.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import argparse

import httpx
import uvicorn

from app.core.config import Settings
from app.db.alerts import AlertRepository
from app.db.shadow_history import initialize, ShadowHistoryRepository
from app.main import create_app
from app.schemas.auth import AnalystCreate, AnalystRole
from app.schemas.collection import SourceBinding

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = 'http://localhost:5173'
PREFIX = '/api/v1/detection-engineering/shadow-v2'


def go_executable() -> Path:
    """Resolve a declared developer tool without depending on a workstation SDK path."""
    candidate = os.environ.get('CYBERQALQON_GO') or shutil.which('go')
    if not candidate or not Path(candidate).is_file():
        raise RuntimeError('Go toolchain required: set CYBERQALQON_GO or add go to the process PATH')
    return Path(candidate).resolve()


def build(output: Path):
    # A newly created caller-owned test directory, never a live deployment path.
    if output.exists() or not output.parent.is_dir():
        raise ValueError('New disposable binary path required')
    go = go_executable()
    env = {**os.environ, 'GOTOOLCHAIN': 'local', 'GOTELEMETRY': 'off', 'GOMAXPROCS': '2', 'GOPROXY': 'off'}
    result = subprocess.run([str(go), 'build', '-p', '1', '-trimpath', '-o', str(output), './cmd/cq-collector'],
                            cwd=ROOT/'collector', env=env, capture_output=True, timeout=180)
    if result.returncode:
        raise RuntimeError('M35 Go build failed; inspect the independent native build receipt')


def body(kind, stream, at, label):
    from scripts.m34_synthetic import envelope
    payload = envelope(stream, source_type=kind, at=at)['payload']
    # Unique synthetic content makes independent input files distinct. A producer
    # generation must never be shared by independent real files without enrollment.
    payload['synthetic_record_label'] = label
    return payload


def checked(response, expected=200):
    if response.status_code != expected:
        raise AssertionError(f'Owned M35 TCP API status {response.status_code}, expected {expected}')
    return response.json()


class Harness:
    def __init__(self, binary: Path):
        self.binary = binary

    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cyberqalqon-m35-GO-SYNTHETIC-', ignore_cleanup_errors=True)
        self.root = Path(self.temp.name)
        self.source = self.root/'owned-source.db'
        self.history = self.root/'owned-history.db'
        self.machine = secrets.token_urlsafe(36)
        self.keys = {kind: secrets.token_urlsafe(36) for kind in ('ZEEK_JSON', 'SURICATA_EVE')}
        self.at = datetime.now(timezone.utc).replace(microsecond=0)-timedelta(minutes=5)
        settings = Settings(database_url='sqlite:///'+self.source.as_posix(), allow_m14_schema_migration=False,
                            wazuh_ingest_api_key=self.machine, ai_enabled=False, correlation_enabled=False,
                            event_batch_ingest_enabled=False)
        AlertRepository(settings.database_url, migration_target_version=17).initialize()
        initialize(self.history, self.source, disposable_only=True)
        store = ShadowHistoryRepository(self.history, self.source)
        bindings = tuple(SourceBinding(source_id=self.source_id(kind), source_type=kind, collector_id='go-jsonl-test',
            source_generation='go-synthetic-generation-v1', sensor_name='SYNTHETIC-GO-M35',
            source_key_sha256=hashlib.sha256(self.keys[kind].encode()).hexdigest()) for kind in self.keys)
        self.app = create_app(settings, disposable_detection_simulation=True, shadow_history=store,
                              disposable_collection_sources=bindings)
        self.server = uvicorn.Server(uvicorn.Config(self.app, host='127.0.0.1', port=0, log_level='critical',
                                                   access_log=False, lifespan='on', ws='none'))
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.base = f'http://127.0.0.1:{self.sock.getsockname()[1]}'
        self.thread = threading.Thread(target=self.server.run, kwargs={'sockets': [self.sock]}, daemon=True)
        self.thread.start()
        self.client = httpx.Client(base_url=self.base, timeout=10, trust_env=False)
        deadline = time.monotonic()+15
        while not self.server.started and time.monotonic()<deadline and self.thread.is_alive():
            time.sleep(.02)
        if not self.server.started:
            self.__exit__(None, None, None)
            raise RuntimeError('Owned TCP fixture failed to start')
        checked(self.client.get('/health'))
        password = secrets.token_urlsafe(32)
        self.app.state.auth_repository.bootstrap_first_admin(AnalystCreate(username='synthetic-go-admin',
            display_name='SYNTHETIC Go acceptance', password=password, role=AnalystRole.ADMIN))
        session = checked(self.client.post('/api/v1/auth/login', headers={'Origin': ORIGIN},
                                          json={'username': 'synthetic-go-admin', 'password': password}))
        self.client.headers.update({'Origin': ORIGIN, 'X-CSRF-Token': session['csrf_token']})
        return self

    def __exit__(self, *_):
        self.client.close()
        self.server.should_exit = True
        self.thread.join(10)
        self.sock.close()
        self.temp.cleanup()
        if self.thread.is_alive():
            raise RuntimeError('Owned TCP fixture did not stop')

    @staticmethod
    def source_id(kind):
        return 'go-zeek' if kind == 'ZEEK_JSON' else 'go-suricata'

    def config(self, label, *, kind='ZEEK_JSON', stream='dns', records=None, raw=None, **budgets):
        root = self.root/label
        result = subprocess.run([str(self.binary), 'init-lab', '--root', str(root)], capture_output=True, timeout=15)
        if result.returncode:
            raise AssertionError('Owned lab initialization failed')
        lab = json.loads(result.stdout)
        path = root/'input.jsonl'
        if raw is None:
            records = records if records is not None else [body(kind, stream, self.at, label)]
            raw = b''.join((json.dumps(row, ensure_ascii=False, separators=(',', ':'))+'\n').encode() for row in records)
        path.write_bytes(raw)
        (root/'ingest.key').write_text(self.machine, encoding='ascii')
        (root/'source.key').write_text(self.keys[kind], encoding='ascii')
        config = {'scope': 'SYNTHETIC_DISPOSABLE_ONLY', 'lab_id': lab['lab_id'], 'lab_root': str(root),
            'source': str(path), 'state_dir': str(root/'spool'), 'source_id': self.source_id(kind),
            'source_type': kind, 'collector_id': 'go-jsonl-test', 'source_generation': 'go-synthetic-generation-v1',
            'stream': stream, 'endpoint': self.base+'/api/v1/collection/events',
            'ingest_key_file': str(root/'ingest.key'), 'source_key_file': str(root/'source.key'),
            'allow_loopback_http': True, 'timeout_ms': 3000, 'backoff_ms': 10, **budgets}
        location = root/'config.json'
        location.write_text(json.dumps(config), encoding='utf-8')
        return location

    def command(self, config, command, *args, expected=0):
        result = subprocess.run([str(self.binary), command, '--config', str(config), *args],
                                capture_output=True, timeout=30)
        if result.returncode != expected:
            # Collector output is restricted to status/static error codes.
            raise AssertionError(f'Go {command} exit={result.returncode} expected={expected}: {result.stderr.decode()}')
        return json.loads(result.stdout.splitlines()[-1]) if result.stdout else None

    @staticmethod
    def state(config):
        return json.loads((config.parent/'spool'/'checkpoint.json').read_bytes())

    def integrity(self):
        result = {}
        for label, path in [('source', self.source), ('history', self.history)]:
            with closing(sqlite3.connect(path.as_uri()+'?mode=ro', uri=True)) as c:
                result[label] = {'schema': c.execute('PRAGMA user_version').fetchone()[0],
                    'quick_check': c.execute('PRAGMA quick_check').fetchone()[0],
                    'foreign_key_violations': len(c.execute('PRAGMA foreign_key_check').fetchall())}
        return result

    def count(self):
        with closing(sqlite3.connect(self.source.as_uri()+'?mode=ro', uri=True)) as c:
            return c.execute('SELECT count(*) FROM security_events').fetchone()[0]


def workflow(binary):
    with Harness(binary) as h:
        statuses = []
        for kind, streams in [('ZEEK_JSON', ('conn', 'dns', 'http', 'ssl')),
                              ('SURICATA_EVE', ('alert', 'dns', 'http', 'tls', 'flow'))]:
            for stream in streams:
                label = kind+'-'+stream
                records = [body(kind, stream, h.at+timedelta(seconds=i), label+str(i))
                           for i in range(3 if kind=='ZEEK_JSON' and stream=='dns' else 1)]
                config = h.config(label, kind=kind, stream='auto' if kind=='SURICATA_EVE' else stream, records=records)
                h.command(config, 'init')
                statuses.append(h.command(config, 'run', '--once', '--max-steps', '64'))
        assert h.count()==11
        start, end = (h.at-timedelta(seconds=1)).isoformat(), (h.at+timedelta(seconds=40)).isoformat()
        search = checked(h.client.post('/api/v1/siem/search', json={
            'query': 'dns.question.name = "synthetic.example.test"', 'start_time': start, 'end_time': end}))
        assert len(search['items'])==4
        event = checked(h.client.get('/api/v1/events/'+search['items'][0]['event_id']))
        preview = checked(h.client.post('/api/v1/detection-engineering/sigma/preview', json={
            'yaml': (ROOT/'examples/sigma/network-dns-repeats.yml').read_text(encoding='utf-8'),
            'profile': 'CQ_ENDPOINT_SHADOW_V1'}))
        run = checked(h.client.post(PREFIX+'/runs', json={'simulation': {
            'rule': preview['rules'][0]['definition'], 'start_time': start, 'end_time': end,
            'evaluation_time': datetime.now(timezone.utc).isoformat()}}))
        assert len(run['result']['finding_ids'])==1
        finding = run['result']['finding_ids'][0]
        detail = checked(h.client.get(PREFIX+'/findings/'+finding))
        workbench = checked(h.client.post('/api/v1/investigations/workbench', json={
            'target_type': 'DURABLE_SHADOW_FINDING', 'target_id': finding, 'shadow_revision': 1,
            'relative_minutes': None, 'start_time': start, 'end_time': end}))
        assert workbench['durable_shadow_context']['finding_id']==finding
        integrity = h.integrity()
        assert integrity['source']['schema']==17 and integrity['history']['schema']==1
        assert all(v['quick_check']=='ok' and v['foreign_key_violations']==0 for v in integrity.values())
        return {'scope': 'SYNTHETIC_DISPOSABLE_GO_TCP_M35', 'production_active': False,
            'historical_continuity': 'UNPROVEN', 'AI_ENABLED': False, 'batch_enabled': False,
            'detections': 'SHADOW_ONLY', 'event_count': h.count(), 'insert_acknowledgements': sum(s['counters']['new_insert_acknowledgements'] for s in statuses),
            'cqql_dns_events': len(search['items']), 'shadow_findings': 1, 'integrity': integrity,
            'collector_statuses': statuses, 'cuse_event': event, 'shadow_run': run,
            'finding_detail': detail, 'workbench_finding_id': workbench['durable_shadow_context']['finding_id']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
        parser.error('New evidence file with existing parent required')
    with tempfile.TemporaryDirectory(prefix='cyberqalqon-m35-GO-SYNTHETIC-build-') as name:
        binary = Path(name)/'cq-collector.exe'
        build(binary)
        result = workflow(binary)
        result['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
    with args.output.open('x', encoding='utf-8') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    print(json.dumps({k: result[k] for k in ('scope', 'event_count', 'insert_acknowledgements', 'cqql_dns_events', 'shadow_findings')}))


if __name__ == '__main__':
    main()
