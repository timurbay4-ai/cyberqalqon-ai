"""Real executable/TCP/SQLite acceptance; every resource is owned and synthetic."""
import hashlib
import json
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import threading
import subprocess

import pytest
import httpx

from scripts.m35_go_synthetic import Harness, build, body, workflow
from scripts.m35_go_synthetic import ROOT


@pytest.fixture(scope='module')
def binary(tmp_path_factory, record_testsuite_property):
    path = tmp_path_factory.mktemp('m35-GO-SYNTHETIC-binary')/'cq-collector.exe'
    build(path)
    files = [*sorted((ROOT/'collector').rglob('*.go')), ROOT/'collector/go.mod',
             ROOT/'collector/testdata/python-canonical.json', Path(__file__), ROOT/'scripts/m35_go_synthetic.py']
    record_testsuite_property('m35_source_sha256', json.dumps({str(p.relative_to(ROOT).as_posix()):
        hashlib.sha256(p.read_bytes()).hexdigest() for p in files}, sort_keys=True))
    record_testsuite_property('go_binary_sha256', hashlib.sha256(path.read_bytes()).hexdigest())
    import sqlite3
    record_testsuite_property('sqlite_version', sqlite3.sqlite_version)
    return path


def test_go_fastapi_cuse_sqlite_cqql_shadow_workbench(binary):
    result = workflow(binary)
    assert result['insert_acknowledgements']==result['event_count']==11
    assert result['cqql_dns_events']==4 and result['shadow_findings']==1
    assert result['production_active'] is False


@pytest.mark.parametrize('stage', ['AFTER_SOURCE_READ', 'AFTER_STATE_WRITE', 'AFTER_STATE_SYNC',
    'AFTER_STATE_COMMIT', 'AFTER_SPOOL_COMMIT', 'BEFORE_HTTP_SEND', 'AFTER_HTTP_RESPONSE',
    'AFTER_ACK_VERIFIED', 'AFTER_ACK_COMMIT'])
def test_executable_hard_crash_recovery_without_duplicate_rows(binary, stage):
    with Harness(binary) as h:
        config = h.config('crash-'+stage)
        h.command(config, 'init')
        h.command(config, 'run', '--once', '--max-steps', '16', '--crash-at', stage, expected=27)
        old = h.state(config)['body']
        assert old['acknowledged_offset']<=old['read_offset']
        before = hashlib.sha256((config.parent/'spool'/'checkpoint.json').read_bytes()).hexdigest()
        observed = h.command(config, 'status')
        assert observed['in_flight']==old['in_flight']
        assert hashlib.sha256((config.parent/'spool'/'checkpoint.json').read_bytes()).hexdigest()==before
        result = h.command(config, 'run', '--once', '--max-steps', '32')
        size = (config.parent/'input.jsonl').stat().st_size
        assert result['read_offset']==result['acknowledged_offset']==size
        assert result['acknowledged_offset']>=old['acknowledged_offset']
        assert result['pending_spool_records']==0 and h.count()==1
        counts = result['counters']
        assert counts['enqueued']==counts['new_insert_acknowledgements']+counts['duplicate_acknowledgements']==1
        if stage in {'AFTER_HTTP_RESPONSE', 'AFTER_ACK_VERIFIED'}:
            assert counts['unknown_outcomes']==counts['duplicate_acknowledgements']==1
        integrity = h.integrity()
        assert all(v['quick_check']=='ok' and not v['foreign_key_violations'] for v in integrity.values())


@pytest.mark.parametrize('kind', ['replace', 'truncate', 'rewrite', 'corrupt-checkpoint', 'truncate-unread', 'rewrite-unread'])
def test_executable_source_or_state_corruption_fail_closed(binary, kind):
    with Harness(binary) as h:
        config = h.config('source-'+kind, records=[body('ZEEK_JSON', 'dns', h.at, kind+str(i)) for i in range(2)])
        h.command(config, 'init')
        h.command(config, 'spool', '--max-steps', '1')
        source = config.parent/'input.jsonl'
        state = config.parent/'spool'/'checkpoint.json'
        if kind=='replace':
            source.rename(source.with_suffix('.old'))
            source.write_bytes(b'{}\n')
        elif kind=='truncate':
            source.write_bytes(b'')
        elif kind=='rewrite':
            source.write_bytes(source.read_bytes().replace(b'SYNTHETIC', b'MUTATED!!'))
        elif kind=='truncate-unread':
            with source.open('r+b') as f:
                f.truncate(h.state(config)['body']['read_offset'])
        elif kind=='rewrite-unread':
            with source.open('r+b') as f:
                f.seek(h.state(config)['body']['read_offset']+10)
                f.write(b'X')
        else:
            state.write_bytes(b'corrupt')
        before = hashlib.sha256(state.read_bytes()).hexdigest()
        h.command(config, 'run', '--once', expected=2)
        assert hashlib.sha256(state.read_bytes()).hexdigest()==before
        assert h.count()==0


def test_executable_partial_corrupt_and_bounded_queue(binary):
    with Harness(binary) as h:
        row = json.dumps(body('ZEEK_JSON', 'dns', h.at, 'partial')).encode()
        config = h.config('partial', raw=row)
        h.command(config, 'init')
        status = h.command(config, 'run', '--once')
        assert status['read_offset']==0 and h.count()==0
        source = config.parent/'input.jsonl'
        with source.open('ab') as f:
            f.write(b'\nnot-json\n'+row+b'\n')
        result = h.command(config, 'run', '--once', expected=2)
        assert result['acknowledged_offset']==len(row)+1
        assert result['read_offset']==len(row)+1 and result['counters']['malformed_records']==1 and h.count()==1
        result = h.command(config, 'run', '--once', expected=2)
        assert result['counters']['malformed_records']==1 and h.count()==1
        bounded = h.config('bounded', records=[body('ZEEK_JSON', 'dns', h.at, str(i)) for i in range(8)], max_queue_records=2)
        h.command(bounded, 'init')
        status = h.command(bounded, 'spool', '--max-steps', '64')
        assert status['pending_spool_records']==2 and status['acknowledged_offset']==0
        assert status['read_offset']<(bounded.parent/'input.jsonl').stat().st_size
        status = h.command(bounded, 'run', '--once', '--max-steps', '64')
        assert status['pending_spool_records']==0 and h.count()==9


def test_executable_auth_gate_preserves_spool(binary):
    with Harness(binary) as h:
        config = h.config('auth')
        # Valid distinct scoped key file but not the registered server key.
        (config.parent/'source.key').write_text('SYNTHETIC-UNREGISTERED-KEY-000000000000000', encoding='ascii')
        h.command(config, 'init')
        result = h.command(config, 'run', '--once', expected=2)
        assert result['acknowledged_offset']==0 and result['pending_spool_records']==1
        assert result['delivery_block']=='AUTHENTICATION_REQUIRED' and h.count()==0


@pytest.mark.parametrize('stage', ['AFTER_STATE_WRITE', 'AFTER_STATE_SYNC', 'AFTER_STATE_COMMIT'])
def test_executable_initial_state_publication_crash(binary, stage):
    with Harness(binary) as h:
        config = h.config('initial-'+stage)
        h.command(config, 'init', '--crash-at', stage, expected=27)
        result = h.command(config, 'run', '--once', '--max-steps', '32')
        assert result['acknowledged_offset']==(config.parent/'input.jsonl').stat().st_size and h.count()==1


def test_executable_retry_commit_crash_keeps_rejected_record(binary):
    with Harness(binary) as h:
        config = h.config('retry-commit')
        (config.parent/'source.key').write_text('SYNTHETIC-UNREGISTERED-KEY-000000000000000', encoding='ascii')
        h.command(config, 'init')
        h.command(config, 'run', '--once', '--crash-at', 'AFTER_RETRY_COMMIT', expected=27)
        result = h.command(config, 'run', '--once', expected=2)
        assert result['acknowledged_offset']==0 and result['pending_spool_records']==1
        assert result['counters']['delivery_rejections']==2 and result['counters']['enqueued']==1 and h.count()==0


def test_real_fastapi_commit_then_wire_disconnect_retries_duplicate(binary):
    with Harness(binary) as h:
        outcomes = []

        class DisconnectOnce(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass  # Never log URLs, headers, source content or credentials.

            def do_POST(self):
                size = int(self.headers.get('Content-Length', '0'))
                if self.path!='/api/v1/collection/events' or not 0<size<262144:
                    self.send_error(400)
                    return
                content = self.rfile.read(size)
                with httpx.Client(timeout=5, trust_env=False) as upstream:
                    response = upstream.post(h.base+'/api/v1/collection/events', content=content,
                        headers={'Content-Type': 'application/json', 'X-API-Key': self.headers.get('X-API-Key', ''),
                                 'X-Source-Key': self.headers.get('X-Source-Key', '')})
                outcomes.append(response.status_code)
                if len(outcomes)==1:
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                self.send_response(response.status_code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(response.content)))
                self.end_headers()
                self.wfile.write(response.content)

        proxy = ThreadingHTTPServer(('127.0.0.1', 0), DisconnectOnce)
        thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        try:
            config = h.config('real-lost-response')
            values = json.loads(config.read_text(encoding='utf-8'))
            values['endpoint'] = f'http://127.0.0.1:{proxy.server_port}/api/v1/collection/events'
            config.write_text(json.dumps(values), encoding='utf-8')
            h.command(config, 'init')
            result = h.command(config, 'run', '--once', '--max-steps', '32')
            assert outcomes==[201, 200] and h.count()==1
            assert result['counters']['unknown_outcomes']==1
            assert result['counters']['new_insert_acknowledgements']==0
            assert result['counters']['duplicate_acknowledgements']==1
            assert result['pending_spool_records']==0
        finally:
            proxy.shutdown()
            proxy.server_close()
            thread.join(5)
            assert not thread.is_alive()


def test_two_executable_processes_cannot_own_same_checkpoint(binary):
    with Harness(binary) as h:
        entered, release = threading.Event(), threading.Event()

        class Stall(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers['Content-Length']))
                entered.set()
                release.wait(8)
                self.send_response(503)
                self.end_headers()

        server = ThreadingHTTPServer(('127.0.0.1', 0), Stall)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        process = None
        try:
            config = h.config('two-processes', max_attempts=1, timeout_ms=5000)
            values = json.loads(config.read_text(encoding='utf-8'))
            values['endpoint'] = f'http://127.0.0.1:{server.server_port}/api/v1/collection/events'
            config.write_text(json.dumps(values), encoding='utf-8')
            h.command(config, 'init')
            process = subprocess.Popen([str(binary), 'run', '--config', str(config), '--once'],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert entered.wait(5)
            state = config.parent/'spool'/'checkpoint.json'
            before = hashlib.sha256(state.read_bytes()).hexdigest()
            status = h.command(config, 'status')
            assert status['in_flight'] is True
            assert hashlib.sha256(state.read_bytes()).hexdigest()==before
            other = subprocess.run([str(binary), 'run', '--config', str(config), '--once'],
                                   capture_output=True, timeout=15)
            assert other.returncode==2 and json.loads(other.stderr)['error_code']=='OWNER_LOCKED'
            assert hashlib.sha256(state.read_bytes()).hexdigest()==before
            release.set()
            process.communicate(timeout=15)
            assert process.returncode==2 and h.count()==0
            assert h.command(config, 'status')['pending_spool_records']==1
        finally:
            release.set()
            if process is not None and process.poll() is None:
                process.terminate()  # Only the owned disposable child process.
                process.communicate(timeout=10)
            server.shutdown()
            server.server_close()
            thread.join(5)
