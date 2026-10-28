"""M33 Mode A: actual application layers, self-created SYNTHETIC storage only.

python -m app.cli.rc_demo --output <new-sanitized-report.json>
No URL, database, credentials, archive, or runtime configuration arguments exist.
"""
from __future__ import annotations

import argparse
import gc
import hashlib
import json
import secrets
import sqlite3
import tempfile
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.db.alerts import AlertRepository
from app.db.shadow_history import initialize, ShadowHistoryRepository
from app.db.fts_rowid import install as install_disposable_fts
from app.main import create_app
from app.schemas.auth import AnalystCreate, AnalystRole
from app.services.shadow_rules import catalog
from app.services.shadow_continuity import prepare, ShadowContinuityWorker
from app.services.shadow_backup import capture_pair, restore_offline

PREFIX = '/api/v1/detection-engineering/shadow-v2'
ORIGIN = 'http://localhost:5173'


def _json(response, status=200):
    if response.status_code != status:
        # Never emit a failed login payload, session, raw event, or API key.
        raise RuntimeError(f'M33 isolated contract failure: HTTP {response.status_code}, expected {status}')
    return response.json()


def _login(client, username, password):
    session = _json(client.post('/api/v1/auth/login', headers={'Origin': ORIGIN},
                               json={'username': username, 'password': password}))
    client.headers.update({'Origin': ORIGIN, 'X-CSRF-Token': session['csrf_token']})


def run_demo():
    import sys
    root = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(root / 'scripts'))
    from m30_synthetic import auth, ssh

    with tempfile.TemporaryDirectory(prefix='cyberqalqon-m33-SYNTHETIC-', ignore_cleanup_errors=True) as temporary:
        directory = Path(temporary)
        source = directory / 'source.db'
        key, password = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        settings = Settings(database_url=f'sqlite:///{source.as_posix()}',
                            wazuh_ingest_api_key=key, ai_enabled=False, correlation_enabled=False,
                            event_batch_ingest_enabled=False, allow_m14_schema_migration=False)
        AlertRepository(settings.database_url, migration_target_version=17).initialize()
        install_disposable_fts(source, directory/'before-fts.db', disposable_only=True)
        sidecar = directory / 'history.db'
        initialize(sidecar, source, disposable_only=True)
        store = ShadowHistoryRepository(sidecar, source)
        base = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=20)
        app = create_app(settings, disposable_detection_simulation=True, disposable_fts_rowid=True, shadow_history=store)
        with TestClient(app) as client:
            app.state.auth_repository.bootstrap_first_admin(AnalystCreate(
                username='synthetic-admin', display_name='SYNTHETIC M33 admin', password=password, role=AnalystRole.ADMIN))
            _login(client, 'synthetic-admin', password)
            for username, role in [('synthetic-analyst', 'ANALYST'), ('synthetic-viewer', 'VIEWER')]:
                _json(client.post('/api/v1/auth/analysts', json={'username': username,
                    'display_name': 'SYNTHETIC M33', 'password': password, 'role': role}), 201)
            _login(client, 'synthetic-analyst', password)
            raw_events = auth(base) + [ssh(100 + i, base + timedelta(seconds=i*10), i == 3) for i in range(4)]
            accepted = []
            for raw in raw_events:
                response = _json(client.post('/api/v1/events/ingest', headers={'X-API-Key': key}, json=raw), 201)
                accepted.append(response['event']['event_id'])
            for raw in raw_events:
                _json(client.post('/api/v1/events/ingest', headers={'X-API-Key': key}, json=raw), 200)
            # Human sessions cannot substitute for machine credentials.
            assert client.post('/api/v1/events/ingest', json=raw_events[0]).status_code == 401
            query = {'query': 'event.code = "4625" OR event.category = "linux_ssh"',
                     'start_time': (base-timedelta(seconds=1)).isoformat(),
                     'end_time': (base+timedelta(minutes=1)).isoformat(), 'limit': 100, 'sort': 'oldest'}
            search = _json(client.post('/api/v1/siem/search', json=query))
            assert len(search['items']) == 7
            assert {row['event_id'] for row in search['items']} <= set(accepted)
            fts = _json(client.post('/api/v1/siem/search', json={**query, 'query': 'text CONTAINS "SYNTHETIC"'}))
            assert {row['event_id'] for row in fts['items']} == set(accepted)
            first = _json(client.get('/api/v1/events/' + accepted[0]))
            assert datetime.fromisoformat(first['timestamp'].replace('Z', '+00:00')) == datetime.fromisoformat(raw_events[0]['timestamp'])
            assert first['cuse']['source_family'] == 'WINDOWS_EVENTCHANNEL'
            assert first['event_code'] == '4625'
            assert first['hostname'] == 'SYNTH-M30-WINDOWS'
            runs = []
            for rule_id in ('SHADOW-WINDOWS-AUTH', 'SHADOW-SSH-AUTH'):
                rule = next(row for row in catalog() if row.rule_id == rule_id)
                _json(client.post(PREFIX + '/validate', json=rule.model_dump(mode='json')))
                body = {'simulation': {'rule': rule.model_dump(mode='json'),
                    'start_time': query['start_time'], 'end_time': query['end_time'],
                    'evaluation_time': datetime.now(timezone.utc).isoformat()}}
                run = _json(client.post(PREFIX + '/runs', json=body))
                again = _json(client.post(PREFIX + '/runs', json=body))
                assert run['run_id'] == again['run_id']
                assert len(run['result']['finding_ids']) == 1
                runs.append(run)
            finding_id = runs[0]['result']['finding_ids'][0]
            finding = _json(client.get(PREFIX + '/findings/' + finding_id))
            assert finding['revision'] == 1 and finding['matching_evidence']['mitre']
            target = {'target_type': 'DURABLE_SHADOW_FINDING', 'target_id': finding_id,
                      'shadow_revision': 1, 'relative_minutes': None,
                      'start_time': query['start_time'], 'end_time': query['end_time']}
            workbench = _json(client.post('/api/v1/investigations/workbench', json=target))
            assert workbench['durable_shadow_context']['finding_id'] == finding_id
            assert workbench['primary_event']['event_id'] in accepted
            # No automatic case/incident; only the following explicit analyst action.
            with closing(sqlite3.connect(source)) as connection:
                assert connection.execute('SELECT COUNT(*) FROM soc_cases').fetchone()[0] == 0
                assert connection.execute('SELECT COUNT(*) FROM incidents').fetchone()[0] == 0
            case = _json(client.post('/api/v1/cases', json={'title': 'SYNTHETIC M33 investigation',
                'description': finding_id, 'severity': 'HIGH', 'priority': 'HIGH'}), 201)
            case_id = case['case_id']
            case = _json(client.post(f'/api/v1/cases/{case_id}/related/event', json={
                'reference_id': accepted[0], 'expected_version': case['version']}), 201)
            case = _json(client.post(f'/api/v1/cases/{case_id}/comments', json={
                'body': 'Synthetic matched pattern; continuity UNPROVEN.', 'expected_version': case['version']}), 201)
            case = _json(client.post(f'/api/v1/cases/{case_id}/evidence', json={
                'reference_type': 'EVENT', 'reference_id': accepted[0], 'annotation': finding_id,
                'expected_version': case['version']}), 201)
            case = _json(client.post(f'/api/v1/cases/{case_id}/status', json={
                'status': 'TRIAGING', 'expected_version': case['version']}))
            # Verify the stored source after the explicit evidence workflow.
            with closing(sqlite3.connect(source)) as connection:
                source_integrity = connection.execute('PRAGMA quick_check').fetchone()[0]
                foreign_keys = len(connection.execute('PRAGMA foreign_key_check').fetchall())
                schema = connection.execute('PRAGMA user_version').fetchone()[0]
                actions = [row[0] for row in connection.execute('SELECT DISTINCT action FROM security_audit_events ORDER BY action')]
                count = connection.execute('SELECT COUNT(*) FROM security_events').fetchone()[0]
            assert source_integrity == 'ok' and foreign_keys == 0 and schema == 17 and count == 8
            assert any('CASE' in action for action in actions)
            operations = _json(client.get('/api/v1/operations/overview'))
            assert operations['storage_retention']['max_records'] == 100000
            assert operations['storage_retention']['retention_days'] == 30
            assert operations['archive_backlog']['state'] == 'UNAVAILABLE'
            assert operations['archive_backlog']['current_lag_bytes'] is None
            assert operations['ingestion_performance']['inserted'] == operations['ingestion_performance']['duplicates'] == 8
            # Schedule independent finite windows over existing durable evaluation.
            checkpoint = directory / 'evaluation-checkpoint.db'
            rule = next(row for row in catalog() if row.rule_id == 'SHADOW-WINDOWS-AUTH')
            service = app.state.shadow_history_service
            preparation = prepare(checkpoint, service, rule, first_end=base+timedelta(seconds=60),
                                  ticks=2, disposable_only=True)
            worker = ShadowContinuityWorker(checkpoint, service, rule, disposable_only=True)
            scheduler = [worker.tick(), worker.tick(), worker.tick()]
            assert scheduler[-1]['status'] == 'COMPLETE' and scheduler[-1]['remaining_ticks'] == 0
            receipt = capture_pair(service, directory/'backup', disposable_only=True)
            restored = restore_offline(directory/'backup', directory/'restore', receipt['manifest_sha256'], disposable_only=True)
            _login(client, 'synthetic-viewer', password)
            assert client.post('/api/v1/investigations/workbench', json=target).status_code == 200
            assert client.post('/api/v1/cases', json={'title': 'Forbidden'}).status_code == 403
            assert client.post(PREFIX + '/runs', json=body).status_code == 403
            assert client.get(PREFIX + '/findings/' + finding_id).status_code == 200
            _login(client, 'synthetic-analyst', password)
            headers = dict(client.headers)
            client.headers.pop('X-CSRF-Token')
            assert client.post('/api/v1/investigations/workbench', json=target).status_code == 403
            client.headers.update(headers)
            assert client.post('/api/v1/investigations/workbench', json=target, headers={'Origin': 'https://untrusted.invalid'}).status_code == 403
            _json(client.get('/health'))
            report = {'scope': 'SYNTHETIC_DISPOSABLE_FULL_APPLICATION', 'production': 'NOT_DEPLOYED',
                'source_schema': schema, 'source_count': count, 'accepted_201': 8, 'duplicate_200': 8,
                'fts_strategy': 'm32_rowid', 'fts_complete_ids': len(fts['items']),
                'findings': 2, 'finding_revision': 1, 'cases_explicit': 1, 'incidents': 0,
                'source_quick_check': source_integrity, 'foreign_key_violations': foreign_keys,
                'historical_continuity': 'UNPROVEN', 'real_collection': 'NOT_LIVE_VALIDATED',
                'scheduler_preparation': preparation, 'scheduler': scheduler,
                'backup_restore': restored['status'], 'audit_actions': actions,
                'security': {'machine_key_isolated': True, 'viewer_mutation_denied': True,
                             'viewer_read_workbench_allowed': True,
                             'csrf_required': True, 'origin_required': True},
                'contract': {'finding': finding, 'workbench': workbench, 'case': case, 'operations': operations},
                'source_sha256': {name: hashlib.sha256((root/name).read_bytes()).hexdigest() for name in (
                    'backend/app/cli/rc_demo.py', 'backend/app/services/shadow_continuity.py',
                    'backend/app/api/routes/investigation_workbench.py', 'backend/app/db/investigation_workbench.py')}}
        del client, app, service, store, worker
        gc.collect()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--frontend-contract', type=Path, help='Optional NEW synthetic JSON capture for frontend tests')
    args = parser.parse_args()
    if args.output.exists() or args.frontend_contract and args.frontend_contract.exists():
        parser.error('output must be a new file')
    report = run_demo()
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    if args.frontend_contract:
        with args.frontend_contract.open('x', encoding='utf-8') as stream:
            json.dump({'scope': report['scope'], 'captured_report_sha256': hashlib.sha256(args.output.read_bytes()).hexdigest(),
                       'contract': report['contract']}, stream, indent=2)
            stream.write('\n')
    print(json.dumps({key: report[key] for key in ('scope', 'source_count', 'findings', 'source_quick_check', 'production')}))


if __name__ == '__main__':
    main()
