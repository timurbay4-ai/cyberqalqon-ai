"""Sanitized source/dependency inventory for release evidence and CI.

Only Git-visible files are hashed. Ignored runtime/secret files are counted by
category without opening or hashing their contents. No Git mutation occurs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from importlib.metadata import distributions
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {'M33_SOURCE_INVENTORY.json', 'M33_SOURCE_AUDIT.json', 'M33_RELEASE_MANIFEST.json'}


def git(*arguments):
    return subprocess.check_output(['git', *arguments], cwd=ROOT).decode('utf-8').strip()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def environment():
    packages = sorted({(d.metadata['Name'], d.version) for d in distributions()})
    resolved = []
    local = []
    for name, version in packages:
        if name.lower().replace('_', '-') == 'cyberqalqon-wazuh-sender':
            local.append({'name': name, 'version': version, 'kind': 'FIRST_PARTY_EDITABLE_SOURCE'})
        elif re.fullmatch(r'[A-Za-z0-9_.-]+', name) and re.fullmatch(r'[A-Za-z0-9_.+!-]+', version):
            resolved.append({'name': name, 'version': version})
        else:
            raise ValueError('UNSUPPORTED_DEPENDENCY_IDENTITY')
    return {'python': sys.version.split()[0], 'sqlite_version': sqlite3.sqlite_version,
            'sqlite_source_id': sqlite3.connect(':memory:').execute('SELECT sqlite_source_id()').fetchone()[0],
            'platform': sys.platform, 'dependencies': resolved, 'first_party': local,
            'lock_scope': 'THIS_INSTALLED_PLATFORM_NOT_A_CROSS_PLATFORM_HASH_LOCK'}


def inventory():
    files = git('ls-files', '--cached', '--others', '--exclude-standard', '-z').split('\0')
    rows = []
    for name in sorted(set(filter(None, files))):
        path = ROOT/name
        if path.name in EXCLUDED or not path.is_file():
            continue
        if (path.suffix.lower() in {'.db', '.sqlite', '.key', '.pem', '.pfx', '.p12'}
                or name.startswith(('artifacts/runtime/', 'secrets/', 'backups/'))
                or path.name in {'.env', '.env.production'}):
            raise ValueError('SENSITIVE_PATH_IN_SOURCE_SET')
        rows.append({'path': name, 'bytes': path.stat().st_size, 'sha256': sha(path.read_bytes())})
    source_rows = [row for row in rows if not row['path'].startswith('docs/')]
    ignored = git('ls-files', '--others', '--ignored', '--exclude-standard', '--directory', '-z').split('\0')
    categories = {'runtime_or_backups': 0, 'dependencies_and_caches': 0, 'configuration_or_credentials': 0, 'other': 0}
    for name in filter(None, ignored):
        key = ('runtime_or_backups' if name.startswith(('artifacts/', 'backups/', 'backend/data/', 'logs/'))
               else 'configuration_or_credentials' if name.startswith(('secrets/', 'credentials/', '.env'))
               else 'dependencies_and_caches' if any(part in name for part in ('.venv', 'node_modules', '__pycache__', '.pytest_cache'))
               else 'other')
        categories[key] += 1
    return {'generated_at': datetime.now(timezone.utc).isoformat(), 'branch': git('branch', '--show-current'),
            'head': git('rev-parse', 'HEAD'), 'cached_ref_freshness': 'NOT_ATTESTED_BY_THIS_COMMAND',
            'separate_remote_observation': 'docs/release/M33_REMOTE_OBSERVATION.json',
            'files': rows, 'source_tree_sha256': sha(json.dumps(source_rows, sort_keys=True, separators=(',', ':')).encode()),
            'fingerprint_scope': 'GIT_VISIBLE_NON_DOC_FILES_INCLUDING_UNTRACKED_NOT_A_COMMIT_ID',
            'excluded_self_reports': sorted(EXCLUDED), 'ignored_metadata_categories': categories,
            'ignored_contents_read': False, 'environment': environment()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--resolved-requirements', type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.resolved_requirements and args.resolved_requirements.exists():
        parser.error('outputs must be new files')
    report = inventory()
    args.output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    if args.resolved_requirements:
        args.resolved_requirements.write_text(''.join(f"{row['name']}=={row['version']}\n" for row in report['environment']['dependencies']), encoding='utf-8')
    print(json.dumps({'source_files': len(report['files']), 'source_tree_sha256': report['source_tree_sha256'],
                      'ignored_contents_read': False}))


if __name__ == '__main__':
    main()
