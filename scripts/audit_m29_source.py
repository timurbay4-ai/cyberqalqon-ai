"""Read-only Git/source hygiene audit; output never contains credential values."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = {
    'private_key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'github_token': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b'),
    'aws_access_id': re.compile(r'\bAKIA[A-Z0-9]{16}\b'),
    'jwt_literal': re.compile(r'\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\b'),
}


def git(*args):
    return subprocess.check_output(['git',*args],cwd=ROOT).decode('utf-8').strip()


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''): value.update(block)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--baseline',type=Path,default=ROOT/'docs/siem/M29_BASELINE_INVENTORY.json')
    parser.add_argument('--milestone',choices=('M29','M30','M31','M32','M33','M34','M35'),default='M29')
    args = parser.parse_args()
    inventory = json.loads(args.baseline.read_text())
    milestone = args.milestone.lower()
    status = subprocess.check_output(['git','status','--porcelain=v1','-uall','-z'],cwd=ROOT).decode().split('\0')
    dirty = [{'status':entry[:2],'path':entry[3:]} for entry in status if entry]
    baseline = {row['path']:row for row in inventory}
    changed = []
    for row in dirty:
        file = ROOT/row['path']
        if not file.is_file():
            raise RuntimeError('unexpected deleted/non-file dirty path')
        row.update({'bytes':None if file.resolve() == args.output.resolve() else file.stat().st_size,
                    'sha256':None if file.resolve() == args.output.resolve() else digest(file)})
        if file.resolve() == args.output.resolve():
            row['hash_scope'] = 'SELF_GENERATED_REPORT_EXCLUDED'
        row['pre_'+milestone] = row['path'] in baseline
        row['changed_during_'+milestone] = row['path'] not in baseline or row['sha256'] != baseline[row['path']]['sha256']
        if row['changed_during_'+milestone]: changed.append(row['path'])
    missing = [name for name in baseline if not (ROOT/name).is_file()]
    files = subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=ROOT).decode().split('\0')
    invalid_json, findings, large, sensitive = [], [], [], []
    for name in filter(None,files):
        file = ROOT/name
        if not file.is_file(): continue
        if file.stat().st_size > 2*1024*1024: large.append(name)
        if (file.suffix.lower() in {'.db','.sqlite','.sqlite3','.key','.pem','.pfx','.p12'}
                or name.startswith(('secrets/','artifacts/runtime/','backups/'))
                or file.name in {'.env','.env.production'}): sensitive.append(name)
        try: content = file.read_text(encoding='utf-8-sig')
        except (UnicodeError,OSError): continue
        if file.suffix == '.json':
            try: json.loads(content)
            except ValueError: invalid_json.append(name)
        for pattern_name,pattern in PATTERNS.items():
            for index,line in enumerate(content.splitlines(),1):
                if pattern.search(line): findings.append({'path':name,'line':index,'rule':pattern_name})
    report = {'generated_at':datetime.now(timezone.utc).isoformat(),'scope':'SOURCE_AND_GIT_METADATA_ONLY',
        'branch':git('branch','--show-current'),'head':git('rev-parse','HEAD'),
        'dirty_count':len(dirty),'baseline_count':len(baseline),'baseline_missing':missing,
        'baseline_byte_identical':sum(1 for row in dirty if row['pre_'+milestone] and not row['changed_during_'+milestone]),
        'baseline_extended_paths':[row['path'] for row in dirty if row['pre_'+milestone] and row['changed_during_'+milestone]],
        'staged_paths':git('diff','--cached','--name-only').splitlines(),
        milestone+'_changed_paths':changed,'inventory':dirty,'invalid_json':invalid_json,
        'credential_pattern_findings':findings,'sensitive_paths':sensitive,'over_2mb':large,
        'credential_scan_limit':'Heuristic patterns, not a guarantee that every possible secret is absent.'}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({key:report[key] for key in ('dirty_count','baseline_missing','invalid_json',
        'credential_pattern_findings','sensitive_paths','over_2mb')}))
    return 1 if missing or invalid_json or findings or sensitive else 0


if __name__ == '__main__': raise SystemExit(main())
