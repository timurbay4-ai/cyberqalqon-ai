"""Auditable source-only manifests and disposable reconstruction; never Git mutation.

This extends the existing release inventory with dependency closure and safe copying.
It does not publish, install, start services, read private runtime trees or waive scans.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import zipfile

from scripts.audit_m29_source import PATTERNS

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_PARTS = {'.git', '.venv', 'venv', 'node_modules', '__pycache__', '.pytest_cache',
                 '.mypy_cache', '.ruff_cache', 'secrets', 'credentials', 'backups', '.qa'}
PRIVATE_SUFFIXES = {'.db', '.sqlite', '.sqlite3', '.key', '.pem', '.pfx', '.p12', '.crt',
                    '.cer', '.exe', '.dll', '.zip', '.7z', '.log', '.pyc', '.pyo'}
WINDOWS_RESERVED = {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}


class ReleaseError(ValueError):
    pass


def relative_name(value: str) -> str:
    if not isinstance(value, str) or not value or '\\' in value or ':' in value or any(ord(c)<32 for c in value):
        raise ReleaseError('INVALID_RELEASE_PATH')
    p = PurePosixPath(value)
    if p.is_absolute() or any(part in {'', '.', '..'} for part in value.split('/')):
        raise ReleaseError('INVALID_RELEASE_PATH')
    if any(part.rstrip(' .')!=part or part.split('.')[0].upper() in WINDOWS_RESERVED for part in p.parts):
        raise ReleaseError('INVALID_RELEASE_PATH')
    return p.as_posix()


def excluded(name: str) -> str | None:
    name = name.casefold()
    p = PurePosixPath(name)
    if any(part in PRIVATE_PARTS for part in p.parts):
        return 'PRIVATE_DEPENDENCY_CACHE_OR_RUNTIME_NAMESPACE'
    if name.startswith(('artifacts/', 'frontend/dist/', 'frontend/build/', 'backend/data/', 'output/', 'tmp/')):
        return 'GENERATED_RUNTIME_OR_BUILD_OUTPUT'
    if p.name.startswith('.env') and p.name not in {'.env.example', '.env.production.example'}:
        return 'PRIVATE_CONFIGURATION'
    if p.suffix.lower() in PRIVATE_SUFFIXES or p.name.endswith(('-wal', '-shm', '.bak', '.tmp')):
        return 'PRIVATE_BINARY_DATABASE_KEY_OR_TEMPORARY_ARTIFACT'
    if name in {'docs/release/m36_source_inventory.json','docs/release/m36_release_source_manifest.json',
                'docs/release/m36_archive_receipt.json'}:
        return 'CURRENT_AUDIT_JSON_EXCLUDED_FROM_SELF_REFERENTIAL_SOURCE_FINGERPRINT'
    return None


def source_file(root: Path, name: str) -> Path:
    name = relative_name(name)
    path = root
    for part in PurePosixPath(name).parts:
        path = path/part
        try:
            info = path.lstat()
        except OSError as exc:
            raise ReleaseError('MISSING_SOURCE_PATH: '+name) from exc
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0)&0x400:
            raise ReleaseError('SOURCE_ALIAS_REJECTED: '+name)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:
        raise ReleaseError('REGULAR_UNALIASED_SOURCE_REQUIRED: '+name)
    if not path.resolve().is_relative_to(root.resolve()):
        raise ReleaseError('SOURCE_OUTSIDE_ROOT')
    return path


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def git_names(root: Path) -> list[str]:
    result = subprocess.run(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'],
        cwd=root, env={**os.environ, 'GIT_OPTIONAL_LOCKS':'0'}, capture_output=True, timeout=30)
    if result.returncode:
        raise ReleaseError('GIT_SOURCE_ENUMERATION_FAILED')
    return sorted(set(filter(None, result.stdout.decode('utf-8').split('\0'))))


def secret_findings(name: str, content: bytes) -> list[dict]:
    try:
        text = content.decode('utf-8-sig')
    except UnicodeError:
        return []
    found=[]
    for rule, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            found.append({'path':name, 'rule':rule, 'line':text.count('\n',0,match.start())+1,
                          'fingerprint':hashlib.sha256(match.group().encode()).hexdigest()[:16]})
    return found


def dependency_graph(root: Path, names: set[str]) -> dict:
    edges=[];missing=[];external=set();dynamic=[]
    def edge(source, reference, candidates, required=True):
        target=next((x for x in candidates if x in names),None)
        if target:edges.append({'source':source,'target':target,'reference':reference})
        elif required:missing.append({'source':source,'reference':reference,'candidates':candidates})
    std=set(sys.stdlib_module_names)|{'__future__'}
    local={'app':('backend',),'cyberqalqon_sender':('wazuh',),'scripts':('',)}
    for name in sorted(names):
        p=root/name
        if p.suffix=='.py':
            tree=ast.parse(p.read_text(encoding='utf-8-sig'),filename=name)
            for node in ast.walk(tree):
                if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr in {'import_module','run_module'}:
                    dynamic.append({'source':name,'line':node.lineno,'kind':node.func.attr})
                if isinstance(node,ast.Import):mods=[n.name for n in node.names]
                elif isinstance(node,ast.ImportFrom) and node.level==0:mods=[node.module or '']
                elif isinstance(node,ast.ImportFrom):
                    parts=list(PurePosixPath(name).parent.parts)
                    if node.level>len(parts):missing.append({'source':name,'reference':'RELATIVE_IMPORT_ESCAPE','candidates':[]});continue
                    base='/'.join(parts[:len(parts)-node.level+1])
                    module=base+'/'+(node.module or '').replace('.','/')
                    edge(name,'relative:'+str(node.module),[module+'.py',module+'/__init__.py'],required=bool(node.module))
                    continue
                else:continue
                for module in mods:
                    top=module.split('.')[0]
                    if top in std or not top:continue
                    if top not in local:external.add(top);continue
                    candidates=[]
                    for prefix in local[top]:
                        base='/'.join(filter(None,[prefix,module.replace('.','/')]))
                        candidates.extend([base+'.py',base+'/__init__.py'])
                    # Namespace packages such as scripts/ need no __init__.py.
                    namespace=module.replace('.','/')+'/'
                    if module=='scripts' and any(n.startswith(namespace) for n in names):continue
                    edge(name,module,candidates)
        if p.suffix in {'.ts','.tsx','.css'}:
            text=p.read_text(encoding='utf-8-sig')
            for ref in re.findall(r'(?:from\s*|import\s*\(?)[\"\x27]([^\"\x27]+)',text):
                if not ref.startswith('.'):external.add(ref.split('/')[0]);continue
                joined=os.path.normpath(str(PurePosixPath(name).parent/ref)).replace('\\','/')
                candidates=[joined,*(joined+x for x in ['.ts','.tsx','.json','.css']),joined+'/index.ts',joined+'/index.tsx']
                edge(name,ref,candidates)
        if p.suffix=='.json':
            data=json.loads(p.read_text(encoding='utf-8-sig'))
            def refs(obj):
                if isinstance(obj,dict):
                    for k,v in obj.items():
                        if k=='$ref' and isinstance(v,str) and not v.startswith(('#','http:','https:')):
                            base=v.split('#')[0]
                            target=os.path.normpath(str(PurePosixPath(name).parent/base)).replace('\\','/')
                            edge(name,v,[target])
                        else:refs(v)
                elif isinstance(obj,list):
                    for v in obj:refs(v)
            refs(data)
    # Go internal packages must be present; external modules are inventoried by go list.
    for name in sorted(n for n in names if n.endswith('.go')):
        text=(root/name).read_text()
        for suffix in re.findall(r'[\"]cyberqalqon\.local/collector/([^\"]+)[\"]',text):
            prefix='collector/'+suffix+'/'
            edge(name,suffix,[n for n in sorted(names) if n.startswith(prefix) and n.endswith('.go')])
    return {'edges':edges,'missing_required_local_modules':missing,'external_import_names':sorted(external),
            'dynamic_entrypoints_requiring_execution':dynamic,
            'scope':'Static module/relative-asset/JSON-ref closure plus actual reconstruction tests; not arbitrary dynamic path evaluation'}


def build_manifest(root: Path, paths: list[str] | None=None) -> dict:
    root=root.resolve();files=[];omitted=[];secrets=[];seen=set()
    names=[]
    # Validate the entire namespace before touching files. On case-sensitive
    # hosts a differently cased alias may sort before the existing source.
    for value in sorted(paths if paths is not None else git_names(root)):
        name=relative_name(value);key=name.casefold()
        if key in seen:raise ReleaseError('CASE_ALIAS_OR_DUPLICATE_PATH')
        seen.add(key)
        names.append(name)
    for name in names:
        reason=excluded(name)
        if reason:omitted.append({'path':name,'reason':reason});continue
        path=source_file(root,name);body=path.read_bytes()
        secrets.extend(secret_findings(name,body))
        files.append({'path':name,'sha256':hashlib.sha256(body).hexdigest(),'bytes':len(body),
                      'mode':0o755 if path.suffix=='.sh' or body.startswith(b'#!') else 0o644,
                      'kind':'TEST_OR_FIXTURE' if '/tests/' in name or name.startswith('tests/') or '.test.' in name else 'SOURCE_OR_AUTHORED_METADATA'})
    if secrets:raise ReleaseError('SOURCE_SECRET_PATTERN_DETECTED; use redacted inventory, never print values')
    graph=dependency_graph(root,{r['path'] for r in files})
    fingerprint=hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return {'contract':'cq-source-release-v1','status':'SOURCE_RELEASE_CANDIDATE','files':files,'excluded':omitted,
            'source_tree_sha256':fingerprint,'dependency_graph':graph,
            'source_root_not_embedded':True,'not_deployment_authorization':True}


def validate_manifest(manifest: dict) -> None:
    if not isinstance(manifest,dict) or manifest.get('contract')!='cq-source-release-v1' or not isinstance(manifest.get('files'),list):
        raise ReleaseError('INVALID_MANIFEST_CONTRACT')
    seen=set()
    for row in manifest['files']:
        if (not isinstance(row,dict) or not isinstance(row.get('sha256'),str)
                or type(row.get('bytes')) is not int or row['bytes']<0
                or type(row.get('mode')) is not int):
            raise ReleaseError('INVALID_MANIFEST_ENTRY')
        name=relative_name(row.get('path'))
        if name.casefold() in seen or excluded(name) or not re.fullmatch('[a-f0-9]{64}',row['sha256']) or row['mode'] not in (0o644,0o755):
            raise ReleaseError('INVALID_MANIFEST_ENTRY')
        seen.add(name.casefold())
    expected=hashlib.sha256(json.dumps(manifest['files'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if expected!=manifest.get('source_tree_sha256'):raise ReleaseError('MANIFEST_CHECKSUM_MISMATCH')


def safe_output_parent(path: Path) -> None:
    """Outputs require an existing unaliased directory; never follow junctions."""
    parent=path.absolute().parent
    for directory in [parent,*parent.parents]:
        try: info=directory.lstat()
        except OSError as exc:raise ReleaseError('OUTPUT_PARENT_REQUIRED') from exc
        if not stat.S_ISDIR(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400 or stat.S_ISLNK(info.st_mode):
            raise ReleaseError('OUTPUT_ALIAS_REJECTED')


def materialize(root: Path, manifest: dict, target: Path) -> None:
    root=root.resolve();validate_manifest(manifest)
    safe_output_parent(target)
    if target.exists() or target.is_symlink():raise ReleaseError('NEW_RECONSTRUCTION_DIRECTORY_REQUIRED')
    resolved=target.resolve()
    if resolved==root or root.is_relative_to(resolved):raise ReleaseError('RECONSTRUCTION_CANNOT_REPLACE_SOURCE')
    target.mkdir(parents=False,exist_ok=False)
    for row in manifest['files']:
        source=source_file(root,row['path'])
        if digest(source)!=row['sha256'] or source.stat().st_size!=row['bytes']:raise ReleaseError('SOURCE_CHANGED_AFTER_MANIFEST: '+row['path'])
        destination=target/row['path'];destination.parent.mkdir(parents=True,exist_ok=True)
        with source.open('rb') as src,destination.open('xb') as dst:shutil.copyfileobj(src,dst,1024*1024)
        if digest(destination)!=row['sha256']:raise ReleaseError('RECONSTRUCTION_CHECKSUM_MISMATCH')
        os.chmod(destination,row['mode'])


def archive(root: Path, manifest: dict, output: Path) -> str:
    validate_manifest(manifest)
    safe_output_parent(output)
    if output.exists() or output.is_symlink():raise ReleaseError('NEW_ARCHIVE_PATH_REQUIRED')
    embedded='SOURCE-RELEASE-MANIFEST.json'
    if any(row['path'].casefold()==embedded.casefold() for row in manifest['files']):
        raise ReleaseError('RESERVED_EMBEDDED_MANIFEST_PATH')
    with output.open('xb') as stream,zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as zipped:
        for row in manifest['files']:
            path=source_file(root,row['path'])
            if digest(path)!=row['sha256'] or path.stat().st_size!=row['bytes']:raise ReleaseError('SOURCE_CHANGED_AFTER_MANIFEST')
            info=zipfile.ZipInfo(row['path'],date_time=(1980,1,1,0,0,0));info.create_system=3
            info.external_attr=(stat.S_IFREG|row['mode'])<<16;info.compress_type=zipfile.ZIP_DEFLATED
            with path.open('rb') as src,zipped.open(info,'w') as dst:shutil.copyfileobj(src,dst,1024*1024)
        info=zipfile.ZipInfo(embedded,date_time=(1980,1,1,0,0,0));info.create_system=3
        info.external_attr=(stat.S_IFREG|0o644)<<16;info.compress_type=zipfile.ZIP_DEFLATED
        zipped.writestr(info,json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    return digest(output)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=ROOT);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--materialize',type=Path);parser.add_argument('--archive',type=Path)
    args=parser.parse_args()
    safe_output_parent(args.output)
    if args.output.exists() or args.output.is_symlink():parser.error('New manifest output required')
    manifest=build_manifest(args.root)
    if manifest['dependency_graph']['missing_required_local_modules']:
        manifest['status']='BLOCKED_MISSING_DEPENDENCY'
    with args.output.open('x',encoding='utf-8') as out:json.dump(manifest,out,indent=2);out.write('\n')
    if manifest['status'].startswith('BLOCKED'):raise SystemExit('Local dependency closure failed; inspect manifest')
    if args.materialize:materialize(args.root,manifest,args.materialize)
    if args.archive:archive(args.root,manifest,args.archive)
    print(json.dumps({'status':manifest['status'],'files':len(manifest['files']),'source_tree_sha256':manifest['source_tree_sha256']}))


if __name__=='__main__':main()
