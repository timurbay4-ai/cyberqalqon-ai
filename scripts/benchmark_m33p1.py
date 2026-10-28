"""New P1 evidence wrapper: original E7 unchanged; native probes optional."""
from contextlib import contextmanager, nullcontext
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time

import benchmark_m33p0 as base


def main():
    if '--help' in sys.argv or '-h' in sys.argv or '--output' not in sys.argv:
        # Preserve argparse's ordinary help/required-argument contract.
        base.main()
        return
    reuse = '--reuse-e1' in sys.argv
    if reuse:
        sys.argv.remove('--reuse-e1')
        # Explicit diagnostic cell only; never redefine original E7 lifecycle.
        index = sys.argv.index('--experiments')+1
        if sys.argv[index] != 'E1' or (index+1 < len(sys.argv) and not sys.argv[index+1].startswith('--')):
            raise ValueError('Connection reuse is restricted to diagnostic E1')
    native = '--native-probe' in sys.argv
    if native:
        sys.argv.remove('--native-probe')
    treatment = 'current'
    if '--build-treatment' in sys.argv:
        index = sys.argv.index('--build-treatment')
        treatment = sys.argv[index+1]
        del sys.argv[index:index+2]
        if treatment not in {'current', 'old-rebuild'}:
            raise ValueError('Invalid diagnostic build treatment')
    output = Path(sys.argv[sys.argv.index('--output')+1])
    if output.exists() or output.is_symlink():
        # The finally receipt must never amend an earlier run after base argparse
        # rejects an existing output path.
        raise ValueError('New evidence path required')
    original_install = base.install_rowid
    selected_install = original_install
    if treatment == 'old-rebuild':
        # Immutable original P0 backup, verified against its initial inventory.
        name = 'backend/app/db/fts_rowid.py'
        source = base.ROOT/'artifacts/runtime/m33p0-baseline-source'/name
        inventory = json.loads((base.ROOT/'docs/release/M33P0_BASELINE_INVENTORY.json').read_text())
        expected = next(row['sha256'] for row in inventory if row['path'] == name)
        if hashlib.sha256(source.read_bytes()).hexdigest() != expected:
            raise ValueError('Historical diagnostic installer checksum mismatch')
        spec = importlib.util.spec_from_file_location('_m33p1_old_fts', source)
        module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        selected_install = module.install
    builds = []
    def observed_install(*args, **kwargs):
        start, cpu = time.perf_counter(), time.process_time()
        result, failed = None, False
        try:
            result = selected_install(*args, **kwargs)
            return result
        except BaseException:
            failed = True
            raise
        finally:
            builds.append({'sequence':len(builds), 'treatment':treatment, 'failed':failed,
                       'wall_ms':(time.perf_counter()-start)*1000,
                       'cpu_ms':(time.process_time()-cpu)*1000,
                       'manifest':result})
    base.install_rowid = observed_install
    original = base.m33_request_trace.installed
    if native or reuse:
        from m33p1_native_probe import installed as native_installed
        from m33p1_reuse_control import installed as reuse_installed
        @contextmanager
        def instrumented():
            with native_installed() if native else nullcontext() as native_report, original() as old_report:
                old_report['native_probe'] = native_report
                with reuse_installed() if reuse else nullcontext() as reuse_report:
                    old_report['connection_reuse'] = reuse_report
                    yield old_report
        base.m33_request_trace.installed = instrumented
    try:
        base.main()
    finally:
        base.m33_request_trace.installed = original
        base.install_rowid = original_install
        # Preserve setup/partial measurements even on a failed benchmark.
        if output.exists():
            report = json.loads(output.read_text(encoding='utf-8'))
            report['p1_instrumentation'] = {'native_probe':native, 'connection_reuse':reuse, 'fts_build_treatment':treatment,
                'build_measurements':builds, 'no_end_to_end_deployment_claim':True}
            output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status':'FAILED','error_type':type(error).__name__}), flush=True)
        raise SystemExit(1) from None
