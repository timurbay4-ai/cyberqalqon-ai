"""Opt-in PYTHONPATH bootstrap for isolated candidate regression + child processes."""
import os
from pathlib import Path
import sys
try:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
    from m32_candidate_runtime import load
    _m32_library,_m32_manifest=load()
except BaseException:
    sys.stderr.write('M32 candidate bootstrap failed closed; no test database opened.\n')
    os._exit(78)
