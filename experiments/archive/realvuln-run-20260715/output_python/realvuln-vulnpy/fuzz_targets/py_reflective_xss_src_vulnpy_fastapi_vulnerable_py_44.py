import atheris
import sys
import re
import os

import tempfile
import shutil



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-vulnpy"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from src.vulnpy.fastapi.vulnerable import get_trigger_view


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

]
_RAISE_MESSAGE  = "PY_REFLECTIVE_XSS: file written outside boundary — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "trigger", "index": 1, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : filesystem_state
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def get_trigger_view(name, trigger)
# condition        : No filesystem writes occur in this function; the sink is HTMLResponse (XSS), not a file I/O call. The filesystem_state monitor will never trigger for this vulnerability class.
# capture_what     : files created or modified during execution — note: the actual vulnerability is reflective XSS via HTMLResponse, not a filesystem operation, so this monitor is expected to be a no-op for this finding
# skip_hint        : False
# ========================================


def _snapshot_dir(path):
    snapshot = {}
    for root, dirs, files in os.walk(path):
        for f in files:
            fp = os.path.join(root, f)
            try:
                snapshot[fp] = os.path.getmtime(fp)
            except OSError:
                pass
    return snapshot


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    if not data:
        return

    name = fdp.ConsumeBytes(len(data) // 2).decode('utf-8', errors='ignore')
    trigger = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    tmpdir = tempfile.TemporaryDirectory()
    tmp_path = tmpdir.name
    before_snapshot = _snapshot_dir(tmp_path)

    try:
        orig_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            get_trigger_view(name, trigger)
        except RuntimeError:
            raise
        except Exception:
            pass
        finally:
            os.chdir(orig_cwd)

        after_snapshot = _snapshot_dir(tmp_path)

        for filepath, mtime in after_snapshot.items():
            if filepath not in before_snapshot:
                raise RuntimeError(_RAISE_MESSAGE.format(captured=filepath, matched_pattern="new_file"))
            elif mtime != before_snapshot[filepath]:
                raise RuntimeError(_RAISE_MESSAGE.format(captured=filepath, matched_pattern="modified_file"))
    finally:
        tmpdir.cleanup()


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    '<script>alert(1)</script>',
    '<ScRiPt>alert(1)</ScRiPt>',
    '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    '<svg/onload=alert(1)>',
    'javascript:alert(1)',
    '<img/src=x/onerror=alert(1)>',
    '<script\x0b>alert(1)</script>',
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-vulnpy/fuzz_corpus/py_reflective_xss_src_vulnpy_fastapi_vulnerable_py_44"
    os.makedirs(_CORPUS_DIR, exist_ok=True)
    for _i, _seed in enumerate(_SEED_CORPUS):
        _seed_path = os.path.join(_CORPUS_DIR, f"seed_{_i:03d}")
        if not os.path.exists(_seed_path):
            with open(_seed_path, "wb") as _f:
                if isinstance(_seed, bytes):
                    _f.write(_seed)
                else:
                    _f.write(_seed.encode("utf-8"))

    if _CORPUS_DIR not in sys.argv:
        sys.argv.append(_CORPUS_DIR)

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()