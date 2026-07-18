import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-threatbyte"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from server.routes import delete_file


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("\\.{2}[/\\\\]", re.IGNORECASE),

    re.compile("(\\.{2}[/\\\\]){2,}", re.IGNORECASE),

    re.compile("\\.{2}[/\\\\].*\\.{2}[/\\\\]", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_PATH-INJECTION: path traversal detected in os.remove argument — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "filename", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : os.remove
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def delete_file(filename)
# condition        : The captured file_path contains path traversal sequences (../ or ..\) indicating the user-provided filename escaped the intended UPLOAD_FOLDER directory
# capture_what     : file_path argument passed to os.remove, constructed via os.path.join(UPLOAD_FOLDER, filename)
# skip_hint        : len(filename) < 3
# ========================================


# === RECORDED_CALL SKELETON ===
# TODO: Complete TestOneInput following these steps:
# 1. Generate inputs using FuzzedDataProvider.
# 2. Apply skip_hint (if applicable).
# 3. Mock the patch target using patch/MagicMock.
# 4. Call target function inside the mock context.
# 5. Compare mock call arguments against _COMPILED_PATTERNS.
# 6. Propagate RuntimeError; swallow other exceptions.
# ==========================================

_SEED_CORPUS = [
    b"../etc/passwd",
    b"..\\..\\windows\\system32\\config",
    b"foo/../../../etc/shadow",
    b"....//....//etc/passwd",
    b"..\\..\\..\\..\\etc\\hosts",
    b"./.././../etc/hostname",
    b"..\\/../etc/issue",
    b"img/../../../../../tmp/test",
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    filename = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    if len(filename) < 3:
        return

    with patch('os.remove') as mock_remove:
        mock_remove.return_value = MagicMock()

        try:
            delete_file(filename)
        except RuntimeError:
            raise
        except Exception:
            pass

        for call in mock_remove.call_args_list:
            captured = ""
            if call.args and len(call.args) > 0:
                captured = str(call.args[0])
            elif call.kwargs:
                captured = str(call.kwargs.get("path", ""))

            for pattern in _COMPILED_PATTERNS:
                match = pattern.search(captured)
                if match:
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=match.pattern))


if __name__ == "__main__":
    _CORPUS_DIR = "output/python/realvuln-threatbyte/fuzz_corpus/py_path_injection_server_routes_py_364"
    os.makedirs(_CORPUS_DIR, exist_ok=True)
    for _i, _seed in enumerate(_SEED_CORPUS):
        _seed_path = os.path.join(_CORPUS_DIR, f"seed_{_i:03d}")
        if not os.path.exists(_seed_path):
            with open(_seed_path, "wb") as _f:
                _f.write(_seed if isinstance(_seed, bytes) else _seed.encode("utf-8"))

    if _CORPUS_DIR not in sys.argv:
        sys.argv.append(_CORPUS_DIR)

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()