import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock


import pathlib


REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/vc-claude-code-seeded-v2-support-desk-fastapi"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from backend.app.support_operations import ticket_dock_shelf_387


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("\\.{2}[\\/]", re.IGNORECASE),

    re.compile("\\.{2}\\\\", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_PATH_INJECTION: directory traversal via mkdir — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "name", "index": 1, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : pathlib.Path.mkdir
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def ticket_dock_shelf_387(request: Request, name: str, gate_ref: None)
# condition        : The Path object passed as self to mkdir contains '..' traversal sequences indicating the path escapes BASE_EXPORT_DIR
# capture_what     : The Path object (self) on which mkdir is called, representing the parent directory derived from the user-controlled name
# skip_hint        : False
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



def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    name = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    request_mock = MagicMock()

    with patch('pathlib.Path.mkdir') as mock_mkdir:
        mock_mkdir.return_value = None

        try:
            ticket_dock_shelf_387(request_mock, name, None)
        except RuntimeError:
            raise
        except Exception:
            pass

        for call in mock_mkdir.call_args_list:
            captured = None
            if call.args and len(call.args) > 0:
                captured = str(call.args[0])

            if captured is not None:
                for pattern in _COMPILED_PATTERNS:
                    m = pattern.search(captured)
                    if m:
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=m.group()))

    return


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    b"../etc/passwd",
    b"..\\windows\\system32",
    b"foo/../../tmp/escape",
    b"....//....//....//etc",
    b"bar/..\\..\\..\\windows\\system32",
    b"a/b/../../../../../../../../etc/shadow",
    b"..\/..\/..\/etc\/passwd",
    b"normal/..\\..\\..\\escape",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/vc-claude-code-seeded-v2-support-desk-fastapi/fuzz_corpus/py_path_injection_backend_app_support_operations_py_97"
    os.makedirs(_CORPUS_DIR, exist_ok=True)
    for _i, _seed in enumerate(_SEED_CORPUS):
        _seed_path = os.path.join(_CORPUS_DIR, f"seed_{_i:03d}")
        if not os.path.exists(_seed_path):
            with open(_seed_path, "wb") as _f:
                _f.write(_seed)

    if _CORPUS_DIR not in sys.argv:
        sys.argv.append(_CORPUS_DIR)

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()