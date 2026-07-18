import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock


import builtins


REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-lets-be-bad-guys"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from badguys.vulnerable.views import code_execution


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("__import__\\(", re.IGNORECASE),

    re.compile("os\\.system\\(", re.IGNORECASE),

    re.compile("subprocess\\.", re.IGNORECASE),

    re.compile("open\\(['\"]", re.IGNORECASE),

    re.compile("eval\\(", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_CODE_INJECTION: arbitrary code passed to exec() — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "first_name", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : builtins.exec
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def code_execution(request)
# condition        : The argument to exec() contains decoded Python code that performs dangerous operations such as importing os/subprocess, calling system commands, reading files, or using eval.
# capture_what     : decoded base64 string passed to exec(), which is the result of base64.decodestring(first_name)
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

_SEED_CORPUS = [
    "X19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ2lkJyk=",
    "b3Muc3lzdGVtKCdjYXQgL2V0Yy9wYXNzd2QnKQ==",
    "c3VicHJvY2Vzcy5jYWxsKFsnaWQnXSk=",
    "b3BlbignL2V0Yy9wYXNzd2QnKS5yZWFkKCk=",
    "ZXZhbCgnX19pbXBvcnRfXygib3MiKS5zeXN0ZW0oImlkIiknKQ==",
    "T1MuU1lTVEVNKCd3aG9hbWknKQ==",
    "X19pbXBvcnRfXyggJ29zJyApLnN5c3RlbSggJ2lkJyAp",
    "ZXZhbCggJ19faW1wb3J0X18oIm9zIiknICk=",
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    first_name = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    mock_request = MagicMock()
    mock_request.first_name = first_name
    mock_request.POST = {'first_name': first_name}
    mock_request.GET = {'first_name': first_name}
    mock_request.data = {'first_name': first_name}

    with patch('builtins.exec') as mock_exec:
        try:
            code_execution(mock_request)
        except RuntimeError:
            raise
        except Exception:
            pass

        for call in mock_exec.call_args_list:
            captured = None
            if call.args and len(call.args) > 0:
                captured = str(call.args[0])

            if captured is not None:
                for pattern in _COMPILED_PATTERNS:
                    if pattern.search(captured):
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=pattern.pattern))


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-lets-be-bad-guys/fuzz_corpus/py_code_injection_badguys_vulnerable_views_py_76"
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