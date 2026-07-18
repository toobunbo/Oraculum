import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-lets-be-bad-guys"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "badguys.settings")
django.setup()

with atheris.instrument_imports():

    from badguys.vulnerable.views import code_execution


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("__import__", re.IGNORECASE),

    re.compile("os\\.system", re.IGNORECASE),

    re.compile("open\\(", re.IGNORECASE),

    re.compile("eval\\(", re.IGNORECASE),

    re.compile("exec\\(", re.IGNORECASE),

    re.compile("subprocess\\.", re.IGNORECASE),

    re.compile("pickle\\.loads", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_CODE_INJECTION: arbitrary code passed to exec — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "request", "index": 0, "type": "django.http.HttpRequest"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : builtins.exec
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def code_execution(request)
# condition        : The captured argument to exec contains Python code indicative of arbitrary code execution, such as __import__, os.system, open(), eval(), or exec() calls
# capture_what     : decoded base64 string passed to exec after evaluation by base64.decodestring(bytes(first_name, 'ascii'))
# skip_hint        : False
# ========================================


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    "X19pbXBvcnRfXygnb3MnKQ==",
    "b3Muc3lzdGVtKCdpZCcp",
    "b3BlbignL2V0Yy9wYXNzd2QnKQ==",
    "ZXhlYygnaW1wb3J0IG9zJyk=",
    "c3VicHJvY2Vzcy5jYWxsKFsnaWQnXSk=",
    "cGlja2xlLmxvYWRzKGIneCcp",
    "X19JbXBvcnRfXygnb3MnKQ==",
    "T1MuU1lTVEVNKCdpZCcp",
    "T3BlbignL2V0Yy9wYXNzd2QnKQ==",
    "ZXZhbCgnX19pbXBvcnRfXygiT1MiKS5zeXN0ZW0oImlkIiknKQ==",
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    first_name = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    mock_request = MagicMock()
    mock_request.GET.get.return_value = first_name
    mock_request.POST.get.return_value = first_name
    mock_request.GET.__getitem__.return_value = first_name
    mock_request.POST.__getitem__.return_value = first_name

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
            else:
                captured = str(call.kwargs.get("code", ""))
            if not captured:
                continue

            for pattern in _COMPILED_PATTERNS:
                if pattern.search(captured):
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=pattern.pattern))


if __name__ == "__main__":
    _CORPUS_DIR = "output/python/realvuln-lets-be-bad-guys/fuzz_corpus/py_code_injection_badguys_vulnerable_views_py_72"
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