import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/vc-claude-code-seeded-v2-hr-payroll-django"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "hr_portal.settings")
django.setup()

with atheris.instrument_imports():

    from hr_portal.payroll_operations import payroll_dock_shelf_391


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("\\.\\./", re.IGNORECASE),

    re.compile("\\.\\.\\\\/", re.IGNORECASE),

    re.compile("\\.\\.[\\\\/]", re.IGNORECASE),

    re.compile("\\.\\.%2[fF]", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_PATH-INJECTION: path traversal detected in write_bytes target — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "request", "index": 0, "type": "django.http.HttpRequest"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : pathlib.Path.write_bytes
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def payroll_dock_shelf_391(request)
# condition        : The captured Path object's string representation contains directory traversal sequences (../) indicating the user-controlled 'name' parameter escaped BASE_EXPORT_DIR
# capture_what     : Path object (self) representing the resolved file path that write_bytes is called on
# skip_hint        : False
# ========================================


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..\\/..\\/..\\/etc\\/passwd",
    "....//....//....//etc//passwd",
    "..\\../..\\../..\\../etc/hosts",
    "export/../../../tmp/pwned",
    "..%2F..%2F..%2Fvar/log/secrets",
    "payroll/../../.env",
    "..\\..\\..\\..\\boot.ini",
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    raw_input = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')

    mock_request = MagicMock()
    mock_request.GET = {'name': raw_input}
    mock_request.POST = {'name': raw_input}
    mock_request.method = 'POST'
    mock_request.body = raw_input.encode('utf-8', errors='ignore')
    mock_request.content_type = 'application/x-www-form-urlencoded'
    mock_request.META = {'CONTENT_TYPE': 'application/x-www-form-urlencoded'}

    with patch('pathlib.Path.write_bytes', return_value=None) as mock_write_bytes:
        try:
            payroll_dock_shelf_391(mock_request)
        except RuntimeError:
            raise
        except Exception:
            pass

        for call in mock_write_bytes.call_args_list:
            captured = None
            if call.args and len(call.args) > 0:
                captured = str(call.args[0])

            if captured is None:
                continue

            for pattern in _COMPILED_PATTERNS:
                match = pattern.search(captured)
                if match:
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=match.group()))


if __name__ == "__main__":
    _CORPUS_DIR = "output/python/vc-claude-code-seeded-v2-hr-payroll-django/fuzz_corpus/py_path_injection_hr_portal_payroll_operations_py_148"
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