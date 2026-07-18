import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/vc-claude-code-seeded-v2-hr-payroll-django"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from hr_portal.payroll_operations import payroll_dock_shelf_391


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("\\.{2}[/\\\\]", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_PATH-INJECTION: directory traversal detected in mkdir path — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "request", "index": 0, "type": "request"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : pathlib.Path.mkdir
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def payroll_dock_shelf_391(request)
# condition        : The captured Path object's string representation contains '../' or '..\' indicating the user-provided name caused the path to escape BASE_EXPORT_DIR
# capture_what     : the Path object (self) representing target.parent, to check whether its string representation contains directory traversal sequences like '../'
# skip_hint        : False
# ========================================


_SEED_CORPUS = [
    b"../../../etc/passwd",
    b"..\..\..\windows\system32",
    b"foo/../../../etc/hosts",
    b"....//....//etc//passwd",
    b"..\/..\/etc\/passwd",
    b"a/../../b/../../../c",
    b"export/../.ssh/id_rsa",
    b"reports/..\\..\\..\\secrets.db",
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    raw_input = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    mock_request = MagicMock()
    mock_request.method = 'POST'
    mock_request.GET = {'name': raw_input, 'filename': raw_input, 'path': raw_input, 'file': raw_input, 'directory': raw_input}
    mock_request.POST = {'name': raw_input, 'filename': raw_input, 'path': raw_input, 'file': raw_input, 'directory': raw_input}
    mock_request.data = {'name': raw_input, 'filename': raw_input, 'path': raw_input, 'file': raw_input, 'directory': raw_input}
    mock_request.body = raw_input.encode('utf-8', errors='ignore')

    mock_file = MagicMock()
    mock_file.name = raw_input
    mock_request.FILES = {'file': mock_file}

    mock_user = MagicMock()
    mock_user.is_authenticated = True
    mock_request.user = mock_user

    with patch('pathlib.Path.mkdir') as mock_mkdir:
        try:
            payroll_dock_shelf_391(mock_request)
        except RuntimeError:
            raise
        except Exception:
            pass

        for call in mock_mkdir.call_args_list:
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
    _CORPUS_DIR = "output/python/vc-claude-code-seeded-v2-hr-payroll-django/fuzz_corpus/py_path_injection_hr_portal_payroll_operations_py_147"
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