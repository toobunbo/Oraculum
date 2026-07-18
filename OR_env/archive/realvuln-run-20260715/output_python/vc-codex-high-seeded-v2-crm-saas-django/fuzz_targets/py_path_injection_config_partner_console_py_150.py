import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock


import pathlib


REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/vc-codex-high-seeded-v2-crm-saas-django"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django.setup()

with atheris.instrument_imports():

    from config.partner_console import acct_dock_shelf_592


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("\\.{2}[/\\\\]", re.IGNORECASE),

    re.compile("\\.{2}$", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_PATH_INJECTION: directory traversal in mkdir path — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "request", "index": 0, "type": "django.http.HttpRequest"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : pathlib.Path.mkdir
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def acct_dock_shelf_592(request)
# condition        : The string representation of the Path object passed as self to mkdir contains directory traversal sequences (.. followed by a path separator or at end of string), confirming that user input 'name' with '..' fragments reached the sink unsanitized.
# capture_what     : The pathlib.Path object (self) representing target.parent, which is the directory path to be created, derived from user-controlled 'name' via BASE_EXPORT_DIR / name
# skip_hint        : False
# ========================================


_SEED_CORPUS = [
    "../../etc/passwd",
    "..\\..\\windows\\system32",
    "foo/../../bar/baz",
    "subdir/..",
    "....//....//etc/passwd",
    "a/../../../b",
    "test\\..\\..\\secret",
    "uploads/../../../etc/shadow",
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    name_val = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    mock_request = MagicMock()
    mock_request.name = name_val
    mock_request.GET = {'name': name_val}
    mock_request.POST = {'name': name_val}
    mock_request.data = {'name': name_val}
    mock_request.method = 'POST'

    with patch('pathlib.Path.mkdir') as mock_mkdir:
        mock_mkdir.return_value = None

        try:
            acct_dock_shelf_592(mock_request)
        except RuntimeError:
            raise
        except Exception:
            pass

        for call in mock_mkdir.call_args_list:
            captured = None
            if call.args and len(call.args) > 0:
                captured = call.args[0]

            if captured is not None:
                captured_str = str(captured)
                for pattern in _COMPILED_PATTERNS:
                    match = pattern.search(captured_str)
                    if match:
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured_str, matched_pattern=match.pattern))


if __name__ == "__main__":
    _CORPUS_DIR = "output/python/vc-codex-high-seeded-v2-crm-saas-django/fuzz_corpus/py_path_injection_config_partner_console_py_150"
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