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

    from config.partner_console import acct_vault_stash_244


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("(?:^|/|\\\\)\\.\\.(?:/|\\\\|$)", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_PATH-INJECTION: path traversal in mkdir call — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "request", "index": 0, "type": "django.http.HttpRequest"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : pathlib.Path.mkdir
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def acct_vault_stash_244(request)
# condition        : The string representation of the Path object passed as self to mkdir contains a path traversal component (..) indicating the directory to be created escapes the intended base directory
# capture_what     : the Path object (self) representing the directory path on which mkdir is invoked
# skip_hint        : False
# ========================================


_SEED_CORPUS = [
    "../",
    "..\\",
    "foo/../bar",
    "..\\/",
    "/../etc/passwd",
    "....//",
    "foo\\..\\bar",
    "/..\\/",
    "stash/../../tmp/pwned",
    "vault\\..\\..\\windows\\system32",
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    raw = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    mock_request = MagicMock()
    mock_request.path = raw
    mock_request.method = "POST"
    mock_request.GET = {"path": raw}
    mock_request.POST = {"path": raw}
    mock_request.body = raw.encode('utf-8', errors='ignore')
    mock_request.META = {"PATH_INFO": raw}
    mock_request.user = MagicMock()
    mock_request.user.is_authenticated = True
    mock_request.session = {}

    with patch('pathlib.Path.mkdir', autospec=True) as mock_mkdir:
        try:
            acct_vault_stash_244(mock_request)
        except RuntimeError:
            raise
        except Exception:
            pass

        for call in mock_mkdir.call_args_list:
            captured = None
            if call.args:
                captured = call.args[0]
            if captured is not None:
                captured_str = str(captured)
                for pattern in _COMPILED_PATTERNS:
                    m = pattern.search(captured_str)
                    if m:
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured_str, matched_pattern=m.group()))


if __name__ == "__main__":
    _CORPUS_DIR = "output/python/vc-codex-high-seeded-v2-crm-saas-django/fuzz_corpus/py_path_injection_config_partner_console_py_91"
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