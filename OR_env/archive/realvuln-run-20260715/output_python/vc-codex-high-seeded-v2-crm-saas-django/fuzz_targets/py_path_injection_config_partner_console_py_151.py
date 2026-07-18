import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/vc-codex-high-seeded-v2-crm-saas-django"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from config.partner_console import acct_dock_shelf_592


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("\\.{2}[\\\\/]", re.IGNORECASE),

    re.compile("\\.{2}[\\\\/]\\.{2}[\\\\/]", re.IGNORECASE),

    re.compile("^[\\\\/]", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_PATH_INJECTION: directory traversal detected in write_bytes path — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "name", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : config.partner_console.Path.write_bytes
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def acct_dock_shelf_592(request)
# condition        : The captured Path object's string representation contains directory traversal sequences (../ or ..\) or starts with an absolute path separator, confirming that user-controlled 'name' escaped BASE_EXPORT_DIR
# capture_what     : Path object (self) whose string representation contains the user-controlled name concatenated into the file path
# skip_hint        : False
# ========================================


_SEED_CORPUS = [
    b"../../../etc/passwd",
    b"..\\..\\..\\windows\\system32\\config",
    b"/etc/shadow",
    b"....//....//....//etc/passwd",
    b"..\\/..\\/..\\/etc/passwd",
    b"/.././.././../etc/hosts",
    b"foo/../../bar/baz",
    b"export/..\\..\\..\\..\\tmp/evil",
    b"report.pdf/../../../etc/crontab",
    b"..%2f..%2f..%2fetc%2fpasswd",
    b"..\\../..\\../..\\../etc/passwd",
    b"/..\\..\\..\\windows\\win.ini",
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    name = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    request = MagicMock()
    request.name = name
    request.GET = {'name': name}
    request.POST = {'name': name}
    request.data = {'name': name}

    with patch('config.partner_console.Path.write_bytes', autospec=True) as mock_write_bytes:
        try:
            acct_dock_shelf_592(request)
        except RuntimeError:
            raise
        except Exception:
            pass

        for call in mock_write_bytes.call_args_list:
            captured = None
            if call.args:
                captured = call.args[0]
            if captured is None:
                continue
            captured_str = str(captured)
            for pattern in _COMPILED_PATTERNS:
                m = pattern.search(captured_str)
                if m:
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=captured_str, matched_pattern=m.pattern))


if __name__ == "__main__":
    _CORPUS_DIR = "output/python/vc-codex-high-seeded-v2-crm-saas-django/fuzz_corpus/py_path_injection_config_partner_console_py_151"
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