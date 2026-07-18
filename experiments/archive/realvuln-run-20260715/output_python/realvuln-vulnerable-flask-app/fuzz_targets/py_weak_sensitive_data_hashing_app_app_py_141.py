import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock


import hashlib


REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-vulnerable-flask-app"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from app.app import reg_customer
    from app.app import app


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile(".+", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_WEAK_SENSITIVE_DATA_HASHING: MD5 used for password hashing — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = []
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : hashlib.md5
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def reg_customer()
# condition        : hashlib.md5 was invoked with a non-empty password string, confirming use of weak MD5 algorithm for password hashing
# capture_what     : password string passed to hashlib.md5 for hashing
# skip_hint        : False
# ========================================


_SEED_CORPUS = [
    b"adminPassword123!admin@test.com" * 3,
    b"testusersecret_passtest@mail.com" * 3,
    b"alicealice_pass_1alice@example.org" * 3,
    b"bobBobSecure2024bob@example.net" * 3,
    b"charlieCharlie123charlie@test.org" * 3,
    b"devdev_pass_123dev@example.com" * 3,
    b"admin admin_pass admin@example.com" * 3,
    b"useruser123user@example.com" * 3,
]



def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    remaining = data
    chunk = len(remaining) // 3
    if chunk < 1 and len(remaining) > 0:
        chunk = 1
    
    username = remaining[:chunk].decode('utf-8', errors='ignore')
    password = remaining[chunk:2*chunk].decode('utf-8', errors='ignore')
    email = remaining[2*chunk:].decode('utf-8', errors='ignore')
    
    form_data = {
        'username': username,
        'password': password,
        'email': email,
    }
    
    with app.test_request_context(method='POST', data=form_data):
        with patch('hashlib.md5', return_value=MagicMock()) as mock_md5:
            try:
                reg_customer()
            except RuntimeError:
                raise
            except Exception:
                pass
            
            for call in mock_md5.call_args_list:
                if call.args and len(call.args) > 0:
                    captured = str(call.args[0])
                    for pattern in _COMPILED_PATTERNS:
                        m = pattern.search(captured)
                        if m:
                            raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=m.pattern))



if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-vulnerable-flask-app/fuzz_corpus/py_weak_sensitive_data_hashing_app_app_py_141"
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