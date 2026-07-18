import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-dvpwa"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    import sqli.dao.user as _target_mod


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("b'\\w+", re.IGNORECASE),

    re.compile("b'[!@#$%^&*()_+\\-=:;\"'<>,./?]+", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_WEAK_SENSITIVE_DATA_HASHING: md5 used for password hashing — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "password", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : sqli.dao.user.md5
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def check_password(password: str)
# condition        : md5 is called with any non-empty bytes payload representing an encoded password, confirming weak hashing of sensitive data
# capture_what     : bytes argument (encoded password) passed to md5 constructor
# skip_hint        : False
# ========================================


# === RECORDED_CALL SKELETON ===
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    password = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    
    with patch('sqli.dao.user.md5') as mock_md5:
        mock_hash_obj = MagicMock()
        mock_hash_obj.hexdigest.return_value = "a" * 32
        mock_hash_obj.digest.return_value = b"\x00" * 16
        mock_md5.return_value = mock_hash_obj
        
        try:
            _target_mod.check_password(password)
        except RuntimeError:
            raise
        except Exception:
            pass
        
        for call in mock_md5.call_args_list:
            captured = None
            if call.args and len(call.args) > 0:
                captured = call.args[0]
            
            if captured is not None:
                captured_str = str(captured)
                for pattern in _COMPILED_PATTERNS:
                    match = pattern.search(captured_str)
                    if match:
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured_str, matched_pattern=match.group()))
    


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    "password123",
    "P@ssw0rd!",
    "admin'--",
    "ABCdef123!@#",
    "!@#$%^&*()",
    "test_password",
    "a=b;c",
    "NormalPassword42",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-dvpwa/fuzz_corpus/py_weak_sensitive_data_hashing_sqli_dao_user_py_41"
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