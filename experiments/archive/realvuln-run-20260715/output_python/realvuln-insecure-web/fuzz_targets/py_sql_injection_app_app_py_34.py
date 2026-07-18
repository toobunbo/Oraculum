import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-insecure-web"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from app.app import login, app


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("'\\s+OR\\s+", re.IGNORECASE),

    re.compile("'\\s+AND\\s+", re.IGNORECASE),

    re.compile("';\\s*\\w", re.IGNORECASE),

    re.compile("'\\s*;\\s*--", re.IGNORECASE),

    re.compile("UNION\\s+SELECT", re.IGNORECASE),

    re.compile("--\\s*$", re.IGNORECASE),

    re.compile("'\\s*OR\\s+'\\d*'='\\d*", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_SQL_INJECTION: unparameterized SQL injection detected — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "username", "index": -1, "type": "str"}, {"name": "password", "index": -1, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : sqlite3.Cursor.execute
# target_arg_index : 0
# target_arg_name  : sql
# input_strategy   : flask_view
# signature        : def login()
# condition        : The captured SQL query string contains evidence of SQL injection: a single-quote breakout followed by SQL keywords or operators that could not originate from the application's static query template
# capture_what     : The full SQL query string passed to cursor.execute, containing f-string interpolated username and password
# skip_hint        : False
# ========================================


# === RECORDED_CALL SKELETON ===



def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    param_username = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    
    param_password = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    
    query_params = {
        
        "username": param_username,
        
        "password": param_password,
        
    }
    
    with app.test_request_context(query_string=query_params):
        with patch("sqlite3.Cursor.execute", MagicMock()) as mock_execute:
            try:
                login()
            except RuntimeError:
                raise
            except Exception:
                pass

            for call in mock_execute.call_args_list:
                captured = None
                if call.args and len(call.args) > 0:
                    captured = str(call.args[0])
                else:
                    captured = str(call.kwargs.get("sql", ""))

                for pattern in _COMPILED_PATTERNS:
                    m = pattern.search(captured)
                    if m:
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=m.pattern))



# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    b"' OR 1=1 --",
    b"' oR '\t1'='1",
    b"' UniOn SeLeCt * from users --",
    b"admin' AnD '1'='1",
    b"'; DROP TABLE users --",
    b"'   OR\t'1'='1' --",
    b"'\nOR  '0'='0'--",
    b"'OR 'a'='a",
]



if __name__ == "__main__":
    _CORPUS_DIR = "output/python/realvuln-insecure-web/fuzz_corpus/py_sql_injection_app_app_py_34"
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