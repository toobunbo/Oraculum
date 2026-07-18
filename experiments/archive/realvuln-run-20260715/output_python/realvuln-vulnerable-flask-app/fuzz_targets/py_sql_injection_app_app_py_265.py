import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-vulnerable-flask-app"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from app.app import search_customer


from app.app import app


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("username\\s*=\\s*''\\s*OR\\s+1\\s*=\\s*1", re.IGNORECASE),

    re.compile("username\\s*=\\s*''\\s*UNION\\s+SELECT", re.IGNORECASE),

    re.compile("username\\s*=\\s*''\\s*OR\\s+'", re.IGNORECASE),

    re.compile("username\\s*=\\s*'.*';\\s*DROP\\s+", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_SQL_INJECTION: SQL injection payload in db.engine.execute argument — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "search_term", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : app.app.db.engine.execute
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def search_customer()
# condition        : The captured SQL query string contains a SQL injection payload that breaks out of the single-quoted username literal and injects SQL keywords (OR, UNION, DROP) indicating successful exploitation
# capture_what     : SQL query string passed to db.engine.execute containing unsanitized user input interpolated via %s formatting
# skip_hint        : not isinstance(search_term, str)
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



def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    # NOTE: For string inputs, use fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    #       instead of ConsumeUnicodeNoSurrogates() to preserve raw seed payloads.
    
    # 1. Generate inputs from fdp
    
    param_search_term = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    
    # 2. Apply skip hint
    if not isinstance(param_search_term, str):
        return
    
    query_params = {
        
        "search_term": param_search_term,
        
    }
    
    # 3. Wrap in Flask Request Context
    with app.test_request_context(query_string=query_params):
        with patch('app.app.db.engine.execute') as mock_execute:
            mock_execute.return_value = MagicMock()
            
            try:
                # 4. Call target function
                search_customer()
            except RuntimeError:
                raise
            except Exception:
                pass
            
            # 5. Oracle check — OUTSIDE the function call try/except, INSIDE the patch context
            for call in mock_execute.call_args_list:
                captured = None
                if call.args and len(call.args) > 0:
                    captured = call.args[0]
                
                if captured is not None:
                    captured_str = str(captured)
                    for pattern in _COMPILED_PATTERNS:
                        match = pattern.search(captured_str)
                        if match:
                            raise RuntimeError(_RAISE_MESSAGE.format(
                                captured=captured_str,
                                matched_pattern=match.pattern
                            ))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    b"' OR 1=1 --",
    b"' UNION SELECT * FROM users --",
    b"' OR '1'='1",
    b"'; DROP TABLE users; --",
    b"' oR  1=1  --",
    b"' UniOn SeLeCt password FROM users --",
    b"' or  'a'='a",
    b"';  DROP TABLE customers--",
    b"'  OR\t1=1\t--",
    b"' UNION\tSELECT\t1,2,3--",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-vulnerable-flask-app/fuzz_corpus/py_sql_injection_app_app_py_265"
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