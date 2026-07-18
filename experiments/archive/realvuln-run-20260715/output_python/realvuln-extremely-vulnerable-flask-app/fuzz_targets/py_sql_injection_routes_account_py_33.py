import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-extremely-vulnerable-flask-app"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from routes.account import search
    from app import app


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("' OR ", re.IGNORECASE),

    re.compile("' UNION ", re.IGNORECASE),

    re.compile("' AND ", re.IGNORECASE),

    re.compile("'--", re.IGNORECASE),

    re.compile("'; ", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_SQL_INJECTION: unsanitized user input in SQL text() fragment — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "search", "index": -1, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : routes.account.text
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def search()
# condition        : The captured SQL string contains a single-quote breakout from the LIKE string literal followed by SQL control keywords (OR, UNION, AND, comment, or statement terminator), confirming raw user input is embedded unsanitized.
# capture_what     : Full SQL fragment string passed to text(), containing unsanitized search_param interpolated via f-string
# skip_hint        : not search
# ========================================


# === RECORDED_CALL SKELETON ===


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    # NOTE: For string inputs, use fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    #       instead of ConsumeUnicodeNoSurrogates() to preserve raw seed payloads.
    
    # 1. Generate inputs from fdp
    
    param_search = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    
    # 2. Skip condition
    if not param_search:
        return
    
    query_params = {
        
        "search": param_search,
        
    }
    
    # 3. Wrap in Flask Request Context with mock
    with app.test_request_context(query_string=query_params):
        with patch('routes.account.text') as mock_text:
            mock_text.return_value = MagicMock()
            
            # 4. Call target function inside the mock context
            try:
                search()
            except RuntimeError:
                raise
            except Exception:
                pass
            
            # 5. Oracle check — OUTSIDE the function call try/except, INSIDE the patch context
            for call in mock_text.call_args_list:
                captured = None
                if call.args and len(call.args) > 0:
                    captured = str(call.args[0])
                elif call.kwargs:
                    for v in call.kwargs.values():
                        captured = str(v)
                        break
                
                if captured is not None:
                    for pattern in _COMPILED_PATTERNS:
                        match = pattern.search(captured)
                        if match:
                            raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=match.pattern))
    



# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    b"' OR 1=1--",
    b"' UNION SELECT NULL,NULL,NULL--",
    b"' aNd '1'='1",
    b"admin'--",
    b"test'; SELECT 1--",
    b"' oR '1'='1' --",
    b"'/**/UNION/**/SELECT/**/1--",
    b"'UnIoN SeLeCt 1,2,3--",
    b"' OR 'a'='a",
    b"'; DROP TABLE users--",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-extremely-vulnerable-flask-app/fuzz_corpus/py_sql_injection_routes_account_py_33"
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