import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-dsvw"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    import dsvw as _target_mod


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("OR\\s+1\\s*=\\s*1", re.IGNORECASE),

    re.compile("UNION\\s+SELECT", re.IGNORECASE),

    re.compile("\\-\\-\\s*$", re.IGNORECASE),

    re.compile("['\"]\\s*(OR|AND)\\s*[\\w\\d]+\\s*=\\s*[\\w\\d]+", re.IGNORECASE),

    re.compile("(DROP|DELETE|UPDATE|INSERT)\\s+", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_SQL-INJECTION: SQL injection detected in query — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "self.path", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : dsvw.ReqHandler.do_GET.cursor.execute
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def do_GET(self)
# condition        : SQL query contains user-injected SQL fragments like ' OR 1=1-- or UNION SELECT
# capture_what     : SQL query string passed to execute
# skip_hint        : not ('id' in query and 'SELECT' in query)
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
    
    param_self_path = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    
    # 2. Apply skip_hint
    if 'id' not in param_self_path or 'SELECT' not in param_self_path:
        return
    
    # Create a mock request handler instance
    handler = _target_mod.ReqHandler()
    handler.path = param_self_path
    handler.request_version = "HTTP/1.1"
    handler.headers = {}
    
    # Mock the response methods to avoid actual network operations
    handler.send_response = MagicMock()
    handler.send_header = MagicMock()
    handler.end_headers = MagicMock()
    handler.wfile = MagicMock()
    
    # 3. Mock the patch target using patch/MagicMock
    with patch('dsvw.ReqHandler.do_GET.cursor.execute', new_callable=MagicMock) as mock_execute:
        try:
            # 4. Call target function inside the mock context
            handler.do_GET()
        except RuntimeError:
            raise
        except Exception:
            pass
        
        # 5. Compare mock call arguments against _COMPILED_PATTERNS
        for call in mock_execute.call_args_list:
            captured = ""
            if call.args:
                captured = str(call.args[0])
            # Convert captured to str before pattern matching
            for pattern in _COMPILED_PATTERNS:
                if pattern.search(captured):
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=pattern.pattern))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "id=1 OR 1=1",
    "id=1 UNION SELECT * FROM users",
    "id=1'; DROP TABLE users--",
    "id=1' OR '1'='1",
    "id=1' AND 1=1--",
    "id=1; INSERT INTO users VALUES ('admin', 'password')",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_sql_injection_dsvw_py_30"
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