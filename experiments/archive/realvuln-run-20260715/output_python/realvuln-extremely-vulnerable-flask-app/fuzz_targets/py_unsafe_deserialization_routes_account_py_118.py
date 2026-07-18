import atheris
import sys
import re
import os
import base64

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-extremely-vulnerable-flask-app"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from routes.account import before_request
    from app import app


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("__reduce__", re.IGNORECASE),

    re.compile("cos\\nsystem", re.IGNORECASE),

    re.compile("csubprocess\\n", re.IGNORECASE),

    re.compile("ceval\\n", re.IGNORECASE),

    re.compile("c__builtin__\\n", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_UNSAFE_DESERIALIZATION: unsafe pickle payload reached loads() sink — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "preferences", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : routes.account.loads
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def before_request()
# condition        : The bytes passed to loads() contain pickle GLOBAL opcodes referencing dangerous modules (os, subprocess, eval, __builtin__) or __reduce__ attribute, confirming an unsafe deserialization exploit payload reached the sink without sanitization.
# capture_what     : raw bytes passed to loads() after base64 decoding of the user-controlled preferences cookie
# skip_hint        : len(preferences) < 2
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
    
    param_preferences = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    
    # 2. Skip condition
    if len(param_preferences) < 2:
        return
    
    query_params = {
        
        "preferences": param_preferences,
        
    }
    
    # 3. Wrap in Flask Request Context with mock
    with app.test_request_context(query_string=query_params):
        with patch("routes.account.loads") as mock_loads:
            mock_loads.return_value = MagicMock()
            
            # 4. Call target function inside the mock context
            try:
                before_request()
            except Exception:
                pass
            
            # 5. Oracle check — OUTSIDE function call try/except, INSIDE patch context
            for call in mock_loads.call_args_list:
                captured = None
                if call.args and len(call.args) > 0:
                    captured = call.args[0]
                
                if captured is not None:
                    if isinstance(captured, bytes):
                        captured_str = captured.decode('latin-1', errors='replace')
                    else:
                        captured_str = str(captured)
                    
                    for pattern in _COMPILED_PATTERNS:
                        if pattern.search(captured_str):
                            raise RuntimeError(_RAISE_MESSAGE.format(
                                captured=captured_str[:200],
                                matched_pattern=pattern.pattern
                            ))



# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    base64.b64encode(b"cos\nsystem\n(S'id'\ntR.").decode('ascii'),
    base64.b64encode(b"csubprocess\nPopen\n(S'id'\ntR.").decode('ascii'),
    base64.b64encode(b"ceval\n(S'__import__(\"os\").system(\"id\")'\ntR.").decode('ascii'),
    base64.b64encode(b"c__builtin__\neval\n(S'1'\ntR.").decode('ascii'),
    base64.b64encode(b"Cos\nSystem\n(S'id'\ntR.").decode('ascii'),
    base64.b64encode(b"CSUBPROCESS\nPopen\n(S'id'\ntR.").decode('ascii'),
    base64.b64encode(b"CEval\n(S'1'\ntR.").decode('ascii'),
    base64.b64encode(b"C__BUILTIN__\neval\n(S'1'\ntR.").decode('ascii'),
    base64.b64encode(b"__reduce__\n").decode('ascii'),
    base64.b64encode(b"__REDUCE__\n").decode('ascii'),
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-extremely-vulnerable-flask-app/fuzz_corpus/py_unsafe_deserialization_routes_account_py_118"
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