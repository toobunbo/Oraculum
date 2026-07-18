# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/code-injection
# function : evaluate
# file     : app.py
# ================================================================
import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock


import builtins


REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-damn-vulnerable-flask-application"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from app import evaluate
    from app import app


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("__import__\\s*\\(", re.IGNORECASE),

    re.compile("exec\\s*\\(", re.IGNORECASE),

    re.compile("eval\\s*\\(", re.IGNORECASE),

    re.compile("os\\.system\\s*\\(", re.IGNORECASE),

    re.compile("subprocess\\.", re.IGNORECASE),

    re.compile("open\\s*\\(['\"]", re.IGNORECASE),

    re.compile("__builtins__", re.IGNORECASE),

    re.compile("getattr\\s*\\(", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_CODE_INJECTION: untrusted input reached eval() — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "expression", "index": -1, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : builtins.eval
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def evaluate()
# condition        : The captured eval argument contains Python code constructs indicative of injection (e.g., __import__, exec, os.system calls, or attribute chains accessing dangerous modules), confirming that untrusted user input reached the eval sink without sanitization.
# capture_what     : expression string passed to eval() from request.form['expression']
# skip_hint        : False
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


_SEED_CORPUS = [
    '__import__("os").system("id")',
    'Exec ("import os; os.system(\'id\')")',
    'Eval ("__import__(\'os\').system(\'id\')")',
    'os .system("cat /etc/passwd")',
    'subprocess .call(["ls", "-la"])',
    "open ('/etc/passwd').read()",
    '__builtins__["__import__"]("os")',
    'getattr (__builtins__, "__import__")("os")',
    '__IMPORT__("os")',
    'OS.system("id")',
    'Subprocess.Popen(["id"])',
    "open (\"/etc/shadow\")",
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    # NOTE: For string inputs, use fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    #       instead of ConsumeUnicodeNoSurrogates() to preserve raw seed payloads.
    
    # 1. Generate inputs from fdp
    
    param_expression = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    
    form_data = {
        "expression": param_expression,
    }
    
    # 2. Wrap in Flask Request Context with form data (request.form['expression'])
    with app.test_request_context(data=form_data, method='POST', content_type='application/x-www-form-urlencoded'):
        # 3. Mock the patch target
        with patch('builtins.eval', MagicMock(return_value=None)) as mock_eval:
            # 4. Call target function inside the mock context
            try:
                evaluate()
            except RuntimeError:
                raise
            except Exception:
                pass

            # 5. Oracle check — OUTSIDE function call try/except, INSIDE patch context
            for call in mock_eval.call_args_list:
                captured = None
                if call.args and len(call.args) > 0:
                    captured = str(call.args[0])
                if captured is not None:
                    for pattern in _COMPILED_PATTERNS:
                        if pattern.search(captured):
                            raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=pattern.pattern))



if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-damn-vulnerable-flask-application/fuzz_corpus/py_code_injection_app_py_120"
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