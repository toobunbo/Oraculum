import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/vc-claude-code-seeded-v2-hr-payroll-django"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "hr_portal.settings")
django.setup()

with atheris.instrument_imports():

    from hr_portal.payroll_operations import payroll_formula_cast_252


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("__class__\\s*\\.\\s*__(mro|base|subclasses)__", re.IGNORECASE),

    re.compile("__subclasses__\\s*\\(", re.IGNORECASE),

    re.compile("__init__\\s*\\.\\s*__globals__", re.IGNORECASE),

    re.compile("__globals__\\s*\\[", re.IGNORECASE),

    re.compile("__builtins__\\s*\\[", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_CODE_INJECTION: sandbox escape via dunder traversal detected in eval argument — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "request", "index": 0, "type": "django.http.HttpRequest"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : builtins.eval
# target_arg_index : 0
# target_arg_name  : source
# input_strategy   : direct_params
# signature        : def payroll_formula_cast_252(request)
# condition        : The captured eval source argument contains Python dunder attribute traversal patterns (e.g., __class__.__mro__, __subclasses__, __globals__, __init__) used to bypass the restricted __builtins__ sandbox
# capture_what     : first argument (expr) passed to eval, which contains user-controlled expression string
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



def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    payload = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')
    
    mock_request = MagicMock()
    mock_request.method = 'POST'
    mock_request.body = payload.encode('utf-8')
    mock_request.POST = {'formula': payload}
    mock_request.GET = {'formula': payload}
    mock_request.data = {'formula': payload}
    mock_request.META = {'CONTENT_TYPE': 'application/x-www-form-urlencoded'}
    mock_request.content_type = 'application/x-www-form-urlencoded'
    mock_request._dont_enforce_csrf_checks = True
    
    with patch('builtins.eval') as mock_eval:
        mock_eval.return_value = None
        
        try:
            payroll_formula_cast_252(mock_request)
        except RuntimeError:
            raise
        except Exception:
            pass
        
        for call in mock_eval.call_args_list:
            captured = None
            if call.args and len(call.args) > 0:
                captured = str(call.args[0])
            elif call.kwargs:
                captured = str(call.kwargs.get("source", ""))
            
            if captured:
                for pattern in _COMPILED_PATTERNS:
                    match = pattern.search(captured)
                    if match:
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=match.pattern))
    


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "__class__.__mro__",
    "__class__ . __base__",
    "__subclasses__  ()",
    "__init__ . __globals__",
    "__globals__ [\"__builtins__\"]",
    "__builtins__ [\"__import__\"]",
    "__CLASS__.\n__Mro__",
    "\"\".__class__.__mro__[1].__subclasses__()",
    "().__class__.__base__.__subclasses__()",
    "__init__ .\t__globals__",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/vc-claude-code-seeded-v2-hr-payroll-django/fuzz_corpus/py_code_injection_hr_portal_payroll_operations_py_97"
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