import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/vc-claude-code-seeded-v2-healthcare-clinic-django"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from clinic_portal.patient_operations import patient_formula_cast_251


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("amount\\.__[a-z_]+", re.IGNORECASE),

    re.compile("fee\\.__[a-z_]+", re.IGNORECASE),

    re.compile("amount\\.__class__", re.IGNORECASE),

    re.compile("fee\\.__class__", re.IGNORECASE),

    re.compile("\\.__[a-z_]+__\\(", re.IGNORECASE),

    re.compile("\\.__mro__", re.IGNORECASE),

    re.compile("\\.__subclasses__", re.IGNORECASE),

    re.compile("\\.__bases__", re.IGNORECASE),

    re.compile("\\.__globals__", re.IGNORECASE),

    re.compile("\\.__builtins__", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_CODE_INJECTION: dangerous expression reached eval — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "request", "index": 0, "type": "HttpRequest"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : clinic_portal.patient_operations.eval
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def patient_formula_cast_251(request)
# condition        : The captured first argument to eval contains attribute access patterns (dot notation) or dunder attribute access on the provided local variables, indicating an attempt to escape the restricted eval environment
# capture_what     : the expression string passed as the first argument to eval, originating from user-controlled input
# skip_hint        : False
# ========================================


_SEED_CORPUS = [
    b"amount.__class__",
    b"fee.__mro__",
    b"amount.__subclasses__()",
    b"(amount).__bases__",
    b"fee.__globals__",
    b"amount.__builtins__",
    b"amount.__init__",
    b"Fee.__class__",
    b"amount .__class__",
    b"fee.\x5f\x5fclass\x5f\x5f",
    b"amount.__dict__",
    b"fee.__subclasses__()",
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    raw = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    mock_request = MagicMock()
    mock_request.GET = {
        'formula': raw,
        'expression': raw,
        'expr': raw,
        'amount': raw,
        'fee': raw,
        'value': raw,
    }
    mock_request.POST = {
        'formula': raw,
        'expression': raw,
        'expr': raw,
        'amount': raw,
        'fee': raw,
        'value': raw,
    }
    mock_request.body = raw.encode('utf-8', errors='ignore')
    mock_request.method = 'POST'
    mock_request.META = {}
    mock_request.FILES = {}
    mock_request.COOKIES = {}
    mock_request.content_type = 'application/x-www-form-urlencoded'

    with patch('clinic_portal.patient_operations.eval') as mock_eval:
        mock_eval.return_value = 0

        try:
            patient_formula_cast_251(mock_request)
        except RuntimeError:
            raise
        except Exception:
            pass

        for call in mock_eval.call_args_list:
            captured = None
            if call.args and len(call.args) > 0:
                captured = str(call.args[0])

            if captured:
                for pattern in _COMPILED_PATTERNS:
                    m = pattern.search(captured)
                    if m:
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=m.pattern))


if __name__ == "__main__":
    _CORPUS_DIR = "output/python/vc-claude-code-seeded-v2-healthcare-clinic-django/fuzz_corpus/py_code_injection_clinic_portal_patient_operations_py_88"
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