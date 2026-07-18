import atheris
import sys
import re
import os



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-damn-vulnerable-flask-application"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from app import sayhi
    from app import app


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("__class__", re.IGNORECASE),

    re.compile("__mro__", re.IGNORECASE),

    re.compile("__subclasses__", re.IGNORECASE),

    re.compile("__globals__", re.IGNORECASE),

    re.compile("__builtins__", re.IGNORECASE),

    re.compile("<Config", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_TEMPLATE_INJECTION: SSTI payload evaluated in render_template_string output — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "name", "index": -1, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : return_value
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def sayhi()
# condition        : The return value contains introspection attributes (e.g., __class__, __mro__, __subclasses__, __globals__, __builtins__) or Flask config markers (<Config) that prove the injected Jinja2 expression was evaluated by the template engine, confirming SSTI.
# capture_what     : return value of the sayhi Flask view function, which is the rendered output of render_template_string
# skip_hint        : not name
# ========================================


# === RETURN_VALUE SKELETON ===
# TODO: Complete TestOneInput following these steps:
# 1. Generate inputs using FuzzedDataProvider.
# 2. Apply skip_hint (if applicable).
# 3. Call target function directly and capture the return value.
# 4. Extract string content from the return value (based on capture_what).
# 5. Compare captured string against _COMPILED_PATTERNS.
# 6. Propagate RuntimeError; swallow other exceptions.
# ==========================================



def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    # NOTE: For string inputs, use fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    #       instead of ConsumeUnicodeNoSurrogates() to preserve raw seed payloads.
    
    # 1. Generate inputs from fdp
    
    param_name = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')
    
    # 2. Apply skip_hint
    if not param_name:
        return
    
    query_params = {
        
        "name": param_name,
        
    }
    
    # 3. Wrap in Flask Request Context and call target
    with app.test_request_context(query_string=query_params):
        try:
            result = sayhi()
        except RuntimeError:
            raise
        except Exception:
            return
    
    # 4. Extract string content from return value
    if result is None or not isinstance(result, str):
        return
    
    # 5. Oracle check — OUTSIDE the try/except
    for pattern in _COMPILED_PATTERNS:
        match = pattern.search(result)
        if match:
            raise RuntimeError(_RAISE_MESSAGE.format(captured=result[:200], matched_pattern=match.group()))
    


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    b"{{__class__}}",
    b"{{''|attr('__class__')}}",
    b"{{lipsum.__globals__}}",
    b"{{cycler.__init__.__globals__.__builtins__}}",
    b"{{config.__class__.__mro__}}",
    b"{{request.application.__globals__}}",
    b"{{get_flashed_messages.__globals__.__builtins__}}",
    b"{{url_for.__globals__}}",
    b"{{namespace.__init__.__globals__}}",
    b"{{self.__init__.__globals__}}",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-damn-vulnerable-flask-application/fuzz_corpus/py_template_injection_app_py_205"
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