# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/template-injection
# function : try_hack_me
# file     : app/main.py
# ================================================================
import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-python-insecure-app"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from app.main import try_hack_me


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("<h1>Hello, \\{\\{.*?\\}\\}!</h1>", re.IGNORECASE),

    re.compile("<h1>Hello, \\{%.*?%\\}!</h1>", re.IGNORECASE),

    re.compile("\\{\\{.*?__class__.*?\\}\\}", re.IGNORECASE),

    re.compile("\\{\\{.*?__import__.*?\\}\\}", re.IGNORECASE),

    re.compile("\\{\\{config.*?\\}\\}", re.IGNORECASE),

    re.compile("\\{%.*?for.*?%\\}", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_TEMPLATE_INJECTION: SSTI detected in Template source — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "name", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : jinja2.Template
# target_arg_index : 0
# target_arg_name  : source
# input_strategy   : direct_params
# signature        : def try_hack_me(name: str)
# condition        : The template source string contains Jinja2 expression delimiters ({{ or {%) injected via the user-controlled name parameter within the HTML context
# capture_what     : template source string passed to jinja2.Template constructor
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
    # NOTE: For string inputs, use fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    #       instead of ConsumeUnicodeNoSurrogates() to preserve raw seed payloads.
    
    name = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    with patch('jinja2.Template') as mock_template:
        mock_template.return_value = MagicMock()
        mock_template.return_value.render.return_value = ""

        try:
            try_hack_me(name)
        except RuntimeError:
            raise
        except Exception:
            pass

        for call in mock_template.call_args_list:
            captured = None
            if call.args and len(call.args) > 0:
                captured = str(call.args[0])
            elif call.kwargs:
                captured = str(call.kwargs.get("source", ""))

            if captured is not None:
                for pattern in _COMPILED_PATTERNS:
                    match = pattern.search(captured)
                    if match:
                        raise RuntimeError(_RAISE_MESSAGE.format(
                            captured=captured,
                            matched_pattern=match.pattern
                        ))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "{{7*7}}",
    "{% for x in [1] %}x{% endfor %}",
    "{{''.__class__}}",
    "{{__import__('os').popen('id').read()}}",
    "{{config}}",
    "{% for i in range(1) %}a{% endfor %}",
    "{{ 7*7 }}",
    "{{Config}}",
    "{{config.__class__.__mro__}}",
    "{%  for  x  in  []  %}{%  endfor  %}",
    "{{config.items()}}",
    "{{request.application.__globals__}}",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-python-insecure-app/fuzz_corpus/py_template_injection_app_main_py_41"
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