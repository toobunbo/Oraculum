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

    re.compile("\\(.*\\)", re.IGNORECASE),

    re.compile("\\[.*\\]", re.IGNORECASE),

    re.compile(".*\\*.*", re.IGNORECASE),

    re.compile(".*\\+.*", re.IGNORECASE),

    re.compile("\\{.*\\}", re.IGNORECASE),

    re.compile(".*\\?\\?.*", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_REGEX_INJECTION: Unescaped user input in regex pattern — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = []
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : re.findall
# target_arg_index : 0
# target_arg_name  : pattern
# input_strategy   : flask_view
# signature        : def do_GET(self)
# condition        : captured regex pattern contains user-controlled input without escaping, enabling ReDoS or data extraction
# capture_what     : regex pattern passed to re.findall
# skip_hint        : len(captured) > 1000 or '\\' in captured
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
    pattern_input = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    
    # 2. Apply skip condition
    if len(pattern_input) > 1000 or '\\' in pattern_input:
        return
    
    # 3. Mock the patch target
    with patch('re.findall', MagicMock()) as mock_findall:
        # 4. Call target function inside the mock context
        try:
            handler = _target_mod.ReqHandler()
            handler.path = '/?' + pattern_input
            handler.wfile = MagicMock()
            handler.headers = {}
            handler.do_GET()
        except RuntimeError:
            raise
        except Exception:
            pass
        
        # 5. Oracle check - outside try/except, inside patch context
        for call in mock_findall.call_args_list:
            captured = ""
            if call.args:
                captured = str(call.args[0])
            elif call.kwargs:
                captured = str(call.kwargs.get('pattern', ''))
            
            # Apply skip hint again to captured value
            if len(captured) > 1000 or '\\' in captured:
                continue
                
            for pattern in _COMPILED_PATTERNS:
                if pattern.search(captured):
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=pattern.pattern))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "(a|b)*",
    "[a-z]+",
    "a*b+c?",
    "{1,2}",
    "??",
    "(.*)",
    "[^a-z]",
    "a{10}",
    "a+?",
    "\\(test\\)",
    "(?:a|b)*",
    "[\\s\\S]*"
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_regex_injection_dsvw_py_26"
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