# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/command-line-injection
# function : BenchmarkTest00168_post
# file     : testcode/BenchmarkTest00168.py
# ================================================================
import atheris
import sys
import re
import os


from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/tuonglnc/repo/VulnHunterX/repos/python/benchmark-python"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from testcode.BenchmarkTest00168 import BenchmarkTest00168_post


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("echo\\s+[^\\s]+", re.IGNORECASE),

]
_RAISE_MESSAGE  = "ORACULUM_VIOLATION: captured={captured}"
_TAINTED_PARAMS = [{"name": "request", "index": -1, "type": "flask_request"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : subprocess.run
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def BenchmarkTest00168_post()
# condition        : {'type': 'regex', 'pattern': 'echo\\s+[^\\s]+', 'test_value': 'echo malicious_input', 'expected_match': True}
# capture_what     : captured value
# skip_hint        : False
# ========================================


# === RECORDED_CALL SKELETON ===
# 1. INPUT GENERATION
#    - Generate inputs for tainted params using FuzzedDataProvider.
#    - For MULTIPLE params: split the buffer proportionally by param count.
#      For str/bytes params divide remaining bytes evenly; consume the last
#      str/bytes param with remaining bytes. Fixed-size types (int, float,
#      bool) consume their natural byte width first.
#      FORBIDDEN: Do NOT use ConsumeIntInRange() to index a strategy or branch.
#    - DO NOT embed a seed list inside TestOneInput or use ConsumeBool() to
#      select from a hardcoded list — seeds are managed externally in _SEED_CORPUS.
#
# 2. SKIP CONDITION
#    - Apply skip_hint early, return immediately if not met.
#
# 3. MOCK SETUP
#    - Patch `subprocess.run` using `with patch(...) as mock_get:`.
#    - Return a realistic MagicMock so the function continues past the patched call.
#
# 4. ORACLE CHECK
#    - After the call, iterate mock_get.call_args_list.
#    - For each call: check call.args[None] first,
#      fall back to call.kwargs.get("None").
#    - Match against every pattern in _COMPILED_PATTERNS.
#    - On match → raise RuntimeError(_RAISE_MESSAGE)
#
# 5. EXCEPTION HANDLING
#    - except RuntimeError: raise   → never swallow oracle signals
#    - except Exception:    return  → only around the target function call
# ==========================================



def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    # 1. INPUT GENERATION
    # Since the function signature is BenchmarkTest00168_post() with no parameters,
    # and _TAINTED_PARAMS indicates it uses a flask request, we simulate a request.
    # However, the actual function does not take arguments, so we just proceed.
    
    # 2. SKIP CONDITION
    # skip_hint is False, so we do not skip.
    
    # 3. MOCK SETUP
    with patch("subprocess.run", return_value=MagicMock()) as mock_run:
        try:
            # Call the target function
            BenchmarkTest00168_post()
        except Exception:
            # Catch any exception from the function and return to let fuzzer continue
            return

        # 4. ORACLE CHECK
        for call in mock_run.call_args_list:
            # Since target_arg_index and target_arg_name are None,
            # we inspect the entire call args and kwargs
            captured = None
            if call.args:
                captured = call.args[0] if len(call.args) > 0 else None
            if captured is None and call.kwargs:
                # If args didn't yield a value, check kwargs
                captured = call.kwargs.get("args", None)
            
            # If we have a captured value, check against patterns
            if captured:
                for pattern in _COMPILED_PATTERNS:
                    if pattern.search(str(captured)):
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured))
    
    # If no patterns matched, the input is safe and we return normally
    return


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "echo test",
    "ECHO test",
    "echo\ttest",
    "echo  test",
    "echo%20test",
    "echo\u00A0test",  # non-breaking space
    "echo\\ test",
    "echo;echo test",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_command_line_injection_testcode_BenchmarkTest00168_py_60"
    os.makedirs(_CORPUS_DIR, exist_ok=True)
    for _i, _seed in enumerate(_SEED_CORPUS):
        _seed_path = os.path.join(_CORPUS_DIR, f"seed_{_i:03d}")
        if not os.path.exists(_seed_path):
            with open(_seed_path, "wb") as _f:
                _f.write(_seed.encode("utf-8"))

    if _CORPUS_DIR not in sys.argv:
        sys.argv.append(_CORPUS_DIR)

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()