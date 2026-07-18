# Oraculum Harness Run

- Started: `2026-07-13T04:57:05`
- Repo: `python/gradio`
- Output dir: `output`

## [1/1] py/full-ssrf

- File: `gradio/image_utils.py:252`
- Target: `py_full_ssrf_gradio_image_utils_py_252`
- Oracle: `output/python/gradio/fuzz_oracles/py_full_ssrf_gradio_image_utils_py_252.json`
- Harness: `output/python/gradio/fuzz_targets/py_full_ssrf_gradio_image_utils_py_252.py`
- Corpus: `output/python/gradio/fuzz_corpus/py_full_ssrf_gradio_image_utils_py_252`

### System Prompt

````text
You are an expert security fuzzing engineer specializing in Python vulnerability research.
Your task is to complete an Atheris fuzz harness that detects sink-reachability bugs
(SSRF, path traversal, command injection, etc.) using a recorded_call oracle strategy.

## Your Role
You intercept a specific function call (the "sink") by mocking it, then inspect
the argument that reaches it. If the argument matches any forbidden pattern,
the oracle fires.

## Critical Oracle Rule — Read This First
The oracle fires on what REACHES the sink, not on what enters the function.
_COMPILED_PATTERNS must be applied ONLY to the argument captured at the patched
call (call.args or call.kwargs) — never to the input parameter itself.

Applying patterns to the input parameter is ALWAYS wrong for recorded_call strategy.
It causes the oracle to fire before the function executes, turning every seed
corpus entry into a false positive regardless of whether the vulnerability exists.

## Harness Completion Rules

### Structure
- Output a single complete Python file. No markdown. No explanation. No code fences.
- You may add helper functions, imports, or constants outside TestOneInput.
- Do not modify any section marked FIXED CONTRACTS.

### TestOneInput — Required Logic

1. INPUT GENERATION
   - Use FuzzedDataProvider to generate inputs for all tainted params based on
     the function signature.

   - STRING INPUTS REGULATION:
     * Always generate string/unicode inputs by consuming bytes and decoding them to preserve raw payloads:
       val = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
     * Do NOT use ConsumeUnicodeNoSurrogates() for arguments that need to match exact exploit patterns (like shell commands, import statement strings).

   - Buffer allocation strategy (inferred from signature):
       - MULTIPLE params → split the buffer proportionally by param count.
         For str/bytes params, divide remaining bytes evenly; consume the
         last str/bytes param with remaining bytes. Fixed-size types (int,
         float, bool) consume their natural byte width first, then split
         the remainder among str/bytes params.
       - FORBIDDEN: Do NOT use ConsumeIntInRange() to select a strategy
         index or branch — this prevents the fuzzer from mutating payload.

2. SKIP CONDITION
   - Apply the skip_hint early in TestOneInput.
   - If input does not meet minimum criteria, return immediately.
   - This avoids wasting fuzzer cycles on irrelevant inputs.
   - The skip condition filters INPUT only — it has no relation to the oracle check.

3. MOCK SETUP
   - Patch the exact target specified in patch_target.
   - Mock only the patched sink. Do NOT mock validation functions, input parsers,
     or any function called BEFORE the sink — those must execute with real logic
     so that the fuzzer tests actual data flow to the sink.
   - Mock return value must be realistic enough for the target function to continue
     executing past the patched call — use MagicMock with appropriate spec.
   - Use `with patch(...) as mock_obj:` scoping.

4. FUNCTION CALL
   - Call the target function inside the patch context.
   - Wrap in try/except Exception: pass — but keep RuntimeError re-raise outside.

5. ORACLE CHECK  ← must be OUTSIDE the function call try/except, INSIDE the patch context
   - After the target function call, iterate mock_obj.call_args_list.
   - For each call, extract the captured argument:
     * Check call.args[target_arg_index] first.
     * Fall back to call.kwargs.get(target_arg_name) if args is empty.
     * kwargs fallback must use a string key ("url", "request", etc.) — never None.
   - Convert captured to str before pattern matching.
   - Run every pattern in _COMPILED_PATTERNS against the captured value.
   - On any match: raise RuntimeError(_RAISE_MESSAGE)

6. EXCEPTION HANDLING
   - except RuntimeError: raise        → never swallow oracle signals
   - except Exception: pass            → swallow all other exceptions
   - Never use bare except.

### Input Generation Strategy
- Think about what values would cause the tainted param to reach the sink.
- Generate variations covering: scheme prefixes, IP formats, encoding variants,
  edge cases from trigger_patterns.
- Do not limit generation to only the seed corpus.

### What NOT to Do
- Do NOT run _COMPILED_PATTERNS against the input parameter — patterns must be
  applied only to the argument captured at the sink.
- Do NOT mock any function called before the sink — validation and parsing logic
  must run with real behavior.
- Do NOT use call.kwargs.get(None) — always use a named string key.
- Do NOT place the oracle check inside the function call try/except block —
  RuntimeError from the oracle must propagate to Atheris.

### Seed Corpus Rules (CRITICAL)
- Define _SEED_CORPUS as a module-level list OUTSIDE TestOneInput.
- Populate it with at least 6 bypass-oriented entries derived from
  trigger_patterns and condition_desc.
- Entries must be designed to reach the sink and trigger oracle patterns.
  Cover: internal IPs, metadata endpoints, file URIs, mixed-case schemes,
  encoded variants.
- NEVER reference _SEED_CORPUS inside TestOneInput.
- NEVER use ConsumeBool() or ConsumeIntInRange() to select from _SEED_CORPUS.
- Seeds are exported to disk at startup (see __main__ block in template).
  libFuzzer will mutate their raw bytes directly — this is how coverage-guided
  mutation works correctly.

## Quality Checklist (verify before outputting)
[ ] All tainted params are fuzzed via FuzzedDataProvider, consuming len(data) for single param
[ ] No ConsumeBool()/ConsumeIntInRange() used to index into a seed list inside TestOneInput
[ ] _SEED_CORPUS defined at module level, outside TestOneInput
[ ] _SEED_CORPUS has at least 6 entries derived from trigger_patterns
[ ] String inputs generated using ConsumeBytes().decode() instead of ConsumeUnicodeNoSurrogates() to preserve seeds
[ ] skip_condition applied to input only — not used in oracle
[ ] patch_target mocked correctly, no pre-sink functions mocked
[ ] Oracle check is OUTSIDE the function call try/except
[ ] Oracle check applies _COMPILED_PATTERNS to captured sink argument, NOT to input
[ ] Both call.args and call.kwargs checked with string key (never None)
[ ] captured converted to str before pattern matching
[ ] RuntimeError is re-raised, never swallowed
[ ] No markdown or explanation in output
````


### User Prompt

````text
Complete the following partial Atheris harness by filling in the TestOneInput body.
Output the complete Python script only. No markdown, no explanation.

# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/full-ssrf
# function : extract_svg_content
# file     : gradio/image_utils.py
# ================================================================
import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/gradio"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from gradio.image_utils import extract_svg_content


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("http://169\\.254\\.169\\.254.*", re.IGNORECASE),

    re.compile("http://127\\.0\\.0\\.1.*", re.IGNORECASE),

    re.compile("http://localhost.*", re.IGNORECASE),

    re.compile("http://\\[::1\\].*", re.IGNORECASE),

    re.compile("http://10\\.\\d+\\.\\d+\\.\\d+.*", re.IGNORECASE),

    re.compile("http://172\\.(1[6-9]|2\\d|3[01])\\.\\d+\\.\\d+.*", re.IGNORECASE),

    re.compile("http://192\\.168\\.\\d+\\.\\d+.*", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_FULL-SSRF: SSRF attempt detected - captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "image_file", "index": 0, "type": "str | Path"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : httpx.get
# target_arg_index : 0
# target_arg_name  : url
# input_strategy   : direct_params
# signature        : def extract_svg_content(image_file: str | Path)
# condition        : URL matches SSRF attack patterns targeting internal services or metadata endpoints
# capture_what     : URL passed to httpx.get
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
    
    # [FILL HERE — follow the skeleton above]
    


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    # [FILL HERE — at least 6 bypass-attempt strings]
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/gradio/fuzz_corpus/py_full_ssrf_gradio_image_utils_py_252"
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
````


### LLM Response (Iteration 1)

````text
import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/gradio"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from gradio.image_utils import extract_svg_content


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("http://169\\.254\\.169\\.254.*", re.IGNORECASE),

    re.compile("http://127\\.0\\.0\\.1.*", re.IGNORECASE),

    re.compile("http://localhost.*", re.IGNORECASE),

    re.compile("http://\\[::1\\].*", re.IGNORECASE),

    re.compile("http://10\\.\\d+\\.\\d+\\.\\d+.*", re.IGNORECASE),

    re.compile("http://172\\.(1[6-9]|2\\d|3[01])\\.\\d+\\.\\d+.*", re.IGNORECASE),

    re.compile("http://192\\.168\\.\\d+\\.\\d+.*", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_FULL-SSRF: SSRF attempt detected - captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "image_file", "index": 0, "type": "str | Path"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : httpx.get
# target_arg_index : 0
# target_arg_name  : url
# input_strategy   : direct_params
# signature        : def extract_svg_content(image_file: str | Path)
# condition        : URL matches SSRF attack patterns targeting internal services or metadata endpoints
# capture_what     : URL passed to httpx.get
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
    
    # 1. INPUT GENERATION
    image_file = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')

    # 2. SKIP CONDITION (None specified, so no skip)

    # 3. MOCK SETUP
    mock_response = MagicMock()
    mock_response.text = "<svg></svg>"
    with patch("httpx.get", return_value=mock_response) as mock_get:
        # 4. FUNCTION CALL
        try:
            extract_svg_content(image_file)
        except Exception:
            pass

        # 5. ORACLE CHECK (outside try/except, inside patch context)
        for call in mock_get.call_args_list:
            captured = None
            if call.args and len(call.args) > 0:
                captured = str(call.args[0])
            elif call.kwargs:
                captured = str(call.kwargs.get("url", ""))

            if captured:
                for pattern in _COMPILED_PATTERNS:
                    if pattern.match(captured):
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=pattern.pattern))

    # 6. EXCEPTION HANDLING
    # RuntimeError is not caught here, so it will propagate


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "http://169.254.169.254/latest/meta-data/",
    "HTTP://127.0.0.1:8080/admin",
    "http://LOCALHOST:9000/config",
    "http://[::1]/test",
    "http://10.0.0.1/internal",
    "http://172.16.0.1/secret",
    "http://192.168.1.1/private",
    "HtTp://169.254.169.254/metadata",
    "http://127.0.0.1:5000/api",
    "http://localhost.localdomain:8000/data"
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/gradio/fuzz_corpus/py_full_ssrf_gradio_image_utils_py_252"
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
````

- Result: `generated`
- Harness: `output/python/gradio/fuzz_targets/py_full_ssrf_gradio_image_utils_py_252.py`

## Summary

- Selected: `1`
- Generated: `1`
- Skipped: `0`
- Failed: `0`
- Status: `output/python/gradio/fuzz_targets/status.json`
