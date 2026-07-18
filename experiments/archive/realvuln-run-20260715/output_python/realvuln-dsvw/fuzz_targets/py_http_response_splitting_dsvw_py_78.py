import atheris
import sys
import re
import os
from unittest.mock import patch, MagicMock
from io import BytesIO

REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-dsvw"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():
    import dsvw as _target_mod
    from http.server import BaseHTTPRequestHandler

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

# Create a minimal HTTP request environment for testing
class MockRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, request_data):
        self.rfile = BytesIO(request_data)
        self.wfile = BytesIO()
        self.raw_requestline = self.rfile.readline()
        self.error_content_type = "text/html"
        self.error_message_format = ""
        self.server = MagicMock()
        self.server.server_name = "test"
        self.server.server_port = 80
        self.client_address = ("127.0.0.1", 80)
        self.headers = {}

    def setup(self):
        pass

    def handle(self):
        pass

    def log_message(self, format, *args):
        pass

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    # Generate a raw HTTP request with fuzzed charset parameter
    charset_value = fdp.ConsumeBytes(512).decode('utf-8', errors='ignore')
    request_data = (
        b"GET / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: text/html; charset=" + charset_value.encode('utf-8', errors='ignore') + b"\r\n"
        b"\r\n"
    )
    
    # Create handler instance
    handler = MockRequestHandler(request_data)
    
    # Parse the request
    try:
        handler.parse_request()
    except:
        return
    
    # Mock the send_header method to capture Content-Type header values
    with patch('http.server.BaseHTTPRequestHandler.send_header', spec=True) as mock_send_header:
        try:
            # Call the target function
            handler.do_GET()
        except Exception:
            pass  # Swallow all exceptions except RuntimeError
        
        # Oracle check - outside the function call try/except
        for call in mock_send_header.call_args_list:
            # Extract the message argument (index 1)
            captured = None
            if call.args and len(call.args) > 1:
                captured = str(call.args[1])
            elif call.kwargs:
                captured = str(call.kwargs.get('message', ''))
            
            if captured is not None:
                # Check against all compiled patterns
                for pattern in _COMPILED_PATTERNS:
                    if pattern.search(captured):
                        raise RuntimeError(_RAISE_MESSAGE.format(
                            captured=captured, 
                            matched_pattern=pattern.pattern
                        ))

# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    "utf-8\r\nX-Injected-Header: test",
    "utf-8\n\rX-Injected-Header: test", 
    "utf-8\rX-Injected-Header: test",
    "utf-8\nX-Injected-Header: test",
    "ascii%0d%0aX-Header:%20test",
    "iso-8859-1\\u000d\\u000aX-Test:%20value"
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
                if isinstance(_seed, bytes):
                    _f.write(_seed)
                else:
                    _f.write(_seed.encode("utf-8"))

    if _CORPUS_DIR not in sys.argv:
        sys.argv.append(_CORPUS_DIR)

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()