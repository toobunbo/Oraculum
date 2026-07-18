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
    import dsvw as _target_mod
    from flask import Flask

# Create Flask app instance for test context
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

# === SEED CORPUS ===
_SEED_CORPUS = [
    "username=admin'--&password=anything",
    "username=admin' OR '1'='1&password=anything",
    "username=admin'; DROP TABLE users; --&password=anything",
    "username=admin' UNION SELECT username, password FROM admins--&password=anything",
    "username=%27%20OR%20%271%27=%271&password=anything",
    "username=admin' OR 1=1--&password=anything"
]

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    # Generate inputs
    username = fdp.ConsumeBytes(512).decode('utf-8', errors='ignore')
    password = fdp.ConsumeBytes(512).decode('utf-8', errors='ignore')
    
    query_params = {
        'username': username,
        'password': password
    }
    
    # Wrap in Flask Request Context
    with app.test_request_context(query_string=query_params):
        # Mock the cursor.execute method
        with patch('dsvw.ReqHandler.do_GET.cursor.execute', spec=True) as mock_execute:
            mock_execute.return_value = MagicMock()
            
            try:
                # Create instance and call target function
                handler = _target_mod.ReqHandler()
                handler.do_GET()
            except Exception:
                pass  # Swallow all exceptions except RuntimeError
            
            # Oracle check - outside try/except but inside patch context
            for call in mock_execute.call_args_list:
                captured = ""
                # Check positional args first
                if call.args:
                    captured = str(call.args[0])
                # Check keyword args if no positional args
                elif call.kwargs:
                    captured = str(call.kwargs.get('sql', ''))
                
                # Check patterns against captured argument
                for pattern in _COMPILED_PATTERNS:
                    if pattern.search(captured):
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=pattern.pattern))


if __name__ == "__main__":
    _CORPUS_DIR = "/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_sql_injection_dsvw_py_67"
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