# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/incomplete-url-substring-sanitization
# function : fetch
# file     : Other/url_fetch.py
# ================================================================
import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock


import urllib.request


REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-vulnerable-python-apps"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from Other.url_fetch import fetch, app


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("^https://insecurewebapp\\.com@[a-zA-Z0-9]", re.IGNORECASE),

    re.compile("^https://insecurewebapp\\.com\\.[a-zA-Z0-9]", re.IGNORECASE),

    re.compile("https://insecurewebapp\\.com@.*?(?:127\\.0\\.0\\.1|192\\.168\\.|10\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.)", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_INCOMPLETE_URL_SUBSTRING_SANITIZATION: SSRF via prefix-bypass URL — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "url", "index": -1, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : urllib.request.urlopen
# target_arg_index : 0
# target_arg_name  : url
# input_strategy   : flask_view
# signature        : def fetch()
# condition        : The URL passed to urlopen starts with the allowed prefix 'https://insecurewebapp.com' but contains an '@' authority override or a subdomain suffix, indicating the prefix-only check was bypassed for SSRF
# capture_what     : full URL string passed to urlopen that bypassed the startswith sanitization
# skip_hint        : not url.startswith('https://insecurewebapp.com')
# ========================================


# === RECORDED_CALL SKELETON ===



def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    # 1. Generate inputs from fdp
    
    param_url = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    
    # 2. Apply skip_hint — filter INPUT only
    if not param_url.startswith('https://insecurewebapp.com'):
        return
    
    query_params = {
        "url": param_url,
    }
    
    # 3. Wrap in Flask Request Context, mock sink, call target, check oracle
    with app.test_request_context(query_string=query_params):
        with patch('urllib.request.urlopen', return_value=MagicMock()) as mock_urlopen:
            try:
                fetch()
            except RuntimeError:
                raise
            except Exception:
                pass
            
            # 5. Oracle check — OUTSIDE function call try/except, INSIDE patch context
            for call in mock_urlopen.call_args_list:
                captured = None
                if call.args and len(call.args) > 0:
                    captured = call.args[0]
                elif call.kwargs:
                    captured = call.kwargs.get("url")
                
                if captured is None:
                    continue
                
                captured_str = str(captured)
                for pattern in _COMPILED_PATTERNS:
                    m = pattern.search(captured_str)
                    if m:
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured_str, matched_pattern=m.pattern))



# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    b"https://insecurewebapp.com@127.0.0.1",
    b"https://insecurewebapp.com@192.168.1.1",
    b"https://insecurewebapp.com@10.0.0.1",
    b"https://insecurewebapp.com@172.16.0.1",
    b"https://insecurewebapp.com.evil.com",
    b"https://INSECUREWEBAPP.COM@127.0.0.1",
    b"https://insecurewebapp.com@172.31.255.255",
    b"https://insecurewebapp.com.attacker.net/path",
    b"https://insecurewebapp.com@10.10.10.10/admin",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-vulnerable-python-apps/fuzz_corpus/py_incomplete_url_substring_sanitization_Other_url_fetch_py_14"
    os.makedirs(_CORPUS_DIR, exist_ok=True)
    for _i, _seed in enumerate(_SEED_CORPUS):
        _seed_path = os.path.join(_CORPUS_DIR, f"seed_{_i:03d}")
        if not os.path.exists(_seed_path):
            with open(_seed_path, "wb") as _f:
                _f.write(_seed)

    if _CORPUS_DIR not in sys.argv:
        sys.argv.append(_CORPUS_DIR)

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()