import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock


import urllib.request


REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/vc-claude-code-seeded-v2-support-desk-fastapi"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from backend.app.support_operations import ticket_relay_probe_354


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("file://", re.IGNORECASE),

    re.compile("https?://localhost[:/]", re.IGNORECASE),

    re.compile("https?://127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}[:/]", re.IGNORECASE),

    re.compile("https?://10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}[:/]", re.IGNORECASE),

    re.compile("https?://172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}[:/]", re.IGNORECASE),

    re.compile("https?://192\\.168\\.\\d{1,3}\\.\\d{1,3}[:/]", re.IGNORECASE),

    re.compile("https?://169\\.254\\.169\\.254[:/]", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_FULL-SSRF: SSRF via urlopen — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "endpoint", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : urllib.request.urlopen
# target_arg_index : 0
# target_arg_name  : url
# input_strategy   : direct_params
# signature        : def ticket_relay_probe_354(endpoint: str, gate_ref: None)
# condition        : The captured URL argument to urlopen matches a pattern indicating a request to an internal IP, localhost, cloud metadata endpoint, or file:// scheme — confirming SSRF exploitation.
# capture_what     : Full URL string passed to urlopen as the first positional argument
# skip_hint        : False
# ========================================


# === RECORDED_CALL SKELETON ===



def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    endpoint = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')
    gate_ref = None
    
    with patch('urllib.request.urlopen') as mock_urlopen:
        mock_urlopen.return_value = MagicMock()
        mock_urlopen.return_value.read.return_value = b''
        mock_urlopen.return_value.status = 200
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_urlopen.return_value)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
        
        try:
            ticket_relay_probe_354(endpoint, gate_ref)
        except RuntimeError:
            raise
        except Exception:
            pass
        
        for call in mock_urlopen.call_args_list:
            captured = None
            if call.args and len(call.args) > 0:
                captured = str(call.args[0])
            elif call.kwargs:
                captured = str(call.kwargs.get("url", ""))
            
            if captured is None:
                continue
            
            for pattern in _COMPILED_PATTERNS:
                m = pattern.search(captured)
                if m:
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=m.pattern))



# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    b"file:///etc/passwd",
    b"http://localhost:8080/admin",
    b"http://127.0.0.1:22",
    b"http://10.0.0.1/secret",
    b"http://192.168.1.1/api",
    b"http://169.254.169.254/latest/meta-data/",
    b"FILE:///etc/shadow",
    b"HTTP://LocalHost:443/",
    b"http://172.16.0.1/internal",
    b"http://127.1.1.1:8080/debug",
    b"https://192.168.0.100:8443/manage",
    b"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
]


if __name__ == "__main__":
    _CORPUS_DIR = "output/python/vc-claude-code-seeded-v2-support-desk-fastapi/fuzz_corpus/py_full_ssrf_backend_app_support_operations_py_75"
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