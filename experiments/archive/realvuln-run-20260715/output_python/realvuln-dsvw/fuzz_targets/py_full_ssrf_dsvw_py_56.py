import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock
from urllib.parse import urlencode, urlparse, parse_qs



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-dsvw"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    import dsvw as _target_mod


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
    param_value = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    if not param_value.strip():
        return
    with patch('urllib.request.urlopen', MagicMock()) as mock_urlopen:
        try:
            handler = _target_mod.ReqHandler()
            handler.path = '/?include=' + param_value
            handler.wfile = MagicMock()
            handler.headers = {}
            handler.do_GET()
        except RuntimeError:
            raise
        except Exception:
            pass
        for call in mock_urlopen.call_args_list:
            captured = str(call.args[0]) if call.args else ""
            for pattern in _COMPILED_PATTERNS:
                if pattern.match(captured):
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=pattern.pattern))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "http://169.254.169.254/latest/meta-data/",
    "HTTP://127.0.0.1:8080/admin",
    "https://[::1]/secret",
    "hTTp://localhost:3000/api",
    "HTTPS://169.254.169.254/metadata",
    "http://127.0.0.1:5000/config",
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
                if isinstance(_seed, bytes):
                    _f.write(_seed)
                else:
                    _f.write(_seed.encode("utf-8"))

    if _CORPUS_DIR not in sys.argv:
        sys.argv.append(_CORPUS_DIR)

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()