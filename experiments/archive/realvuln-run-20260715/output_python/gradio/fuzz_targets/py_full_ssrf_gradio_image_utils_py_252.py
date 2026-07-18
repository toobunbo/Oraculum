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
                if isinstance(_seed, bytes):
                    _f.write(_seed)
                else:
                    _f.write(_seed.encode("utf-8"))

    if _CORPUS_DIR not in sys.argv:
        sys.argv.append(_CORPUS_DIR)

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()