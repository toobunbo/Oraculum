import atheris
import sys
import re
import os
import asyncio
import json

from unittest.mock import patch, MagicMock


import pathlib


REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/vc-claude-code-seeded-v2-support-desk-fastapi"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from backend.app.support_operations import ticket_vault_stash_232


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("\"ref\"\\s*:\\s*\"[^\"]*\\.\\./", re.IGNORECASE),

    re.compile("\"ref\"\\s*:\\s*\"[^\"]*\\.\\.\\\\", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_PATH_INJECTION: directory traversal in write_text payload — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "request", "index": 0, "type": "Request"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : pathlib.Path.write_text
# target_arg_index : 0
# target_arg_name  : data
# input_strategy   : direct_params
# signature        : def ticket_vault_stash_232(request: Request, gate_ref: None)
# condition        : The JSON payload written to the file contains a 'ref' field value with directory traversal sequences (../ or ..\\), confirming the unsanitized user input reached the sink.
# capture_what     : JSON string passed to write_text, which contains the user-controlled ref value including any traversal sequences
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
    
    body_bytes = fdp.ConsumeRemainingBytes()
    
    mock_request = MagicMock()
    
    async def mock_body():
        return body_bytes
    
    async def mock_json():
        try:
            return json.loads(body_bytes.decode('utf-8', errors='ignore'))
        except Exception:
            return {}
    
    mock_request.body = mock_body
    mock_request.json = mock_json
    
    with patch('pathlib.Path.write_text', return_value=None) as mock_write:
        try:
            result = ticket_vault_stash_232(mock_request, None)
            if asyncio.iscoroutine(result):
                asyncio.run(result)
        except RuntimeError:
            raise
        except Exception:
            pass
        
        for call in mock_write.call_args_list:
            captured = None
            if call.args and len(call.args) > 0:
                captured = call.args[0]
            elif call.kwargs:
                captured = call.kwargs.get("data")
            
            if captured is not None:
                captured_str = str(captured)
                for pattern in _COMPILED_PATTERNS:
                    match = pattern.search(captured_str)
                    if match:
                        raise RuntimeError(_RAISE_MESSAGE.format(
                            captured=captured_str,
                            matched_pattern=match.group()
                        ))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    b'{"ref": "../etc/passwd"}',
    b'{"ref": "..\\windows\\system32"}',
    b'{"ref"  :  "../tmp/evil"}',
    b'{"REF": "../etc/shadow"}',
    b'{"ref": "....//....//etc/passwd"}',
    b'{"ref": "..\\\\..\\\\windows"}',
    b'{"ticket_id": 1, "ref": "../etc/hosts"}',
    b'{"ref": "safe/../../escape"}',
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/vc-claude-code-seeded-v2-support-desk-fastapi/fuzz_corpus/py_path_injection_backend_app_support_operations_py_57"
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