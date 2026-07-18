import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/vc-claude-code-seeded-v2-support-desk-fastapi"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from backend.app.support_operations import ticket_vault_stash_232


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("\\.{2}[/\\\\]", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_PATH-INJECTION: directory traversal detected in mkdir path — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "request", "index": 0, "type": "Request"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : pathlib.Path.mkdir
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def ticket_vault_stash_232(request: Request, gate_ref: None)
# condition        : The captured Path object's string representation contains directory traversal sequences (../ or ..\)
# capture_what     : Path object (self) representing target.parent, containing the unsanitized directory traversal path
# skip_hint        : False
# ========================================


# === RECORDED_CALL SKELETON ===



def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    path_payload = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')
    
    mock_request = MagicMock()
    mock_request.json.return_value = {
        "path": path_payload,
        "name": path_payload,
        "dir": path_payload,
        "directory": path_payload,
        "folder": path_payload,
        "destination": path_payload,
        "target": path_payload,
        "file_path": path_payload,
        "filepath": path_payload,
        "location": path_payload,
        "base_dir": path_payload,
        "vault_path": path_payload,
        "stash_path": path_payload,
    }
    mock_request.body.return_value = path_payload.encode('utf-8', errors='ignore')
    
    with patch('pathlib.Path.mkdir') as mock_mkdir:
        mock_mkdir.return_value = None
        
        try:
            ticket_vault_stash_232(mock_request, None)
        except Exception:
            pass
        
        for call in mock_mkdir.call_args_list:
            captured = None
            if call.args and len(call.args) > 0:
                captured = str(call.args[0])
            
            if captured:
                for pattern in _COMPILED_PATTERNS:
                    match = pattern.search(captured)
                    if match:
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=match.pattern))
    


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    "../../etc/passwd",
    "..\\..\\windows\\system32",
    "....//....//etc/shadow",
    "..\\/..\\/tmp/secret",
    "  ../  ../  var/log",
    "..././..././etc/passwd",
    "../../../home/user/.ssh",
    "..%2f..%2fetc%2fpasswd",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/vc-claude-code-seeded-v2-support-desk-fastapi/fuzz_corpus/py_path_injection_backend_app_support_operations_py_56"
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