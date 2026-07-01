import atheris
import sys
import re
import os



REPO_ROOT = "/home/tuonglnc/repo/Oraculum/benchmark/mini_benchmark/vhx_root/repos/python/mini-bench"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from target_app import get_safe_url


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("http://evil.com", re.IGNORECASE),

    re.compile("https://malicious.org", re.IGNORECASE),

    re.compile("//evil.com", re.IGNORECASE),

    re.compile("/\\x2fevil.com", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_URL_REDIRECTION: Unsafe URL returned — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "user_url", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : return_value
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def get_safe_url(user_url: str)
# condition        : Return value contains a malicious URL that bypasses sanitization and enables open redirection
# capture_what     : return value of the function
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
    user_url = fdp.ConsumeUnicodeNoSurrogates(len(data))
    try:
        result = get_safe_url(user_url)
    except RuntimeError:
        raise
    except Exception:
        return
    if result is None or not isinstance(result, str):
        return
    captured = result
    for pattern in _COMPILED_PATTERNS:
        if pattern.search(captured):
            raise RuntimeError(_RAISE_MESSAGE.format(captured=repr(captured), matched_pattern=pattern.pattern))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "http://evil.com",
    "https://malicious.org",
    "//evil.com",
    "/\x2fevil.com",
    "hTTp://eViL.CoM",
    "https://malicious.org/path?param=value",
    "http://evil.com:80/path",
    "//evil.com@trusted.com",
    "http://evil.com%23@example.com",
    "/\\/evil.com",
    "http:\\\\evil.com",
    "http://evil.com?redirect=http://trusted.com",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "benchmark/mini_benchmark/oraculum_output/python/mini-bench/fuzz_corpus/py_url_redirection_target_app_py_8"
    os.makedirs(_CORPUS_DIR, exist_ok=True)
    for _i, _seed in enumerate(_SEED_CORPUS):
        _seed_path = os.path.join(_CORPUS_DIR, f"seed_{_i:03d}")
        if not os.path.exists(_seed_path):
            with open(_seed_path, "wb") as _f:
                _f.write(_seed.encode("utf-8"))

    if _CORPUS_DIR not in sys.argv:
        sys.argv.append(_CORPUS_DIR)

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()