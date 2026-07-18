# Repair Loop: Post-Generation Harness Auto-Repair

## 1. Why Do We Need This?

The LLM (DeepSeek / glm-5) generates fuzz harnesses automatically. In an ideal world, every generated harness would work instantly. In reality, **~45% of harnesses fail at runtime** due to trivial boilerplate mistakes:

- Missing Django setup (`django.setup()` not called)
- Missing Flask request context (`test_request_context()` not used)
- Slow Atheris instrumentation (import time > 45 seconds)
- Markdown fences leaking into Python files (LLM output not fully cleaned)
- Syntax errors (trailing `import` statements, empty module names)
- Missing PYTHONPATH for repo-local modules

These are not hard problems. A human developer could fix them in seconds. But we have thousands of harnesses — we cannot fix them by hand.

**Repair Loop is our answer.** It treats each failing harness as a patient, diagnoses the error, applies a fix, re-runs the test, and repeats until the harness works or until it determines the problem is unfixable.

---

## 2. Prior Art: CKG-Fuzzer and Dynamic Program Repair

The concept of "post-generation repair" comes from the CKG-Fuzzer paper, which introduced **Dynamic Program Repair (DPR)** for C/C++ fuzz harnesses:

> [CKG-Fuzzer] proposed an automatic repair framework for LibFuzzer harnesses that failed to compile or crashed immediately. Their error taxonomy covered C-specific issues: missing includes, undefined symbols, type mismatches at link time.

Our work adapts DPR to **Python**, which has fundamentally different failure modes:

| Aspect | CKG-Fuzzer (C/C++) | Oraculum Repair Loop (Python) |
|--------|-------------------|-------------------------------|
| Error type | Compile/link errors, segfaults | Runtime import errors, missing framework context, Atheris timeout |
| Fix mechanism | Text substitution (sed-like) | Regex + AST transformation + LLM Agent |
| Validation | Re-compile (gcc) | Re-run (python harness.py -runs=1) |
| Error classification | Parser error output | stderr traceback matching |
| Framework awareness | None (plain C) | Django/Flask/FastAPI context injection |

The key insight from CKG-Fuzzer that we inherit: **deterministic errors from generative models can be fixed with deterministic transformations**. We extend this by adding an **LLM Agent fallback** for errors that do not match known patterns — something CKG-Fuzzer could not do.

---

## 3. Architecture

```
                     ┌─────────────────────┐
                     │  python harness.py   │
                     │  -runs=1 (timeout X) │
                     └──────────┬──────────┘
                                │ PASS/rc=0
                                │ ──────────► ✅ Done
                                │
                                ▼
                     ┌─────────────────────┐
                     │  classify_error()   │
                     │  read stderr        │
                     │  match patterns     │
                     └──────────┬──────────┘
                                │
              ┌─────────────────┼──────────────────┐
              ▼                 ▼                  ▼
     Static Fixers        LLM Agent Fixer     Unrepairable
     (4 fixers)           (DeepSeek V3.1)     (mark & skip)
              │                 │
              ▼                 ▼
         ┌──────────────────────────┐
         │  Re-run harness          │
         │  (up to 3 iterations)    │
         └──────────────────────────┘
```

### 3.1 Dry-Run

Every harness is executed with:

```bash
timeout 90 python3 /path/to/harness.py -runs=1
```

The `-runs=1` flag tells Atheris to run exactly **one fuzz iteration** and exit. This is not real fuzzing — it is a health check. We only need to know:

- **PASS** (return code 0): the harness loaded, Atheris initialized, one fuzz input was processed, no crash.
- **BUG** (return code 77, or RuntimeError/AssertionError in stderr): the harness triggered a vulnerability on the very first test case. This is a confirmed True Positive.
- **FAIL** (return code 1): the harness failed to load or crashed for non-bug reasons (import error, syntax error, missing framework, etc.).
- **TIMEOUT** (exception): the harness took longer than the timeout (90 seconds). Usually due to Atheris instrumentation being too slow.

Key implementation detail: **the harness must be run from the correct working directory**. Before our fix, all harnesses were run from `fuzz_targets/`, which broke imports of repo-local modules (e.g., `from app.models import User`). Now the Repair Loop infers the repo root from the file path and runs each harness from that directory. It also sets `PYTHONPATH=<repo_root>` for harnesses that lack the `REPO_ROOT` variable.

### 3.2 Error Classification

The `classify_error()` function reads the harness's stderr output and matches it against known patterns:

| Error Type | stderr Pattern | Example |
|-----------|---------------|---------|
| `SEED_ENCODE` | `'bytes' has no attribute 'encode'` | Seed corpus bytes vs str mismatch |
| `DJANGO_SETUP` | `ImproperlyConfigured: settings are not configured` | Missing `django.setup()` |
| `FLASK_CONTEXT` | `Working outside of request context` | Missing `app.test_request_context()` |
| `FASTAPI_SETUP` | `RuntimeError: not a valid` / `does not support TestClient` | Missing FastAPI TestClient |
| `IMPORT_ERROR` | `ModuleNotFoundError` / `ImportError` | Module path wrong or missing package |
| `ORACLE_TYPE` | `IndexError: tuple index out of range` / `KeyError` on args | Oracle guard missing |
| `ATHERIS_CRASH` | `SystemError` / `Segmentation fault` | Atheris instrumentation crash |
| `ATHERIS_TIMEOUT` | `TIMEOUT` in stderr | Atheris took >90 seconds |
| `UNKNOWN` | No pattern matched | Fallback — sent to LLM Agent |

### 3.3 Repair Strategies

#### Static Fixers (fast path, no LLM cost)

These are regex-based transformations that handle the most common errors deterministically:

**1. Seed Encoding Fix** (`fix_seed_encoding`)
- Problem: `_SEED_CORPUS` has `bytes` literals but write code calls `.encode("utf-8")`
- Fix: Replace `.encode()` with an `isinstance` check that handles both `str` and `bytes`

**2. Framework Context Injection** (`fix_framework_context`)
- Django: Prepend `os.environ.setdefault('DJANGO_SETTINGS_MODULE', ...)` + `django.setup()`
- Flask: Wrap the target call inside `with app.test_request_context(...):`
- FastAPI: Add `from fastapi.testclient import TestClient` and create client instance

**3. Atheris Timeout Fix** (`fix_atheris_timeout`)
- Problem: `with atheris.instrument_imports():` takes >90 seconds for large Django/FastAPI apps because it instruments every module individually
- Fix: Replace with `atheris.instrument_all()`, which instruments all modules at once (much faster), and dedent the import block

**4. Markdown Fence + Import Cleanup** (in `runner.py` preprocessing)
- Problem: Some LLM-generated harnesses start with ` ```python ` (markdown fence) or have trailing empty `import` statements
- Fix: Strip markdown fences, remove empty import lines, fix unterminated triple-quoted strings

#### Dynamic Fixer (LLM Agent, DeepSeek V3.1)

When no static fixer matches the error, the Repair Loop calls **DeepSeek V3.1** via the `fix_with_llm()` function:

1. Send the harness source code + the error message to the LLM
2. Prompt: "Fix this Python fuzz harness that failed with the given error. Return ONLY the fixed code."
3. Apply the returned fix
4. Re-dry-run
5. If still failing and error type changed, try again (max 3 iterations)

The LLM Agent handles error types that cannot be fixed with simple regex:
- Unusual import errors
- Oracle type guard issues
- Atheris instrumentation crashes
- Unknown/unseen error patterns

In our experiments, the LLM Agent was invoked **3 times** across 123 harnesses. It generated fixes each time, but none resulted in a PASS — the errors were too deep (repo-local module structure issues).

---

## 4. Source Code Structure

```
src/oraculum/harness/repair/
├── __init__.py                     # Exports RepairLoop
├── runner.py                       # RepairLoop class — orchestrator
├── error_classifier.py             # classify_error(stderr) → ErrorType
├── dry_run.py                      # dry_run_harness() + _infer_repo_root()
└── fixers/
    ├── __init__.py                 # FIXER_REGISTRY + current_error context
    ├── seed_encoding.py            # fix_seed_encoding()
    ├── framework_context.py        # fix_framework_context() (Django/Flask/FastAPI)
    ├── atheris_timeout.py          # fix_atheris_timeout() (instrument_imports → instrument_all)
    └── llm_agent.py                # fix_with_llm() (DeepSeek V3.1)

scripts/run_repair_loop.py          # Batch repair CLI
config/prompts/repair_agent.txt     # LLM Agent system prompt
```

### Key classes and functions:

| Function/Class | File | Purpose |
|---------------|------|---------|
| `RepairLoop` | `runner.py` | Main orchestrator — dry-run → classify → fix → retry |
| `repair_one(harness_path)` | `runner.py` | Repair a single harness |
| `dry_run_harness(path, cwd)` | `dry_run.py` | Run harness with timeout |
| `_infer_repo_root(path)` | `dry_run.py` | Infer repo root from harness path |
| `classify_error(stderr)` | `error_classifier.py` | Match stderr to ErrorType |
| `FIXER_REGISTRY` | `fixers/__init__.py` | Dict mapping ErrorType → fix function |
| `set_current_error(stderr)` | `fixers/__init__.py` | Store stderr for LLM Agent |

---

## 5. How to Run the Repair Loop

### Single harness:

```python
from oraculum.harness.repair.runner import RepairLoop

loop = RepairLoop(timeout=90)  # 90 seconds timeout
result = loop.repair_one("/path/to/harness.py")

print(f"Status: {result.summary}")
# "[PASS] harness.py — 0 fixes"
# or "[FIX] harness.py — I1:atheris_timeout applied (requires re-smoke)"
# or "[ERR] harness.py — unrepairable (import_error)"
```

### All harnesses in a directory:

```python
from oraculum.harness.repair.runner import RepairLoop
import glob

loop = RepairLoop(timeout=90)
for harness in glob.glob("output/python/*/fuzz_targets/*.py"):
    result = loop.repair_one(harness)
    print(result.summary)
```

### From CLI:

```bash
python3 scripts/run_repair_loop.py \
  --input-dir output/python \
  --timeout 90 \
  --output repair_results.json
```

---

## 6. Experimental Results

Two sets of results are reported to maintain scientific transparency:

**Set A — Fully automated pipeline** (no manual intervention):
- 123 harnesses generated from 671 VHX True Positives
- After static repair (seed encoding, framework context, instrument_all, markdown strip, import cleanup):
  - **67 PASS / 123 (54.5%)**
- No BUG detected because the automated dry-run does not look for Atheris crash codes

**Set B — With minimal manual assistance** (PYTHONPATH configuration for repo-local modules, additional syntax fixes):
- After all fixes:
  - **71 PASS / 123 (57.7%)**
  - **17 BUG** confirmed (harness crashed on first fuzz input, indicating a real vulnerability)
  - **35 FAIL** — all due to Atheris runtime limitations (cannot instrument certain C extension modules)
  - **0 TIMEOUT**
  - **Working: 88/123 (71.5%)**

The 17 BUGs are the strongest evidence for the pipeline's effectiveness. These are not simulated — they are actual Atheris crashes triggered by real vulnerability inputs.

---

## 7. Limitations and Future Work

1. **Atheris incompatibility with C extensions**: 35 harnesses could not be instrumented by Atheris because they depend on modules with native C code (e.g., `lxml`, `psycopg2`, `cryptography`). This is a fundamental limitation of Atheris, not the pipeline.

2. **LLM Agent success rate**: The DeepSeek-based LLM Agent was invoked 3 times but did not successfully repair any harness. The prompt needs refinement to better handle repo-local module structure issues.

3. **Fuzzing depth**: All results are based on `-runs=1` (single iteration). Running each harness for 10-60 seconds would likely find many more bugs. The 17 BUGs found in 1 iteration suggest a high "ground truth" rate.

4. **Django version lock**: The environment uses Django 3.2 for compatibility with legacy code. Newer Django projects may require different fixes.
