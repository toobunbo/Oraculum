# Oraculum Repair Loop

**Post-Generation Runtime Error Repair for LLM-Synthesized Python Fuzz Harnesses**

## 1. Problem

In the full Real-Vuln-Benchmark evaluation (104 harnesses, 22 repos), the smoke test yielded:

| Outcome | Count | Percentage |
|---|---|---|
| **PASS** (clean run) | 18 | 17.3% |
| **BUG** (oracle detected violation) | 19 | 18.3% |
| **ERR** (runtime error in harness) | 66 | 63.5% |
| OTHER | 1 | 1.0% |

**63.5% of automatically generated fuzz harnesses fail at runtime**, not due to incorrect oracle logic, but due to **trivial framework boilerplate errors** that LLMs systematically produce.

## 2. Error Taxonomy

Empirical analysis of all 66 ERR harnesses from the archive reveals 5 distinct error categories:

### E1: Seed Corpus Type Mismatch (28/66 = 42%)

**Root cause**: The LLM generates `_SEED_CORPUS` entries as `bytes` literals (`b"..."`) but the postamble writes them with `_seed.encode("utf-8")`, which is a `str` method.

```python
# Generated pattern (ERR):
_SEED_CORPUS = [
    b"file:///etc/passwd",       # ← bytes, not str
    b"http://169.254.169.254/",  # ← bytes, not str
]
# ...
for _i, _seed in enumerate(_SEED_CORPUS):
    _f.write(_seed.encode("utf-8"))  # AttributeError: 'bytes' object has no attribute 'encode'
```

**Detection pattern** in traceback:
```
AttributeError: 'bytes' object has no attribute 'encode'
```

**Affected**: 28 harnesses across 13 repos (most DJANGO, FastAPI, and some FLASK repos).

---

### E2: Missing Framework Initialization (18/66 = 27%)

**Root cause**: Django/FastAPI/Flask harnesses call framework-dependent code (route handlers, ORM queries) without initializing the framework context.

#### E2a: Missing Django setup (12)

```python
# Generated pattern (ERR):
from hr_portal.payroll_operations import payroll_formula_cast_252
# → django.core.exceptions.ImproperlyConfigured:
#   Requested settings, but settings are not configured
```

**Required**: `os.environ['DJANGO_SETTINGS_MODULE'] = 'project.settings'` + `django.setup()`

#### E2b: Missing Flask request context (5)

```python
# Generated pattern (ERR):
from app import app, evaluate
evaluate()  # → RuntimeError: Working outside of request context
```

**Required**: `with app.test_request_context(data=form_data, method='POST'):`

#### E2c: Missing FastAPI TestClient (1)

```python
# Generated pattern (ERR):
from fastapi import FastAPI
# route handler called without TestClient context
```

**Required**: `from fastapi.testclient import TestClient` + `client = TestClient(app)`

---

### E3: Import/Mock Path Resolution Failure (10/66 = 15%)

**Root cause**: LLM imports a module or patches a function path that does not match the actual project structure.

```python
# Generated pattern (ERR):
patch('config.partner_console.safe_exec')  # → ImportError: no such function
```

**Detection pattern**: `ModuleNotFoundError`, `ImportError`, `AttributeError` on import/patch.

---

### E4: Oracle Argument Type Guard (6/66 = 9%)

**Root cause**: Oracle check accesses `call.args[0]` or `call.kwargs["key"]` without verifying that the mock call has the expected argument structure.

```python
# Generated pattern (ERR):
for call in mock_eval.call_args_list:
    captured = str(call.args[0])  # → IndexError if call.args is empty
```

**Detection pattern**: `IndexError: tuple index out of range`, `KeyError`, `TypeError`.

---

### E5: Atheris Instrumentation Crash (4/66 = 6%)

**Root cause**: `atheris.instrument_imports()` fails on complex Django/C extension model chains.

```python
# Generated pattern (ERR):
with atheris.instrument_imports():
    from django.db import models  # Atheris fails on C-ext
```

**Detection pattern**: Segfault or `SystemError` during import inside `instrument_imports()`.

---

## 3. Repair Loop Design

### 3.1 Architecture

```
[Harness Generation]
        │
        ▼
┌─────────────────────┐
│  Dry Run (5s)       │──────────→ PASS ──→ ✅ Done
│  time python -runs=1 │
└─────────┬───────────┘
          │ ERR (timeout/crash)
          ▼
┌─────────────────────┐
│  Error Classifier   │──→ ErrorType(E1–E5)
│  (traceback parse)  │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Repair Strategy    │──→ Apply deterministic fix
│  (per ErrorType)    │
└─────────┬───────────┘
          │
          ▼
    ┌─ Re-dry-run ──┐
    │  max 3 iter    │──→ PASS ──→ ✅ Done
    └────────────────┘
          │ still ERR after 3×
          ▼
       ❌ Mark as UNREPAIRABLE
```

### 3.2 Error Classification

The classifier reads `stderr` from the dry run and matches known error signatures:

| ErrorType | stderr pattern | Priority |
|---|---|---|
| E1 | `'bytes' object has no attribute 'encode'` | P0 |
| E2a | `ImproperlyConfigured.*settings are not configured` | P0 |
| E2b | `Working outside of request context` | P0 |
| E2c | `RuntimeError.*not a valid*` or ASGI/TestClient absence | P0 |
| E3 | `ModuleNotFoundError`, `ImportError`, `AttributeError` on import | P1 |
| E4 | `IndexError.*tuple index out of range`, `KeyError`, `TypeError` in oracle | P1 |
| E5 | `SystemError` or segfault during `instrument_imports` | P2 |

### 3.3 Repair Strategies

#### S1: Seed Encoding Fix (∼3 AST edits)

**Input**: Harness source with `_SEED_CORPUS` containing `bytes` + `_seed.encode("utf-8")`
**Output**: Conditional write that handles both `str` and `bytes`

**Transformation**:
```python
# BEFORE:
_SEED_CORPUS = [b"file:///etc/passwd", ...]
for _i, _seed in enumerate(_SEED_CORPUS):
    with open(_seed_path, "wb") as _f:
        _f.write(_seed.encode("utf-8"))

# AFTER:
_SEED_CORPUS = [b"file:///etc/passwd", ...]
for _i, _seed in enumerate(_SEED_CORPUS):
    with open(_seed_path, "wb") as _f:
        if isinstance(_seed, bytes):
            _f.write(_seed)
        else:
            _f.write(_seed.encode("utf-8"))
```

**Implementation**: Template-aware regex replacement. The seed corpus loop has a deterministic structure in all generated harnesses (same `for _i, _seed` pattern).

#### S2a: Django Setup Injector (prepend lines)

**Input**: Harness with Django imports but no setup
**Output**: Prepend `os.environ` + `django.setup()` before `with atheris.instrument_imports():`

```python
# BEFORE:
with atheris.instrument_imports():
    from django_models import target

# AFTER:
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', '<detected>.settings')
django.setup()

with atheris.instrument_imports():
    from django_models import target
```

**Settings detection**: Scan repo root for `*/settings.py` via glob. If exactly one found, use it. Otherwise, prompt the user (or skip).

#### S2b: Flask Context Injector (restructure `TestOneInput`)

**Input**: Harness with Flask import + direct call
**Output**: Wrap the target call inside `app.test_request_context()`

**Transformation**: Find the target call and wrap it:
```python
# BEFORE:
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    param = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    # ...
    evaluate()  # direct call outside context

# AFTER:
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    param = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    # ...
    with app.test_request_context(data=form_data, method='POST'):
        evaluate()
```

#### S2c: FastAPI TestClient Injector

**Input**: Harness with `from fastapi import` but no TestClient
**Output**: Add `from fastapi.testclient import TestClient` + wrap calls in `client.get/post`

#### S3: Oracle Type Guard (insert guard conditions)

**Input**: Harness with unprotected `call.args[0]` access
**Output**: Guarded access with fallback

```python
# BEFORE:
for call in mock_eval.call_args_list:
    captured = str(call.args[0])

# AFTER:
for call in mock_eval.call_args_list:
    captured = None
    if call.args and len(call.args) > 0:
        captured = str(call.args[0])
    elif call.kwargs:
        captured = str(call.kwargs.get("source", ""))
    if captured is None:
        continue
```

### 3.4 Iteration Policy

| Iteration | Fix Priority | Rationale |
|---|---|---|
| **Loop 1** | E1 (seed) | Fast, high-impact, fixes 42% of ERR |
| **Loop 2** | E2 (framework) | Fixes 27% more — but some E2 are masked by E1 |
| **Loop 3** | E3–E4 (import/type) | Fixes remaining ∼24% |

Each loop:
1. Applies the fix
2. Re-runs dry run (5s timeout)
3. If PASS → done
4. If ERR with different error type → classify & fix in next iteration
5. If ERR with same error type → mark as UNREPAIRABLE and skip

### 3.5 Scope Limits

| Category | Action |
|---|---|
| E5 (Atheris crash) | Skip — cannot fix; mark as UNREPAIRABLE |
| E3 (import) | Try `try/except ImportError` + `sys.path` fix; skip if still fails |
| Auto-detected `settings.py` | If >1 `settings.py` found in repo, skip Django fix |

## 4. Expected Impact

Using the archive data (66 ERR):

| Fix applied | ERR remaining | New PASS+BUG | Recovery rate |
|---|---|---|---|
| Baseline | 66 | 0 | — |
| S1 (seed fix) | 38 | 28 | 42% |
| S1 + S2 (seed + framework) | 20 | 46 | 70% |
| S1 + S2 + S3 (all) | 14 | 52 | 79% |

**Theoretical upper bound**: 52/66 ERR cases recoverable (79%).
**Expected real recovery**: ∼65% (some E3/E4 cases have confounding factors).

After repair: total PASS+BUG increases from 37 → ∼89, raising **overall bug detection** from 19/104 (18.3%) to an estimated 19/104 → same 19 bugs but **more harness volume means more runs and potentially more bugs found** under longer fuzzing.

## 5. Implementation Plan

```
src/oraculum/harness/repair/
├── __init__.py                  # exports RepairLoop
├── runner.py                    # RepairLoop class (orchestrator)
├── error_classifier.py          # parse_traceback() → ErrorType
├── dry_run.py                   # run_harness_with_timeout()
└── fixers/
    ├── __init__.py              # FixerRegistry
    ├── seed_encoding.py         # fix_seed_encoding(source) → source
    └── framework_context.py     # fix_framework_context(source, repo_root) → source
```

Integration: `scripts/run_repair_loop.py` — CLI that takes `output/python/` directory, runs repair on all ERR harnesses, produces report.

## 6. Measurement Protocol

For scientific rigor:

1. **Before repair**: Count ERR per category (E1–E5) via traceback classification
2. **After repair**: Count remaining ERR, new PASS, new BUG
3. **Ablation**: Repair with only S1, only S2, all S1+S2+S3
4. **Report**: Per-harness repair outcome table (ERR-type → fix applied → PASS/ERR → final status)
