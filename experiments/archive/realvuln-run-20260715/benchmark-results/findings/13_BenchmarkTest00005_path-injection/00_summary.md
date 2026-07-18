# BenchmarkTest00005 — `py/path-injection`

- **File:** `testcode/BenchmarkTest00005.py:60`
- **Function:** `BenchmarkTest00005_post`
- **OWASP category:** `pathtraver`
- **VHX verdict:** `True Positive` (confidence `Low`)
- **OWASP ground truth:** `FP`
- **Match:** ❌ FP-MISMATCH

## VHX xác nhận sai — cơ chế: `sink-not-visible`

VHX không thấy sink/guard nhưng vẫn chốt TP (nương CodeQL precision)

> Xem `REPORT.md` (mục Mismatch Analysis) cho phân tích đầy đủ + proof.

## Artifacts (theo thứ tự pipeline)
- `01_source.py` — source code thật của test case
- `02_finding.json` — enriched finding (VHX verification)
- `03_classification.json` — Oraculum strategy classification
- `04_oracle.json` — fuzz oracle spec
- `05_harness.py` — Atheris fuzz target
