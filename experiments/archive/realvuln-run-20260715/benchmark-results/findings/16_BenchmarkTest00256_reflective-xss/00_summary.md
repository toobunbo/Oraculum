# BenchmarkTest00256 — `py/reflective-xss`

- **File:** `testcode/BenchmarkTest00256.py:48`
- **Function:** `BenchmarkTest00256_post`
- **OWASP category:** `xss`
- **VHX verdict:** `True Positive` (confidence `High`)
- **OWASP ground truth:** `FP`
- **Match:** ❌ FP-MISMATCH

## VHX xác nhận sai — cơ chế: `dead-branch`

VHX không thấy điều kiện hằng số → taint đi qua dead code

> Xem `REPORT.md` (mục Mismatch Analysis) cho phân tích đầy đủ + proof.

## Artifacts (theo thứ tự pipeline)
- `01_source.py` — source code thật của test case
- `02_finding.json` — enriched finding (VHX verification)
- `03_classification.json` — Oraculum strategy classification
- `04_oracle.json` — fuzz oracle spec
- `05_harness.py` — Atheris fuzz target
