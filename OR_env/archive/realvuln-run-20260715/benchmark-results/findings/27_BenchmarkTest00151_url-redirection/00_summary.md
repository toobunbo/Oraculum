# BenchmarkTest00151 — `py/url-redirection`

- **File:** `testcode/BenchmarkTest00151.py:64`
- **Function:** `BenchmarkTest00151_post`
- **OWASP category:** `redirect`
- **VHX verdict:** `True Positive` (confidence `High`)
- **OWASP ground truth:** `FP`
- **Match:** ❌ FP-MISMATCH

## VHX xác nhận sai — cơ chế: `bool-misread`

VHX đọc sai logic boolean của guard

> Xem `REPORT.md` (mục Mismatch Analysis) cho phân tích đầy đủ + proof.

## Artifacts (theo thứ tự pipeline)
- `01_source.py` — source code thật của test case
- `02_finding.json` — enriched finding (VHX verification)
- `03_classification.json` — Oraculum strategy classification
- `04_oracle.json` — fuzz oracle spec
- `05_harness.py` — Atheris fuzz target
