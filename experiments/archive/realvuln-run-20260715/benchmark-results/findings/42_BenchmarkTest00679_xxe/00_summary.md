# BenchmarkTest00679 — `py/xxe`

- **File:** `testcode/BenchmarkTest00679.py:52`
- **Function:** `BenchmarkTest00679_post`
- **OWASP category:** `xxe`
- **VHX verdict:** `True Positive` (confidence `High`)
- **OWASP ground truth:** `FP`
- **Match:** ❌ FP-MISMATCH

## VHX xác nhận sai — cơ chế: `taint-killed-index`

VHX theo dõi taint sai (off-by-one list index sau pop)

> Xem `REPORT.md` (mục Mismatch Analysis) cho phân tích đầy đủ + proof.

## Artifacts (theo thứ tự pipeline)
- `01_source.py` — source code thật của test case
- `02_finding.json` — enriched finding (VHX verification)
- `03_classification.json` — Oraculum strategy classification
- `04_oracle.json` — fuzz oracle spec
- `05_harness.py` — Atheris fuzz target
