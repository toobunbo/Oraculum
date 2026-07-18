# BenchmarkTest00021 — `py/xpath-injection`

- **File:** `testcode/BenchmarkTest00021.py:58`
- **Function:** `BenchmarkTest00021_post`
- **OWASP category:** `xpathi`
- **VHX verdict:** `True Positive` (confidence `Medium`)
- **OWASP ground truth:** `FP`
- **Match:** ❌ FP-MISMATCH

## VHX xác nhận sai — cơ chế: `sanitizer-misjudged`

VHX đánh giá sai sanitizer là bypassable (thực tế adequate cho context)

> Xem `REPORT.md` (mục Mismatch Analysis) cho phân tích đầy đủ + proof.

## Artifacts (theo thứ tự pipeline)
- `01_source.py` — source code thật của test case
- `02_finding.json` — enriched finding (VHX verification)
- `03_classification.json` — Oraculum strategy classification
- `04_oracle.json` — fuzz oracle spec
- `05_harness.py` — Atheris fuzz target
