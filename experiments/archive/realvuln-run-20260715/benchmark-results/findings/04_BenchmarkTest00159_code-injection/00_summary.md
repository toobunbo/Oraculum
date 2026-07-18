# BenchmarkTest00159 — `py/code-injection`

- **File:** `testcode/BenchmarkTest00159.py:45`
- **Function:** `BenchmarkTest00159_post`
- **OWASP category:** `codeinj`
- **VHX verdict:** `True Positive` (confidence `High`)
- **OWASP ground truth:** `TP`
- **Match:** ✅ MATCH

_Đúng hướng — VHX đồng tình với OWASP ground truth._

## Artifacts (theo thứ tự pipeline)
- `01_source.py` — source code thật của test case
- `02_finding.json` — enriched finding (VHX verification)
- `03_classification.json` — Oraculum strategy classification
- `04_oracle.json` — fuzz oracle spec
- `05_harness.py` — Atheris fuzz target
