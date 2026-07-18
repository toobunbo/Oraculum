# Benchmark Results — benchmark-python (33 findings)

Thư mục tổng hợp kết quả cho run `benchmark-python` (VHX verify → Oraculum classify/oracle/harness),
đánh giá trên OWASP Benchmark for Python.

## Bố cục

- `REPORT.md` — báo cáo phân tích đầy đủ (Summary, Detailed, Mismatch Analysis, Taxonomy, Verification).
- `index.csv` — bảng phẳng machine-readable: 1 dòng/finding (verdict, gt, match, mode, folder).
- `ground-truth.csv` — nhãn OWASP cho 33 test case.
- `findings/<NN>_<test>_<rule>/` — **mỗi finding 1 folder tự chứa**, file đánh số theo thứ tự pipeline:
  - `00_summary.md` — đọc trước: verdict / ground-truth / match / cơ chế sai
  - `01_source.py` — source code thật của test case
  - `02_finding.json` — VHX verification (đầu vào)
  - `03_classification.json` — Oraculum strategy
  - `04_oracle.json` — fuzz oracle spec
  - `05_harness.py` — Atheris fuzz target (đầu ra)

> Thứ tự số phản ánh pipeline: **source → VHX finding → classify → oracle → harness**. Mỗi folder là một đơn vị hoàn chỉnh, đọc độc lập được.

## Tóm tắt

- Tổng: **33 findings** (32 test case phân biệt; `BenchmarkTest00460` flag 2 lần).
- Match: Yes 13 + Partial 4 + FP-mismatch 16.
- **Precision: 17/33 = 51.5%.**
- Xem `REPORT.md` cho 7 cơ chế VHX xác nhận sai + proof empirical.

## Cơ chế sai (16 FP)

- `sanitizer-misjudged` (3): BenchmarkTest00073, BenchmarkTest00158, BenchmarkTest00021 — VHX đánh giá sai sanitizer là bypassable (thực tế adequate cho context)
- `dead-branch` (2): BenchmarkTest00156, BenchmarkTest00256 — VHX không thấy điều kiện hằng số → taint đi qua dead code
- `taint-killed-index` (2): BenchmarkTest00459, BenchmarkTest00679 — VHX theo dõi taint sai (off-by-one list index sau pop)
- `wrong-surface` (4): BenchmarkTest00150, BenchmarkTest00257, BenchmarkTest00591, BenchmarkTest01083 — VHX nhầm attack surface (response header ≠ reflective-xss body)
- `bool-misread` (1): BenchmarkTest00151 — VHX đọc sai logic boolean của guard
- `sink-not-visible` (1): BenchmarkTest00005 — VHX không thấy sink/guard nhưng vẫn chốt TP (nương CodeQL precision)
- `config-disagree` (3): BenchmarkTest00017, BenchmarkTest00204, BenchmarkTest00539 — VHX yêu cầu hardening nhưng default config đã an toàn (empirically refuted)

## Lưu ý phạm vi
- Dataset chỉ chứa verdict `True Positive` (filter TP) → chỉ đo precision, không đo recall.
- Mỗi folder tự chứa nên có thể đọc độc lập (reproducible unit).
