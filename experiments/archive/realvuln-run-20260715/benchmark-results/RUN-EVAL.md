# Run Evaluation — 33 findings (benchmark-python) qua Oraculum + smoke-test

**Ngày:** 2026-07-13
**Mô hình LLM:** `ollama_chat/qwen3-coder:480b-cloud` (7 key Ollama Cloud từ `~/OR_env/.env`)
**Dataset:** 33 finding VHX tìm ra (TP-filtered) — OWASP Benchmark for Python
**Artifacts:** classifications + fuzz_oracles + fuzz_targets (qwen3-coder, restore từ `benchmark-results/`)

---

## ⚖️ HONEST RE-MEASUREMENT (de-conflated oracle-only + heavy fuzz + variance)

Phát hiện bias: metric "trigger" cũ **gộp** `ORACULUM_VIOLATION` (công oracle) với `incidental_crash` (handler tự crash, có cả khi oracle OFF) → precision bị underestimate, recall bị overestimate. Sửa: metric = **chỉ `oracle_violation`**. Đo `33 × N=3 × -runs=10000` (±std qua 3 repeats; kết quả deterministic ±0).

| | precision | recall | F1 |
|---|---|---|---|
| **Honest (oracle-only, -runs=10000)** | **78.6% ±0** | 64.7% ±0 | 71.0% ±0 |
| Before (conflated, -runs=1000) | 60.9% | 82.4% | 70.0% |

run-0 breakdown: `oracle_violation=14` (11 TP + 3 FP), `incidental_crash=9`, `no_trigger=9`, `timeout=1`.

**Đọc trung thực (KHÔNG spin):**
- **Precision THẬT = 78.6%** (+17.7pp vs 60.9%) — nhưng gain chủ yếu từ **đo đúng** (de-conflation loại 6 incidental FP), không phải capability mới. Đây là sửa metric, not improvement.
- **Recall honest = 64.7%** (11/17 TP oracle-detect) — thấp hơn 82.4% cũ VÌ 82.4% bị inflate bởi 3 incidental-crash TP (handler crash, không phải oracle). Honest recall thấp hơn.
- **F1 ~flat (71.0 vs 70.0)** — capability thật không đổi qua các "tier".
- **Recall recovery (Tier 1 deser/00930) KHÔNG materialize** ở -runs=10000: fuzzer không reach exploit base64/encoding cho deser/00930 dù direct-test chứng minh oracle-logic đúng (deser seed→pickle.loads→`system`→match). Cần real time-fuzz (`-max_total_time` lớn) hoặc direct seed injection — **future work**, chưa giải.

**Kết luận không bias:** cải thiện "kết quả tốt hơn trước" chủ yếu là **precision thật (78.6%)** — nhưng đó là đo đúng, không phải nâng capability. F1 thật ~0.71. Recall là trục yếu (64.7%), cần real-fuzz/seed-injection để phục hồi (đã chứng minh logic đúng, chỉ fuzzer chưa reach). **Đây là giới hạn thật của hệ thống ở config hiện tại, báo thẳng.**

`scripts/fuzz_eval.py` sinh số liệu; `benchmark-results/fuzz-eval.json` raw.

---

## 🟢🟢🟢🟢 BASELINE ABLATION (oracle ON vs OFF) — contribution cô lập

Ablation: cùng scaffolding (flask deterministic harness), chỉ khác oracle-check ON vs OFF (OFF = thay `raise RuntimeError(_RAISE_MESSAGE…)` bằng `pass` → default Atheris crash-only). `-runs=1000`.

| | TP trigger (17) | FP trigger (16) | total crash-signal |
|---|---|---|---|
| **Oracle ON** (Oraculum) | **14** | 9 | 23 |
| **Oracle OFF** (default crash-only) | 9 | 7 | 16 |
| **Net oracle contribution** | **+5 TP (+29% recall)** | +2 FP | +7 |

**Đọc kết quả:**
- Default crash-only Atheris (OFF) đã detect 9/17 TP — không phải 0, vì OWASP handler tự raise uncaught exception (RuntimeError từ handler) trên một số input → Atheris bắt như crash.
- Oraculum oracle (ON) detect **14/17 TP — thêm 5 bug thật (+29% recall)** so với crash-only. Đây là **contribution đo được, cô lập**: oracle thêm 5 phát hiện mà crash-only bỏ sót.
- Cost: +2 FP (precision trade-off, nhất quán với precision-erosion finding).
- → **Bằng chứng publication**: oracle Oraculum thêm detection power over default fuzzing, đo được +29% recall trên bug thật.

---

## 🟢🟢🟢 TIER 1 (recall recovery) + phát hiện precision-erosion

Tier 1 (3 fix deterministic): (1) 00460 dup data-fix → 33/33 generate; (2) deser seed `base64-url(pickle-RCE)`; (3) `request.query_string` detect. Mỗi fix **verified bằng direct handler test** (vd deser: seed→`pickle.loads`→captured chứa `system`→signature match ✓).

### Đo theo -runs (signal khác nhau!)

| Metric (-runs) | precision | recall | F1 |
|---|---|---|---|
| -runs=1 (clean corpus) | 72.2% | 76.5% | 74.3% |
| -runs=1000 (seed+mutations) | 60.9% | 82.4% | 70.0% |
| pre-Tier1 baseline (-runs=1) | 70.6% | 70.6% | 70.6% |

### Phát hiện nghiên cứu quan trọng: precision ERODES under fuzzing

Khi -runs tăng (1→1000), **recall lên (70.6→82.4%) NHƯNG precision xuống (70.6→60.9%)** — FP-trigger 5→9. Lý do: fuzzer mutate ra input **exploit-SHAPED cho cả FP cases** (vd eval-literal FP 00073: fuzzer tìm `'__import__("os")'` — quoted string chứa keyword, проходит guard, đến eval, signature match → trigger; nhưng eval chỉ return string, không execute → không phải bug thật). Vậy **payload-shape signature có ceiling** — không phân biệt được "exploit-shape đến sink" vs "exploit-shape thật sự khai thác".

→ **F1 ~flat (~70-74)** bất kể Tier 1. Gain precision thật cần **dynamic exploit verification** (Tier 4: verify input THỰC SỰ khai thác, vd eval có execute không), không chỉ regex shape.

### Kết luận Tier 1 (trung thực)
- ✅ Code fixes ĐÚNG + verified individually; 33/33 generate; recall recovery ở -runs=1000 (82.4%).
- ⚠️ F1 không nhảy như dự đoán (dự đoán ~0.87, thực tế ~0.70-0.74) — dự đoán sai vì không tính precision-erosion.
- 🔬 **Phát hiện có giá trị nghiên cứu**: payload-shape oracle precision erodes under real fuzzing → cần dynamic verification. Đây là insight publishable (limitation + future direction).

---

## 🟢🟢 ORACLE PRECISION (reachability → exploitability)

Framework-fix cho 26/33 trigger nhưng ma trận bị nhiễu (11/16 FP trigger vì LLM patterns loose `[\s\S]+` check reachability). Bước này thay bằng **deterministic exploit-signature registry** per rule (`src/oraculum/harness/exploit_signatures.py`) → oracle kiểm tra **exploit-shape** (input có hình dạng exploit thật).

### So sánh loose-oracle vs precision-oracle (smoke `-runs=1`)

| | Loose oracle (LLM) | Precision oracle (registry) |
|---|---|---|
| TP trigger | 15 | 12 |
| FP trigger | 11 | **5** |
| **Precision** = TP/(TP+FP) | 58.1% | **70.6%** |
| **Recall** = TP/17 | 88.2% | 70.6% |
| F1 | 0.708 | 0.706 |

**Precision +12.5pp** (58→70.6%). FP residual 5 = 2 eval-literal-guard (00073,00158: guard ép eval nhận string-literal chứa keyword, signature match content nhưng không execute) + 3 xml-bomb config-disagree (00017,00204,00539: default SAX không expand → OWASP xếp FP).

**Recall −17.6pp** (88→70.6%) tập trung 2 nhóm CỨU ĐƯỢC: 3 deser (00078,00164,00507: cần seed `base64-url(pickle-RCE)` cụ thể — seed thường fail b64decode → pickle.loads không gọi) + 2 xxe (00460 gen-fail dup, 00930 input-encoding). Fix bằng targeted seed + real-fuzz (`-max_total_time`) → kỳ vọng recall phục hồi mà không mất precision.

### Đóng góp + hạn chế
- **Đóng góp:** exploit-signature registry deterministic (9 rule group) — oracle từ reachability → exploitability, loại bỏ LLM-loose-noise. Unit test 19/19 (match exploit + reject benign, kể cả cmd-wrapper false-match).
- **FP residual là hard cases thật** (eval-literal guard, xml SAX default) — không phải loose-noise → tín hiệu sạch hơn cho baseline comparison.
- **Follow-up:** (1) targeted deser/xxe seed để phục hồi recall; (2) eval-literal detection (phân biệt "eval execute" vs "eval return string"); (3) real-fuzz thay `-runs=1`.

---

## 🟢 POST-FIX (framework-support P3) — 0/33 → 26/33 trigger

Sau khi fix framework-support (branch `feat/flask-framework-support`), fuzz-confirmation **chạy được**:

| Tổng quan | Trước fix | Sau fix |
|---|---|---|
| Compile | 33/33 | 33/33 |
| Smoke pass / oracle-trigger | **0/33** | **26/33** |
| Import crash (nested init(app)) | 30/33 | 0 |
| Syntax (py3.12 f-string) | 3/33 | 0 (venv 3.12) |

### Ma trận ground-truth × oracle-trigger (sau fix)

| | trigger | no_trigger | error |
|---|---|---|---|
| **TP (17)** | **15** | 1 | 1 |
| **FP (16)** | 11 | 5 | 0 |

**Đọc kết quả:**
- **Recall trên TP = 15/17 = 88%** — fuzz-confirmation xác nhận động được 15/17 bug thật. Đây là giá trị cốt lõi: runtime oracle vượt phán xét tĩnh.
- **11/16 FP cũng trigger** → oracle patterns (LLM-sinh, vd `[\s\S]+`) quá lỏng, match bất kỳ input nào đến sink. Đây là vấn đề **chất lượng oracle** (precision), tách biệt khỏi framework fix — là follow-up tiếp theo.
- 5 FP no-trigger + 1 TP no-trigger (fuzz chưa mutate ra payload phù hợp trong -runs=1).
- 1 error_import (Flask `EnvironBuilder`/atheris interaction), 1 stale harness (BenchmarkTest00460 xxe — dup target_id mismatch).

### Contribution (P3 framework-support, deterministic)
- `src/oraculum/harness/input_source.py` (MỚI): AST detector input-source (form/cookie/args/header/path) — tham chiếu `config/queries/python/web_params.ql`.
- `src/oraculum/harness/import_resolver.py`: phát hiện `def init(app):` → emit module import thay vì from-import.
- `src/oraculum/harness/templates/base_harness_flask.j2` (MỚI): harness deterministic đầy đủ cho Flask `init(app)` (app setup + `view_functions` extraction + request context theo source + patch sink + oracle check) — không cần LLM fill.
- `src/oraculum/harness/template_builder.py`: route sang flask deterministic khi `flask_view + init(app) + recorded_call`.
- `src/oraculum/harness/runner.py`: skip LLM khi skeleton đã complete (no `[FILL HERE]`).
- Tests: `test_harness_flask_template.py` cập nhật + `test_input_source_detection` mới; **70/70 pytest pass**, ruff sạch (file mới).

### Follow-up (ngoài scope)
- **Oracle precision**: trigger-patterns cần chặt hơn (regex theo payload cụ thể, không `[\s\S]+`) → giảm 11 FP-trigger.
- Flask `EnvironBuilder` import error (1 case) — atheris instrumentation vs flask.testing.
- BenchmarkTest00460 dup (xml-bomb + xxe cùng file:line) — target_id collision cần xử lý.

---

## ⴰ BEFORE-FIX (lịch sử, 0/33) — giữ làm baseline

## Mục tiêu

Chạy toàn bộ 33 findings VHX-tìm-ra trong `benchmark-results/` qua pipeline Oraculum + **smoke-test fuzz** (Bước 5 của guide `~/OR_env`) để đo fuzz-confirmation.

## Tổng quan kết quả

| Chỉ số | Giá trị |
|---|---|
| Tổng findings đem test | 33 |
| Harness sinh thành công | 33/33 (qwen3-coder) |
| **Compile Rate** (py_compile) | **33/33 = 100%** |
| **Smoke Test Pass** (-runs=1, không crash + chạy được) | **0/33 = 0%** |
| Oracle trigger (bắt bug) | 0/33 |
| Fuzzing Success Rate | 0% |

→ Pipeline sinh harness + compile hoàn hảo, nhưng **0 harness chạy được** — fuzz-confirmation block tại bước import.

## Per-finding (33)

Tất cả 33 finding đều `strategy = recorded_call` (dangerous sinks: eval, subprocess, httpx.get, xml parser, xpath, redirect, pickle...).

| # | Test | Rule | Strategy | Compile | Smoke | Failure mode |
|---|---|---|---|---|---|---|
| 1 | BenchmarkTest00073 | py/code-injection | recorded_call | OK | Fail | import_nested_func |
| 2 | BenchmarkTest00156 | py/code-injection | recorded_call | OK | Fail | import_nested_func |
| 3 | BenchmarkTest00158 | py/code-injection | recorded_call | OK | Fail | import_nested_func |
| 4 | BenchmarkTest00159 | py/code-injection | recorded_call | OK | Fail | import_nested_func |
| 5 | BenchmarkTest00165 | py/command-line-injection | recorded_call | OK | Fail | import_nested_func |
| 6 | BenchmarkTest00167 | py/command-line-injection | recorded_call | OK | Fail | import_nested_func |
| 7 | BenchmarkTest00168 | py/command-line-injection | recorded_call | OK | Fail | import_nested_func |
| 8 | BenchmarkTest00267 | py/command-line-injection | recorded_call | OK | Fail | import_nested_func |
| 9 | BenchmarkTest00001 | py/path-injection | recorded_call | OK | Fail | import_nested_func |
| 10 | BenchmarkTest00002 | py/path-injection | recorded_call | OK | Fail | import_nested_func |
| 11 | BenchmarkTest00005 | py/path-injection | recorded_call | OK | Fail | syntax_fstring_312 |
| 12 | BenchmarkTest00150 | py/reflective-xss | recorded_call | OK | Fail | import_nested_func |
| 13 | BenchmarkTest00256 | py/reflective-xss | recorded_call | OK | Fail | import_nested_func |
| 14 | BenchmarkTest00257 | py/reflective-xss | recorded_call | OK | Fail | import_nested_func |
| 15 | BenchmarkTest00591 | py/reflective-xss | recorded_call | OK | Fail | import_nested_func |
| 16 | BenchmarkTest01083 | py/reflective-xss | recorded_call | OK | Fail | import_nested_func |
| 17 | BenchmarkTest00078 | py/unsafe-deserialization | recorded_call | OK | Fail | import_nested_func |
| 18 | BenchmarkTest00164 | py/unsafe-deserialization | recorded_call | OK | Fail | import_nested_func |
| 19 | BenchmarkTest00270 | py/unsafe-deserialization | recorded_call | OK | Fail | import_nested_func |
| 20 | BenchmarkTest00507 | py/unsafe-deserialization | recorded_call | OK | Fail | import_nested_func |
| 21 | BenchmarkTest00067 | py/url-redirection | recorded_call | OK | Fail | import_nested_func |
| 22 | BenchmarkTest00068 | py/url-redirection | recorded_call | OK | Fail | import_nested_func |
| 23 | BenchmarkTest00151 | py/url-redirection | recorded_call | OK | Fail | import_nested_func |
| 24 | BenchmarkTest00258 | py/url-redirection | recorded_call | OK | Fail | import_nested_func |
| 25 | BenchmarkTest00017 | py/xml-bomb | recorded_call | OK | Fail | import_nested_func |
| 26 | BenchmarkTest00204 | py/xml-bomb | recorded_call | OK | Fail | import_nested_func |
| 27 | BenchmarkTest00459 | py/xml-bomb | recorded_call | OK | Fail | import_nested_func |
| 28 | BenchmarkTest00460 | py/xxe | recorded_call | OK | Fail | import_nested_func |
| 29 | BenchmarkTest00539 | py/xml-bomb | recorded_call | OK | Fail | import_nested_func |
| 30 | BenchmarkTest00021 | py/xpath-injection | recorded_call | OK | Fail | syntax_fstring_312 |
| 31 | BenchmarkTest00460 | py/xxe | recorded_call | OK | Fail | import_nested_func |
| 32 | BenchmarkTest00679 | py/xxe | recorded_call | OK | Fail | import_nested_func |
| 33 | BenchmarkTest00930 | py/xxe | recorded_call | OK | Fail | syntax_fstring_312 |

## Failure modes (2 nguyên nhân, 0 thành công)

### 1. `import_nested_func` — 30/33 (91%)
```
ImportError: cannot import name 'BenchmarkTest00xxx_post' from 'testcode.BenchmarkTest00xxx'
```
**Gốc rễ:** OWASP Benchmark for Python định nghĩa hàm vulnerable **lồng trong `def init(app):`** (Flask route registration):
```python
def init(app):
    @app.route('/benchmark/.../BenchmarkTest00073', methods=['POST'])
    def BenchmarkTest00073_post():   # ← nested, không phải module-level
        ...
```
Harness Oraculum sinh `from testcode.BenchmarkTest00073 import BenchmarkTest00073_post` — nhưng hàm đó không tồn tại ở module-level (chỉ được tạo khi `init(app)` chạy). `import_resolver` của Oraculum **giả định hàm module-level**, không xử lý nested route handlers.

→ Đây là gap **framework support** (ORACULUM.mld P3: "Flask view functions / framework-specific test clients" chưa support).

### 2. `syntax_fstring_312` — 3/33 (9%)
```
SyntaxError: f-string: expecting '}'   (BenchmarkTest00005, 00021, 00930)
```
**Gốc rễ:** OWASP Benchmark source dùng f-string lồng quote (PEP 701, Python 3.12+):
```python
f'{escape_for_html(fd.read(1000).decode('utf-8'))}'   # nested single-quotes
```
Venv Oraculum là Python 3.11 (pyproject yêu cầu `<3.14,>=3.10`; 3.14 bị chặn, 3.11 là bản có sẵn). 3.11 không parse f-string lồng quote → SyntaxError khi import module source.

→ **Fix được** bằng venv Python 3.12. Nhưng 3 case này dù sửa syntax vẫn sẽ vấp `import_nested_func` (giống 30 case kia) → vẫn 0 pass.

## Kết luận

- **Key Ollama Cloud + pipeline Oraculum: HOẠT ĐỘNG** — 33/33 harness sinh bằng qwen3-coder, 100% compile OK.
- **Fuzz-confirmation: 0/33** — block hoàn toàn ở bước import, do 2 gap:
  1. **Framework-structure gap (chính, 30/33):** Oraculum chưa import được hàm nested trong `init(app)` của Flask benchmark. Đây là ORACULUM.mld P3 (framework support) cụ thể hóa.
  2. **Python 3.12 needed (phụ, 3/33):** benchmark source dùng f-string 3.12+; venv 3.11 không parse được.
- **Không phải lỗi key/LLM** — LLM sinh harness đúng cấu trúc, syntax OK. Lỗi ở tầng harness-runtime/framework mà ORACULUM.mld đã dự liệu (P1 harness validator + P3 framework support chưa build).

## Để fuzz-confirmation hoạt động (follow-up, ngoài scope A)

1. **Framework support (P3):** import_resolver cần xử lý `init(app)` pattern — hoặc gọi `init(mock_app)` rồi lấy route handler, hoặc generate harness setup Flask app + test client (theo ORACULUM.mld "Flask view functions / framework-specific test clients").
2. **Venv Python 3.12:** recreate `.venv` bằng 3.12 (thỏa `<3.14,>=3.10`) để parse f-string lồng quote.
3. **Harness validator (P1):** thêm phase import/smoke check trước khi tính harness "runnable" (ORACULUM.mld P1) — hiện Oraculum chỉ `ast.parse`, không phát hiện import_nested_func.
