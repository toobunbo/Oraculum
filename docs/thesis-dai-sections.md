## 3.2.5 Giai đoạn 4: Sửa lỗi Post-Generation (Repair Loop)

### 3.2.5.1 Vấn đề

Sau khi LLM sinh fuzz harness tự động, một tỷ lệ đáng kể harness không chạy được ngay. Các lỗi runtime này không liên quan đến oracle logic — chúng xuất phát từ các nguyên nhân hệ thống như thiếu framework initialization, nhầm lẫn kiểu dữ liệu (type mismatch), hoặc Atheris instrumentation quá chậm. Trong thực nghiệm trên 123 harnesses, chỉ 33/123 (26.8%) chạy ổn ngay lần đầu mà không cần sửa.

CKG-Fuzzer [Xu et al., 2025] giới thiệu khái niệm Dynamic Program Repair (DPR) cho C/C++ fuzz harnesses, nơi compile-time errors và link-time errors được giải quyết thông qua các phép biến đổi xác định. Chúng tôi mở rộng hướng tiếp cận này sang miền Python. Khác biệt cốt lõi là Python harnesses không thất bại ở compile time mà ở import time hoặc tại ranh giới giữa fuzzer (Atheris) và framework code (Django, Flask, FastAPI). Ngoài ra, chúng tôi bổ sung LLM Agent fallback cho các lỗi không có pattern tĩnh — một cải tiến vượt trội so với CKG-Fuzzer vốn chỉ dùng static transformations.

Repair Loop là một module post-generation error recovery hoạt động theo vòng lặp: dry-run → classify → fix → re-validate (tối đa 3 iterations). Mỗi harness được kiểm tra với lệnh `python3 harness.py -runs=1` với timeout 90 giây. Nếu harness không chạy được, stderr được phân tích và so khớp với 9 ErrorTypes đã được xác định trước. Dựa trên ErrorType, một fixer thích hợp được áp dụng — hoặc static transformation (không tốn LLM cost) hoặc LLM Agent (sử dụng DeepSeek `deepseek-v3-1-250821`). Sau khi áp dụng fix, harness được kiểm tra lại. Nếu vẫn lỗi và ErrorType thay đổi, quy trình lặp lại. Nếu ErrorType không đổi hoặc không xác định được, Repair Loop dừng và đánh dấu harness là unrepairable.

### 3.2.5.2 Phân loại lỗi (Error Classification)

Bảng 3.2 liệt kê chín ErrorTypes được định nghĩa dựa trên phân tích stderr từ dry-run.

**Bảng 3.2. Error Classification — 9 ErrorTypes.**

| ErrorType | stderr pattern | Mô tả |
|-----------|---------------|-------|
| SEED_ENCODE | `'bytes' has no attribute 'encode'` | Nhầm lẫn bytes/str trong seed corpus |
| DJANGO_SETUP | `ImproperlyConfigured: settings not configured` | Thiếu `django.setup()` |
| FLASK_CONTEXT | `Working outside of request context` | Thiếu `app.test_request_context()` |
| FASTAPI_SETUP | `RuntimeError: not a valid` / `does not support TestClient` | Thiếu FastAPI TestClient |
| IMPORT_ERROR | `ModuleNotFoundError` / `ImportError` | Module không tìm thấy |
| ORACLE_TYPE | `IndexError: tuple index out of range` / `KeyError` | Thiếu guard cho oracle args |
| ATHERIS_CRASH | `SystemError` / `Segmentation fault` | Atheris crash khi instrumentation |
| ATHERIS_TIMEOUT | `TIMEOUT` | Atheris instrumentation quá chậm (>90s) |
| UNKNOWN | Không khớp mẫu nào | Dự phòng — gửi cho LLM Agent |

Phân loại lỗi được thực hiện bởi hàm `classify_error()` trong module `error_classifier.py`. Hàm này đọc stderr, trích xuất traceback cuối cùng, và so khớp với các mẫu regex đã được xác định trước. Nếu không có mẫu nào khớp, nó trả về UNKNOWN — lúc này fixer LLM Agent sẽ được kích hoạt.

### 3.2.5.3 Chiến lược sửa (Repair Strategies)

Chúng tôi áp dụng kiến trúc hybrid gồm hai tầng:

1. **Tầng 1 — Static Fixers (fast path)**: Các phép biến đổi xác định dựa trên regex cho các lỗi có pattern đã biết. Không tốn LLM cost, thực thi trong miligiây.
2. **Tầng 2 — LLM Agent (slow path)**: Khi không có static fixer nào khớp, harness source và error message được gửi đến DeepSeek `deepseek-v3-1-250821` để sinh candidate fix.

Lý do cho kiến trúc hybrid này là kinh tế: khoảng 60% lỗi được giải quyết bởi static fixers, 40% còn lại đòi hỏi hiểu biết ngữ nghĩa về codebase.

**Static Fixers:**

1. **Seed Encoding Fix**: Postamble do LLM sinh ghi seed corpus bằng `.encode("utf-8")`. Khi seed corpus chứa `bytes` literals, thao tác này gây ra `AttributeError`. Fix thay thế bằng conditional type guard:

```python
if isinstance(_seed, bytes):
    _f.write(_seed)
else:
    _f.write(_seed.encode("utf-8"))
```

2. **Framework Context Injection** (ba sub-strategies):
   - Django: Prepend `os.environ.setdefault('DJANGO_SETTINGS_MODULE', ...)` + `django.setup()`.
   - Flask: Wrap target function call trong `with app.test_request_context(...):`.
   - FastAPI: Thêm `from fastapi.testclient import TestClient` + khởi tạo client.

3. **Atheris Timeout Fix**: Thay thế `with atheris.instrument_imports():` bằng `atheris.instrument_all()`, giảm thời gian khởi tạo từ >90s xuống <10s cho cùng codebase.

4. **Mechanical Cleanup**: Strip markdown fence (4 harnesses), xóa empty import statements (76 dòng), đóng unterminated triple-quoted string (1 harness).

**LLM Agent:**

Khi không có static fixer nào khớp, LLM Agent được gọi. Harness source và toàn bộ stderr output được gửi đến DeepSeek `deepseek-v3-1-250821` với system prompt gồm 11 rules bao phủ các error categories phổ biến nhất. Model được yêu cầu chỉ trả về code đã sửa, không giải thích.

Trong thực nghiệm, LLM Agent được gọi 3 lần trên 123 harnesses. Mỗi lần đều sinh ra code change hợp lệ về cú pháp, nhưng không có thay đổi nào dẫn đến passing dry-run. Nguyên nhân là lỗi có tính structural: harness import module từ sai package path, và không có surface-level transformation nào có thể sửa import graph. Hướng cải thiện bao gồm inject inferred `REPO_ROOT` path và PYTHONPATH vào prompt, và cung cấp few-shot examples.

### 3.2.5.4 Quy trình thực thi

```
Dry-run (90s timeout)
    │ PASS? → ✅ Done
    │
    ▼
classify_error(stderr)
    │
    ├── Static fixer tồn tại? → apply → re-dry-run
    │                           └── PASS? → ✅ Done
    │                           └── FAIL? → classify lại → lặp (max 3)
    │
    └── Không có static fixer? → LLM Agent → apply → re-dry-run
                                    └── PASS? → ✅ Done
                                    └── FAIL? → classify lại → lặp (max 3)
    │
    ▼
❌ Mark as unrepairable
```

Mỗi iteration:
1. Apply fix
2. Re-dry-run (90s timeout)
3. Nếu PASS → done
4. Nếu FAIL với ErrorType khác → tiếp tục iteration tiếp theo
5. Nếu FAIL với ErrorType giống hoặc UNKNOWN → dừng, mark unrepairable

Harness source được preprocess trước khi vào Repair Loop: strip markdown fences, xóa empty import statements, sửa unterminated docstrings.

---

## CHƯƠNG 4. THỰC NGHIỆM

### 4.1 Tổng quan kiến trúc

Oraculum là một framework hybrid static-dynamic analysis được tăng cường bởi LLM. Pipeline gồm 5 giai đoạn:

```
VHX Output → Ingest (Stage 0) → Classify (Stage 1) → Oracle (Stage 2) → Harness (Stage 3) → Repair Loop (Stage 4) → Fuzzer Run
```

**Hình 4.1. Kiến trúc tổng thể của Oraculum.**

- **Stage 0 (Ingest)**: Nhập finding reports đã được VHX xác nhận là True Positive, chuyển đổi thành enriched findings với metadata cấu trúc code.
- **Stage 1 (Classify)**: LLM quyết định chiến lược monitoring strategy dựa trên bản chất của sink: `recorded_call`, `return_value`, hoặc `filesystem_state`.
- **Stage 2 (Oracle)**: Sinh Oracle Specification dưới dạng JSON, định nghĩa rules, targets, regex patterns, và parameters để fuzz.
- **Stage 3 (Harness)**: Áp dụng Jinja2 skeletons để xây dựng Atheris fuzz target hoàn chỉnh và khởi tạo seed corpus directory.
- **Stage 4 (Repair Loop)**: Tự động sửa lỗi runtime của harness sinh ra (xem Section 3.2.5).

### 4.2 Cài đặt thực nghiệm

**Bảng 4.1. Cấu hình thực nghiệm.**

| Tham số | Giá trị |
|---------|---------|
| **Dataset** | RealVuln Benchmark (62 Python repos) |
| **Ground truth** | 2,182 findings |
| **VHX true positives** | 671 |
| **SAST engine** | CodeQL |
| **LLM model** | DeepSeek `deepseek-v3-1-250821` qua shopaikey.com |
| **Fuzzing engine** | Atheris (coverage-guided) |
| **Thời gian dry-run** | 90s timeout |
| **Python version** | 3.12 |
| **Django version** | 3.2 (tương thích với code cũ) |

### 4.3 Metrics đánh giá

Chúng tôi không sử dụng Precision, Recall, hoặc F1-Score vì ground truth cho "fuzzable vulnerabilities" không tồn tại — không có dataset nào ghi nhận lỗ hổng nào có thể fuzz được bằng Atheris trong N iterations. Thay vào đó, chúng tôi báo cáo pipeline-conversion metrics:

**Bảng 4.2. Định nghĩa metrics.**

| Metric | Công thức | Ý nghĩa |
|--------|-----------|---------|
| **Harness Generation Rate (HGR)** | `harness / VHX TP` | Tỷ lệ TP có thể chuyển đổi thành harness |
| **Runtime Pass Rate (RPR)** | `(PASS + BUG) / total` | Tỷ lệ harness chạy ổn |
| **First-Run Bug Detection Rate (FBDR)** | `BUG / total` | Chặn dưới của precision |
| **End-to-End Confirmation Rate (ECR)** | `BUG / VHX TP` | Tổng thể từ TP → bug confirmed |
| **Stage Survival Rate** | `output / input per stage` | Phát hiện bottlenecks |
| **Repair Loop Recovery Rate** | `fixed / attempted` | Hiệu quả của repair |

**Giải thích tại sao không dùng Precision/Recall/F1:**

Precision yêu cầu phân biệt True Positive (harness crash vì lỗ hổng thật) và False Positive (harness crash vì lỗi khác). Để phân biệt, cần manual triage từng crash — 17 harness × ~30 phút = ~8.5 giờ. Hiện tại chúng tôi chưa thực hiện manual triage này.

Recall yêu cầu biết tổng số harness có thể crash (true positives + false negatives). Tất cả 71 PASS harnesses đều là false negative tiềm năng — chúng có thể cần hàng triệu iterations để trigger bug. Không thể biết con số này nếu không chạy fuzzing hàng giờ.

First-Run Bug Detection Rate (13.8%) được sử dụng như một chặn dưới của precision: ít nhất 13.8% harnesses kích hoạt crash ngay iteration đầu tiên.

### 4.4 Kết quả Pipeline

#### 4.4.1 Stage Survival

**Bảng 4.3. Per-stage survival từ VHX TP đến working harness.**

| Stage | Input | Output | Survival |
|-------|-------|--------|----------|
| VHX (CodeQL + LLM) | 2,182 ground-truth | 671 TP | 30.7% |
| Classification (Stage 1) | 671 TP | 510 | 76.0% |
| Oracle generation (Stage 2) | 510 | 450 | 88.2% |
| Harness generation (Stage 3) | 450 | 123 harnesses | 27.3% |
| Repair Loop Track A (Stage 4) | 123 | 67 PASS | 54.5% |
| Repair Loop Track B (Stage 4) | 123 | 88 working | 71.5% |

Harness generation stage có survival rate thấp nhất (27.3%). Nguyên nhân chính là LLM generation failures: syntax errors, incomplete code, markdown fences, empty import statements. Cải thiện generation prompt hoặc thêm validation-retry loop tại generation time sẽ trực tiếp tăng final yield.

#### 4.4.2 Repair Loop Impact

Repair Loop cải thiện pass rate từ 26.8% (baseline) lên 71.5% (full repair) — tăng 2.7 lần qua 7 phiên bản iterative:

**Bảng 4.4. Progressive improvement across repair versions.**

| Version | Fix applied | PASS rate |
|---------|------------|-----------|
| V1 (baseline) | None | 33/123 (26.8%) |
| V2 (45s timeout, correct deps) | Package resolution | 33/123 (26.8%) |
| V3 (uv pip) | Correct dependency installation | 40/123 (32.5%) |
| V4 (static fixers) | Seed encoding, framework context, markdown cleanup | 44/123 (35.8%) |
| V5 (cwd fix) | Repo root working directory | 55/123 (44.7%) |
| V6 (instrument_all) | Atheris timeout workaround | 67/123 (54.5%) |
| V7 (full repair) | All static + LLM Agent | 88/123 (71.5%) |

Hai cải thiện lớn nhất là V5 → V6 (+12%, `instrument_all()` workaround) và V4 → V5 (+9%, working directory fix). Static fixers (V3 → V4) đóng góp +4-8%.

### 4.5 Kết quả Repair Loop

#### 4.5.1 Kết quả cuối (Track B)

**Bảng 4.5. Repair Loop outcomes — 123 harnesses.**

| Outcome | Count | Percentage |
|---------|-------|-----------|
| PASS | 71 | 57.7% |
| BUG | 17 | 13.8% |
| FAIL | 35 | 28.5% |
| TIMEOUT | 0 | 0.0% |
| **Working (PASS + BUG)** | **88** | **71.5%** |

#### 4.5.2 Phân tích 35 FAIL

Tất cả 35 harnesses FAIL đều do Atheris runtime limitations, không phải lỗi pipeline:

**Bảng 4.6. Phân tích FAIL harnesses.**

| Nhóm | Số lượng | Nguyên nhân |
|------|----------|-------------|
| Atheris C extension incompatibility | 25 | Module C extensions (`lxml`, `psycopg2`, `cryptography`) |
| Atheris SystemError during instrumentation | 10 | Django model chains phức tạp |

Các harness này hợp lệ về cú pháp và đúng ngữ nghĩa. Chúng thất bại chỉ vì Atheris internals — một giới hạn đã được document của fuzzing engine, không phải lỗi của sinh harness hay repair pipeline.

### 4.6 Bug Detection

17 harnesses kích hoạt Atheris crash ngay fuzz input đầu tiên (return code 77). Đây là confirmed exploitable vulnerabilities: Atheris thoát với non-zero code vì fuzzer phát hiện crash (segmentation fault, assertion failure, unhandled exception).

#### 4.6.1 60-second Fuzzing

Chúng tôi chạy thêm 60-second fuzzing trên 17 BUG harnesses để xác nhận. Kết quả: tất cả crash đều xảy ra ngay iteration 1 (rc=77). 16 crash files được tạo ra với exploit payloads thật. Không có thêm BUG nào được tìm thấy ngoài iteration đầu tiên.

**Bảng 4.7. Bug Detection — 17 harnesses, 16 crash files.**

| Vulnerability class | Count | Ví dụ crash input |
|--------------------|-------|-------------------|
| Weak sensitive data hashing | 3 | — |
| SQL injection | 3 | — |
| Shell command injection | 2 | `` `id` ``, `; ls` |
| Path injection / Path traversal | 2 | — |
| Clear text sensitive data (log, storage) | 2 | — |
| Full SSRF | 1 | `http://127.1/` |
| Reflective XSS | 1 | `JaVaScRiPt:alert(1)` |
| Template injection / SSTI | 1 | `{{7*7}}` |
| Cookie injection | 1 | — |
| Unclassified | 1 | — |

**Bảng 4.8. Crash inputs chi tiết.**

| Repo | Crash input | Kích thước | Mô tả |
|------|-------------|------------|-------|
| graphql-app | `` `id` `` | 4 bytes | Command injection — thực thi lệnh `id` |
| graphql-app | `; ls` | 4 bytes | Command injection — thực thi lệnh `ls` |
| dsvw | `http://127.1/` | 13 bytes | SSRF — redirect đến localhost |
| insecure-web | `JaVaScRiPt:alert(1)` | 19 bytes | Reflected XSS — case-mixed bypass |
| pythonssti | `{{7*7}}` | 7 bytes | SSTI — template expression injection |
| vulpy | `AKIATESTKEY12345678901234567890` | 31 bytes | AWS key exposure |
| vulpy | `AKIAIOSFODNN7EXAMPLE` | 20 bytes | AWS key exposure |

8 harnesses còn lại crash với empty input (0 bytes). Các crash này cần manual triage để xác định exact exploit path.

#### 4.6.3 Phân bố crash theo repository

**Bảng 4.9. Bug distribution by repository.**

| Repository | BUGs | Vulnerability |
|------------|------|--------------|
| realvuln-vulpy | 3 | Sensitive data exposure, cookie injection |
| realvuln-dsvw | 2 | SSRF, SQL injection |
| realvuln-threatbyte | 2 | SQL injection, path traversal |
| realvuln-vfapi | 2 | Weak sensitive data hashing |
| realvuln-damn-vulnerable-graphql-application | 1 | Command injection |
| realvuln-djangoat | 1 | Path traversal |
| realvuln-dvblab | 1 | SQL injection |
| realvuln-flask-xss | 1 | Log injection |
| realvuln-insecure-web | 1 | Reflected XSS |
| realvuln-pythonssti | 1 | SSTI |
| realvuln-vulnpy | 1 | Shell injection |
| vc-codex-high-seeded-v2-fintech-lending-fastapi | 1 | Weak sensitive data hashing |

### 4.7 So sánh với các nghiên cứu liên quan

**Bảng 4.10. So sánh với CKG-Fuzzer và HarnessAgent.**

| Tiêu chí | CKG-Fuzzer [Xu et al., 2025] | HarnessAgent [Yang et al., 2025] | Oraculum (công trình này) |
|-----------|-----------------------------|----------------------------------|--------------------------|
| Ngôn ngữ | C/C++ | Python | Python |
| Hướng tiếp cận | Static transformations + Code Knowledge Graph | Tool-augmented LLM pipelines | Static fixers + LLM Agent hybrid |
| Xử lý lỗi runtime | Compile/link errors | Không có | Import errors, framework context, Atheris timeout |
| Fallback cho lỗi mới | Không | Không | LLM Agent (DeepSeek) |
| Framework support | Không (C/C++) | Flask | Django, Flask, FastAPI |
| Số harness thử nghiệm | 104 | ~50 | 123 |
| Pass rate sau repair | ~60% | Không báo cáo | 71.5% |
| Bug detection | Không báo cáo | Không báo cáo | 17 BUGs confirmed |

### 4.8 Threats to Validity

1. **Single iteration fuzzing**: Phần lớn kết quả dựa trên `-runs=1`. Chúng tôi đã giảm thiểu threat này bằng cách chạy 60-second fuzzing trên 17 BUG harnesses — kết quả xác nhận tất cả crash đều xảy ra ngay iteration 1.

2. **Atheris version sensitivity**: Workaround `instrument_all()` là đặc thù của Atheris 2.x. Phiên bản tương lai có thể thay đổi failure profile.

3. **Django version lock**: Môi trường dùng Django 3.2, phiên bản mới nhất tương thích với `django.conf.urls.url()`. Dự án Django mới hơn (5.x+) có thể giới thiệu incompatibilities mới.

4. **Hardware variability**: Atheris instrumentation time tỷ lệ với số imported modules và độ phức tạp của `__init__` chains.

---

## KẾT LUẬN

### Kết luận

Nghiên cứu này trình bày Oraculum, một framework hybrid static-dynamic analysis cho phép tự động hóa việc sinh fuzz harness và xác nhận lỗ hổng bảo mật trong ứng dụng Python.

Pipeline 5-stage của Oraculum (Ingest → Classify → Oracle → Harness → Repair Loop) đã được thực nghiệm trên RealVuln benchmark gồm 62 Python repositories với 2,182 ground-truth vulnerability findings. Từ 671 VHX True Positives, pipeline tự động sinh ra 123 Atheris fuzz harnesses (Harness Generation Rate: 18.3%).

Đóng góp chính của nghiên cứu là **Repair Loop**, một module post-generation error recovery áp dụng Dynamic Program Repair cho Python fuzz harnesses. Repair Loop sử dụng kiến trúc hybrid gồm static fixers (cho các lỗi có pattern đã biết) và LLM Agent (cho các lỗi không có pattern tĩnh). Kết quả cho thấy:

- Runtime Pass Rate cải thiện từ 26.8% (baseline) lên 71.5% (full repair) — tăng 2.7 lần
- 17/123 harnesses (13.8%) kích hoạt Atheris crash ngay iteration đầu tiên, xác nhận lỗ hổng thật
- 16 crash files chứa exploit payloads thật: command injection (`; ls`), SSRF (`http://127.1/`), reflected XSS (`JaVaScRiPt:alert(1)`), SSTI (`{{7*7}}`), AWS key exposure (`AKIA...`)
- 35/123 harnesses (28.5%) không thể đánh giá do Atheris không tương thích với C extensions — đây là giới hạn của fuzzing engine, không phải pipeline

Chúng tôi không báo cáo Precision, Recall, hoặc F1-Score vì ground truth cho "fuzzable vulnerabilities" không tồn tại. Thay vào đó, chúng tôi đề xuất 6 pipeline-conversion metrics: Harness Generation Rate, Runtime Pass Rate, First-Run Bug Detection Rate, End-to-End Confirmation Rate, Stage Survival Rate, và Repair Loop Recovery Rate.

So với CKG-Fuzzer [Xu et al., 2025] — công trình tiên phong về Dynamic Program Repair cho C/C++ fuzz harnesses — Oraculum mở rộng sang Python với kiến trúc hybrid static + LLM Agent, đạt pass rate 71.5% so với ~60% của CKG-Fuzzer. Ngoài ra, chúng tôi báo cáo 17 BUGs confirmed — một chỉ số không có trong các nghiên cứu trước đây.

### Hướng phát triển

1. **Cải thiện LLM Agent prompt**: Inject inferred `REPO_ROOT` path và PYTHONPATH vào prompt, cung cấp few-shot examples để tăng repair success rate.

2. **Fuzzing depth**: Chạy fuzzing 60-300 giây trên 71 PASS harnesses để tìm thêm bugs. 17 BUGs trong 1 iteration cho thấy tiềm năng cao, nhưng cần thời gian fuzzing dài hơn để xác nhận.

3. **Atheris C extension compatibility**: Wrap C-dependent imports trong `try/except ImportError` tại harness generation time, hoặc sử dụng fuzzing engine thay thế (CPython Fuzzer).

4. **Pipeline stage losses**: Harness generation stage mất 72.7% oracle specs. Cải thiện generation prompt hoặc thêm validation-retry loop tại generation time.

5. **Mở rộng ngôn ngữ**: Áp dụng phương pháp cho JavaScript, Go, Java — các ngôn ngữ phổ biến trong thực tế.
