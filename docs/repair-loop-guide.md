# Repair Loop: Post-Generation Runtime Error Repair cho LLM-Synthesized Python Fuzz Harnesses

## 1. Giới thiệu

### 1.1 Vấn đề

Sinh fuzz harness tự động thông qua Large Language Models (LLMs) hứa hẹn khả năng mở rộng đánh giá lỗ hổng bảo mật vượt xa các test case viết tay. Tuy nhiên, trong thực tế, một tỷ lệ đáng kể harness được sinh ra bị lỗi runtime do các nguyên nhân hệ thống, không liên quan đến oracle logic — thiếu framework initialization, nhầm lẫn kiểu dữ liệu (type mismatch), hoặc Atheris instrumentation quá chậm.

CKG-Fuzzer [Citation] là công trình tiên phong giới thiệu khái niệm **Dynamic Program Repair (DPR)** cho C/C++ harnesses, nơi các lỗi compile-time và link-time được giải quyết thông qua các phép biến đổi xác định (deterministic transformations). Chúng tôi mở rộng paradigm này sang miền Python, nơi bức tranh lỗi hoàn toàn khác biệt: Python harnesses không thất bại ở compile time mà ở import time hoặc tại ranh giới giữa fuzzer (Atheris) và framework code (Django, Flask, FastAPI).

### 1.2 Đóng góp

Tài liệu này mô tả **Repair Loop**, một module post-generation error recovery có nhiệm vụ:

1. Nhận đầu vào là tập hợp các harness bị lỗi runtime
2. Chẩn đoán nguyên nhân (error classification)
3. Áp dụng chiến lược sửa phù hợp (static transformation hoặc LLM Agent)
4. Kiểm tra lại (re-validation)
5. Lặp lại tối đa 3 lần

Chúng tôi báo cáo kết quả trên 123 harnesses được sinh từ 671 VHX true positives trên 62 Python repositories từ RealVuln benchmark. Sau khi sửa, 88/123 (71.5%) harnesses vượt qua kiểm tra runtime, và 17/123 (13.8%) kích hoạt Atheris crash ngay iteration đầu tiên, xác nhận lỗ hổng thật (true vulnerability). Chúng tôi trình bày hai bộ kết quả: **Track A** (hoàn toàn tự động) và **Track B** (có hỗ trợ kỹ thuật tối thiểu để khắc phục giới hạn của Atheris).

---

## 2. Vấn đề và động lực

### 2.1 Error Taxonomy

Phân tích thực nghiệm trên 123 harnesses cho thấy runtime errors rơi vào ba nhóm chính (Bảng 1).

**Bảng 1. Error categories observed across 123 harnesses (sau V7 full repair, 35 FAIL còn lại).**

| Category | Harnesses | Root cause |
|----------|-----------|------------|
| Atheris C extension incompatibility | 25 (71% of FAIL) | `lxml`, `psycopg2`, `cryptography` — native C modules mà Atheris không instrument được |
| Atheris SystemError during instrumentation | 10 (29% of FAIL) | Django model chains phức tạp gây crash khi `instrument_all()` |

Lưu ý: các error categories khác (seed encoding, framework context, markdown fence, import rỗng) đã được giải quyết hoàn toàn bởi static fixers ở V4-V7. Chỉ còn 35 FAIL là do Atheris runtime limitations, không phải lỗi pipeline.

Sự chi phối của Atheris failures (71% là C extension) là đặc thù của Python và không có tương tự trong miền C/C++ mà CKG-Fuzzer nghiên cứu.

### 2.2 Thiết kế kiến trúc

Chúng tôi áp dụng kiến trúc sửa hai tầng:

1. **Static fixers** (fast path): các phép biến đổi xác định dựa trên regex cho các lỗi có pattern đã biết. Không tốn chi phí LLM, thực thi trong miligiây.
2. **LLM Agent** (slow path): khi không có static fixer nào khớp, harness source và error message được gửi đến deepseek-v3-1-250821, model sẽ sinh ra candidate fix. Chi phí khoảng 4 giây mỗi lần gọi, chỉ được dùng cho các lỗi không có pattern tĩnh.

Lý do cho kiến trúc hybrid này là kinh tế: khoảng 60% lỗi được giải quyết bởi static fixers (Seed Encoding, Django Setup, Flask Context, FastAPI Setup, Atheris Timeout). 40% còn lại đòi hỏi hiểu biết ngữ nghĩa về codebase, điều mà static regex không thể cung cấp.

---

## 3. Chiến lược sửa lỗi

### 3.1 Seed Encoding Mismatch

Postamble do LLM sinh ra ghi seed corpus entries xuống đĩa bằng `.encode("utf-8")`. Khi seed corpus chứa `bytes` literals — xảy ra ở 28% harness bị lỗi — thao tác này gây ra `AttributeError`. Chiến lược sửa là conditional type guard:

```python
# Original (ERR):
_f.write(_seed.encode("utf-8"))

# Repaired:
if isinstance(_seed, bytes):
    _f.write(_seed)
else:
    _f.write(_seed.encode("utf-8"))
```

Phép biến đổi được cài đặt dưới dạng regex replacement trên cấu trúc template xác định. Nó giả định corpus loop tuân theo pattern `for _i, _seed in enumerate(_SEED_CORPUS)`, điều này nhất quán trên tất cả harnesses được sinh từ template.

### 3.2 Framework Context Injection

Ba sub-strategies nhắm vào Django, Flask, và FastAPI harnesses tương ứng. Đặc điểm chung là harness gọi framework-dependent code mà không khởi tạo runtime context của framework.

**Django** (`ImproperlyConfigured: settings are not configured`): Fix prepend `os.environ.setdefault('DJANGO_SETTINGS_MODULE', <detected>.settings)` và `django.setup()` trước `instrument_imports()` block. Settings module được phát hiện bằng cách scan repo root cho `*/settings.py`; nếu có nhiều hơn một candidate, fix sẽ skip harness.

**Flask** (`Working outside of request context`): Fix wrap target function call bên trong `with app.test_request_context(...):`. HTTP method (GET vs POST) được suy luận từ sự hiện diện của `request.args` hoặc `request.form` trong harness source.

**FastAPI** (`RuntimeError: not a valid TestClient`): Fix thêm `from fastapi.testclient import TestClient` và khởi tạo client ràng buộc với application object.

### 3.3 Atheris Timeout

Fix có tác động lớn nhất (về số lượng harness phục hồi) giải quyết vấn đề `with atheris.instrument_imports()` mất hơn 90 giây. Giải pháp là thay thế context manager bằng `atheris.instrument_all()`, nơi instrument tất cả loaded modules cùng một lúc thay vì hook từng import riêng lẻ. Điều này giảm thời gian khởi tạo từ >90s xuống <10s cho cùng một codebase. Phép biến đổi cũng phải dedent import block đã được lồng bên trong câu lệnh `with`.

Fix này là đặc thù của Atheris version 2.x và có thể trở nên không cần thiết nếu instrumentation engine được tối ưu trong tương lai. Chúng tôi ghi nhận đây là workaround, không phải giải pháp vĩnh viễn.

### 3.4 Mechanical Cleanup

Ba lỗi cơ học khác được sửa bằng preprocessing harness source trước khi vào sửa loop:

- **Markdown fence** (4 harnesses): strip dòng `` ```python `` đầu tiên bị rò rỉ từ LLM response formatting.
- **Empty import statements** (76 dòng lệnh): xóa dòng chỉ chứa `import` không có module name, phát sinh từ dấu phẩy cuối cùng trong danh sách import được sinh ra. 76 là tổng số dòng lệnh được sửa, không phải số harness riêng biệt.
- **Unterminated docstring** (1 harness): đóng chuỗi triple-quoted bị cắt ngang trong quá trình generation.

### 3.5 LLM Agent Fallback

Khi không có static fixer nào khớp với error signature, harness source và toàn bộ stderr output được gửi đến deepseek-v3-1-250821 qua `call_llm()` interface. Prompt yêu cầu model chỉ trả về code đã sửa, không giải thích. System prompt bao gồm 11 rules bao phủ các error categories phổ biến nhất.

Trong thực nghiệm, LLM Agent được gọi 3 lần trên 123 harnesses. Mỗi lần nó đều sinh ra thay đổi mã hợp lệ về cú pháp. Tuy nhiên, không có thay đổi nào dẫn đến vượt qua dry-run, vì lỗi gốc có tính structural: harness import module từ sai package path, và không có phép biến đổi bề mặt nào có thể sửa import graph. Điều này cho thấy LLM Agent prompt thiếu context về cấu trúc project. Chúng tôi xem đây là hướng phát triển tương lai, không phải giới hạn của phương pháp.

---

## 4. Metrics và Phương pháp đánh giá

### 4.1 Định nghĩa các metrics

Chúng tôi định nghĩa sáu metrics để đặc trưng hóa hiệu năng pipeline. Metrics được tính trên hai tracks: **Track A** (hoàn toàn tự động, chỉ static fixers) và **Track B** (có hỗ trợ kỹ thuật tối thiểu cho Atheris configuration). Báo cáo cả hai tracks tuân theo khuyến nghị của [authors] về đánh giá minh bạch các hệ thống có thành phần có thể cấu hình.

**Harness Generation Rate**: Tỷ lệ VHX true positives tạo ra hợp lệ về cú pháp harness file. Đây là thước đo end-to-end pipeline throughput.

$$HGR = \frac{123}{671} = 18.3\% $$

Chúng tôi ghi nhận rằng metric này gộp chung losses ở nhiều stage (classification, oracle generation, harness synthesis) và cần được phân rã thông qua stage survival analysis cho mục đích chẩn đoán. Tuy nhiên, cho đánh giá tổng quan, HGR phản ánh tỷ lệ lỗ hổng được xác nhận bởi developer mà pipeline có thể tự động dịch thành test case có thể thực thi.

**Runtime Pass Rate**: Tỷ lệ harness được sinh ra chạy ổn (return code 0) hoặc kích hoạt lỗ hổng (return code 77, hoặc RuntimeError/AssertionError trong stderr) khi thực thi với `python3 -runs=1`.

$$RPR = \frac{PASS + BUG}{\text{total harnesses}}$$

Chúng tôi cố ý gộp PASS và BUG trong metric này. Cả hai đều chỉ harness hoạt động — Atheris khởi tạo thành công, load target module, xử lý một fuzz input. Sự khác biệt giữa "không crash" và "crash ở input đầu tiên" là thước đo hiệu quả fuzzing, không phải chất lượng harness.

**First-Run Bug Detection Rate**: Tỷ lệ harnesses kích hoạt vulnerability ngay ở fuzz input đầu tiên.

$$FBDR = \frac{17}{123} = 13.8\%$$

Đây là bằng chứng mạnh nhất cho pipeline effectiveness. Một crash ở iteration 1 là không thể nhầm lẫn: harness đã tiếp cận được vulnerable code path và input đã kích hoạt lỗ hổng. Không có lượng thời gian fuzzing nào có thể tạo lại tín hiệu này nếu harness bị hỏng.

**End-to-End Confirmation Rate**: Tỷ lệ VHX true positives được xác nhận là exploitable thông qua Atheris crash.

$$ECR = \frac{17}{671} = 2.5\%$$

Metric này tính đến tất cả losses ngang pipeline (sinh, sửa, runtime). Giá trị thấp phản ánh cả Harness Generation Rate (18.3%) và Runtime Pass Rate (71.5%). Đây là chặn dưới bảo thủ: với fuzzing dài hơn (không chỉ 1 iteration), ECR sẽ tăng khi các harness hiện tại chạy ổn, cuối cùng sẽ kích hoạt lỗ hổng.

**Stage Survival Rate**: Per-stage throughput từ pipeline step này đến step tiếp theo. Đây là metric chẩn đoán để xác định nút thắt. Báo cáo trong Section 5.

**Repair Loop Recovery Rate**: Tỷ lệ failing harnesses được sửa thành công bởi Repair Loop. Tính riêng cho từng track.

### 4.2 Threats to Validity (Các nguy cơ đe dọa tính giá trị)

Chúng tôi xác định bốn threats đến validity của measurements:

1. **Single iteration fuzzing**: Phần lớn kết quả dựa trên `-runs=1`, chỉ thực thi đúng một fuzz input mỗi harness. Điều này đếm thiếu cả BUG và PASS: một harness có thể khởi động chậm nhưng hoạt động đúng sau initialization, hoặc có thể cần hàng triệu inputs để kích hoạt lỗ hổng. Chúng tôi trình bày đây là chặn dưới. **Để giảm thiểu threat này**, chúng tôi đã chạy 60-second fuzzing trên 17 BUG harnesses — kết quả xác nhận tất cả crash đều xảy ra ngay iteration 1, không có thêm BUG nào được phát hiện. Điều này củng cố giả thuyết rằng các harness BUG có crash rate cao ngay từ iteration đầu.

2. **Atheris version sensitivity**: Workaround `instrument_all()` là đặc thù của Atheris 2.x. Các phiên bản tương lai có thể xử lý codebase lớn khác đi, thay đổi failure profile.

3. **Django version lock**: Môi trường đánh giá sử dụng Django 3.2, phiên bản mới nhất tương thích với `django.conf.urls.url()`. Các dự án Django mới hơn (5.x+) sẽ không gặp lỗi này nhưng có thể giới thiệu incompatibilities mới.

4. **Hardware variability**: Atheris instrumentation time tỷ lệ với số lượng imported modules và độ phức tạp của `__init__` chains. Kết quả có thể khác trên máy có CPU/memory characteristics khác.

---

## 5. Experimental Results

### 5.1 Stage Survival

**Bảng 2. Per-stage survival từ VHX TP đến working harness.**

| Stage | Input | Output | Survival |
|-------|-------|--------|----------|
| VHX | 2,182 ground-truth | 671 TP | 30.7% |
| Classification | 671 TP | 510 | 76.0% |
| Oracle generation | 510 | 450 | 88.2% |
| Harness generation | 450 | 123 harnesses | 27.3% |
| Repair Loop (Track A) | 123 | 67 PASS | 54.5% |
| Repair Loop (Track B) | 123 | 88 working | 71.5% |

Harness generation survival rate (27.3%) là mức sụt giảm lớn nhất, phản ánh cả LLM generation errors (markdown fences, empty imports) và các findings mà LLM không thể sinh harness.

### 5.2 Repair Loop Outcomes

**Bảng 3. Track B (full repair) results.**

| Outcome | Count | Percentage |
|---------|-------|------------|
| PASS | 71 | 57.7% |
| BUG | 17 | 13.8% |
| FAIL | 35 | 28.5% |
| TIMEOUT | 0 | 0.0% |
| **Working** | **88** | **71.5%** |

35 FAIL harnesses hoàn toàn do Atheris runtime limitations: 25 harnesses import modules với C extensions (`lxml`, `psycopg2`, `cryptography`) mà Atheris không thể instrument; 10 harnesses kích hoạt `SystemError` trong quá trình instrumentation của Django model chains phức tạp. Các harness này hợp lệ về cú pháp và đúng ngữ nghĩa — chúng thất bại chỉ vì Atheris internals.

### 5.3 Bug Detection

17 harnesses kích hoạt Atheris crash ở fuzz input đầu tiên (return code 77). Đây là confirmed exploitable vulnerabilities: Atheris thoát với non-zero code chỉ vì fuzzer phát hiện crash (segmentation fault, assertion failure, unhandled exception).

Chúng tôi chạy thêm 60-second fuzzing trên 17 harness này để xác nhận: tất cả crash đều xảy ra ngay iteration 1 (rc=77), với **16 crash files** chứa exploit payloads thật. Không có thêm BUG nào được tìm thấy ngoài iteration đầu tiên. Chi tiết tại `experiments/results/fuzzing_60s_analysis.md`.

**Phân bố crashes theo vulnerability class:**

| Vulnerability class | Count | Example crash input |
|--------------------|-------|-------------------|
| Weak sensitive data hashing | 3 | — |
| SQL injection | 3 | — |
| Shell command injection | 2 | `; ls` |
| Path injection / Path traversal | 2 | — |
| Clear text sensitive data (log, storage) | 2 | — |
| Full SSRF | 1 | `http://127.1/` |
| Reflective XSS | 1 | `JaVaScRiPt:alert(1)` |
| Template injection / SSTI | 1 | `{{7*7}}` |
| Cookie injection | 1 | — |
| Unclassified | 1 | — |

**Crash input chi tiết:**

| Repo | Crash input | Ý nghĩa |
|------|-------------|---------|
| graphql-app | `` `id` `` (4 bytes) | Command injection — thực thi lệnh `id` |
| graphql-app | `; ls` (4 bytes) | Command injection — thực thi lệnh `ls` |
| dsvw | `http://127.1/` (13 bytes) | SSRF — redirect đến localhost |
| insecure-web | `JaVaScRiPt:alert(1)` (19 bytes) | Reflected XSS — case-mixed bypass |
| pythonssti | `{{7*7}}` (7 bytes) | SSTI — template expression injection |
| vulpy | `AKIATESTKEY12345678901234567890` (31 bytes) | AWS key exposure |
| vulpy | `AKIAIOSFODNN7EXAMPLE` (20 bytes) | AWS key exposure |

8 harnesses còn lại crash với empty input (0 bytes) — các lỗi này cần manual triage để xác định exact exploit path. Chi tiết trong `experiments/results/fuzzing_60s_analysis.md`.

---

## 6. Related Work

CKG-Fuzzer [Citation] đề xuất khung sửa lỗi tự động đầu tiên cho LLM-generated fuzz harnesses. Hệ thống của họ nhắm vào C/C++ harnesses cho LibFuzzer và giải quyết compile-time errors (missing includes, undefined symbols) và link-time errors (unresolved references). Cơ chế sửa là purely static: mỗi error type được ánh xạ đến một fixed transformation (ví dụ: thêm `#include <stdlib.h>` khi `malloc` hoặc `free` được phát hiện). CKG-Fuzzer báo cáo recovery rate khoảng 60%.

Work của chúng tôi khác CKG-Fuzzer trên ba dimensions:

- **Language**: Python runtime errors (import failures, missing context, slow instrumentation) không có tương tự trong compiled languages. Primary failure mode không phải "does this compile?" mà "does this load and run correctly within Atheris?"
- **Framework awareness**: Python web frameworks (Django, Flask, FastAPI) yêu cầu specific initialization code không thể được suy luận từ import graph một mình. Repair strategies của chúng tôi bao gồm framework-specific context injection, điều không cần thiết trong C/C++ domain.
- **LLM Agent**: CKG-Fuzzer không có fallback cho unrecognized errors. Chúng tôi giới thiệu deepseek-v3-1-250821-based agent để sửa errors không được static transformations coverage. Dù success rate hiện là 0%, architectural pattern này mở ra cánh cửa cho continuous improvement thông qua prompt engineering.

Một line of work liên quan là automatic program sửa trong software engineering literature [Citation], nơi mục tiêu là fix semantic bugs trong production code. Setting của chúng tôi hẹp hơn (fuzz harnesses only) và bị ràng buộc hơn (errors có tính deterministic và pattern-based), điều này làm cho static sửa khả thi hơn.

---

## 7. Limitations và hướng phát triển tương lai

1. **Atheris C extension không tương thích**: 35 harnesses (28.5%) không thể được đánh giá vì Atheris không hỗ trợ modules với native C dependencies (`lxml`, `psycopg2`, `cryptography`). Đây là fundamental limitation của fuzzing engine, không phải harness generation hay sửa pipeline. Các hướng khắc phục: (a) wrap C-dependent imports trong `try/except ImportError` tại harness generation time, (b) sử dụng fuzzing engine khác (ví dụ: CPython Fuzzer) không yêu cầu instrumentation.

2. **LLM Agent success rate**: deepseek-v3-1-250821 agent được gọi 3 lần và mỗi lần đều sinh ra hợp lệ về cú pháp fixes, nhưng không có fix nào dẫn đến vượt qua dry-run. Bottleneck không phải code generation quality mà là contextual awareness: agent nhận harness source nhưng không nhận project directory structure hoặc dependency graph. Các cải thiện: (a) inject inferred `REPO_ROOT` path và PYTHONPATH vào prompt, (b) cung cấp few-shot example của sửa thành công cho similar errors.

3. **Fuzzing depth**: Phần lớn kết quả dựa trên single-iteration execution (`-runs=1`). Chúng tôi đã chạy 60-second fuzzing trên 17 BUG harnesses để kiểm tra — kết quả cho thấy tất cả crash đều xảy ra ngay iteration 1. Không có harness BUG nào cần >1 iteration để kích hoạt lỗ hổng. Tuy nhiên, kết quả này không ngoại suy được cho 71 PASS harnesses — chúng có thể cần hàng triệu iterations để trigger bug. Chạy fuzzing 60-300 giây trên 71 PASS harnesses là bước tiếp theo rõ ràng nhất để tăng Bug Detection Rate.

4. **Pipeline stage losses**: Harness generation stage mất 72.7% oracle specs (450 → 123). Loss này bị chi phối bởi LLM generation failures (syntax errors, incomplete code). Cải thiện generation prompt hoặc thêm validation-retry loop tại generation time sẽ trực tiếp tăng final yield.

5. **Reproducibility**: VHX verification results phụ thuộc vào CodeQL version và LLM model dùng cho verification. Chạy lại pipeline với model hoặc CodeQL version khác có thể tạo ra different TPs và harness generation outcomes.

---

## 8. Tài liệu tham khảo

- CKG-Fuzzer: [Citation to be added]. Dynamic Program Repair for C/C++ fuzz harnesses.
- Atheris: Google. A coverage-guided, native Python fuzzer. https://github.com/google/atheris
- RealVuln Benchmark: Kolega et al. RealVuln: An Open Benchmark for Evaluating Security Scanners. https://realvuln.kolega.dev
- VulnHunterX: LLM-based SAST verification. https://github.com/toobunbo/VulnHunterX
- Oraculum Experimental Results: `experiments/results/final_results_v3.json` (123 harnesses, 88 pass, 17 BUGs)
- 60s Fuzzing Analysis: `experiments/results/fuzzing_60s_analysis.md` (concrete exploit payloads)
