# Hướng Dẫn Chi Tiết Chạy Thử Nghiệm Oraculum Với Real-Vuln-Benchmark & VulnHunterX

Tài liệu này được biên soạn chi tiết từ con số 0 nhằm giúp bất kỳ ai (bao gồm các partner/tester mới tiếp cận dự án) có thể tự thiết lập môi trường, chạy pipeline kiểm tra tĩnh, sinh fuzzer harness và thực hiện chạy fuzzing để đánh giá hiệu quả của hệ thống **Oraculum**.

---

## 1. Tổng Quan Về Quy Trình Thử Nghiệm

Mục đích của đợt thử nghiệm này là đối chứng khả năng tự động tạo mã fuzzer và bắt lỗi của **Oraculum** với tập lỗi thực tế (ground truth) của **Real-Vuln-Benchmark**:

```
[Real-Vuln-Benchmark] (Mã nguồn lỗi thật)
       │
       ▼ (Chạy quét tĩnh & lọc nhiễu)
[VulnHunterX] ──► Sinh file verification summary (Chứa các True Positive findings)
       │
       ▼ (Ingest và chạy qua 3 Stage của Oraculum)
[Oraculum] ──► Sinh Atheris Fuzzer Targets + Custom Oracles
       │
       ▼ (Chạy Fuzzer trong môi trường ảo)
[Atheris Run] ──► Kiểm tra xem có bắt được Violation (Lỗi bảo mật) hay không
```

---

## 2. BƯỚC 1: Chuẩn Bị Môi Trường Chung

Trước tiên, máy tính của bạn cần được cấu hình các biến môi trường và Python ảo.

1. **Yêu cầu hệ thống**: Linux (khuyên dùng Ubuntu) và cài sẵn Python 3.12 (hoặc tối thiểu là 3.10).
2. **Kích hoạt virtual environment**:
   Mọi thao tác chạy lệnh đều cần chạy trong virtual environment (`.venv`) của dự án.
   ```bash
   source .venv/bin/activate
   ```
3. **Cấu hình file `.env`**:
   Đảm bảo file `.env` ở thư mục gốc của dự án chứa thông tin kết nối LLM. Oraculum chính thức hỗ trợ 3 nhà cung cấp (`openai`, `anthropic`, `ollama`):
   
   * **Lựa chọn A: Ollama Cloud (Chế độ tự động xoay vòng nhiều Keys)**
     ```ini
     LLM_PROVIDER=ollama
     LLM_MODEL=qwen3-coder:480b-cloud
     OLLAMA_API_BASE=https://ollama.com
     OLLAMA_API_KEYS=key1,key2,key3
     ```
     
   * **Lựa chọn B: Ollama (Chạy Local)**
     ```ini
     LLM_PROVIDER=ollama
     LLM_MODEL=qwen3-coder
     OLLAMA_API_BASE=http://localhost:11434
     ```
     
   * **Lựa chọn C: OpenAI**
     ```ini
     LLM_PROVIDER=openai
     LLM_MODEL=gpt-4o
     OPENAI_API_KEY=your-openai-api-key
     # Không bắt buộc: OPENAI_BASE_URL=https://custom-proxy.com/v1
     ```
     
   * **Lựa chọn D: Anthropic**
     ```ini
     LLM_PROVIDER=anthropic
     LLM_MODEL=claude-3-5-sonnet-latest
     ANTHROPIC_API_KEY=your-anthropic-api-key
     ```
4. **Kiểm tra môi trường**:
   Chạy lệnh sau để đảm bảo mọi cấu hình và kết nối LLM đều ở trạng thái sẵn sàng (phải đạt `✅` hết):
   ```bash
   oraculum check-env
   ```

---

## 3. BƯỚC 2: Cài Đặt Dữ Liệu Real-Vuln-Benchmark Trong VulnHunterX

Chúng ta cần chuẩn bị mã nguồn các dự án mục tiêu của Real-Vuln-Benchmark.

1. **Di chuyển vào thư mục VulnHunterX**:
   *(Giả định thư mục VulnHunterX nằm song song với thư mục Oraculum trong máy của bạn)*
   ```bash
   cd ../VulnHunterX
   source .venv/bin/activate
   ```
2. **Tải cấu trúc ground-truth của Real-Vuln-Benchmark**:
   Chạy script để tự động tải thông tin lỗi của Real-Vuln:
   ```bash
   python benchmarks/scripts/setup_datasets.py --dataset realvuln
   ```
   *Lệnh này sẽ clone dự án Real-Vuln-Benchmark về thư mục `benchmarks/datasets/realvuln`.*

3. **Tải và check out mã nguồn các dự án lỗi (Target Repos)**:
   Real-Vuln-Benchmark bao gồm 26 dự án Python web (Flask, Django, FastAPI...). Chúng ta cần clone và checkout chúng về đúng phiên bản chứa lỗi:
   ```bash
   cd benchmarks/datasets/realvuln
   python3 clone_repos.py             # Tải toàn bộ 26 dự án về thư mục _repos/
   python3 smoke_test.py              # Kiểm tra xem các dự án đã checkout đúng commit sha chưa
   cd ../../../VulnHunterX            # Quay lại thư mục gốc của VulnHunterX
   ```

---

## 4. BƯỚC 3: Chạy Quét & Xác Minh Bằng VulnHunterX

Để có đầu vào cho Oraculum, chúng ta dùng VulnHunterX quét các dự án mục tiêu để tìm và xác minh lỗi True Positive.

Ví dụ ta sẽ chạy kiểm thử dự án **`code-injection-bench`** (một repo chứa các lỗi chèn mã độc thực tế):

1. **Chạy lệnh scan**:
   ```bash
   vuln-hunter-x scan \
     --local-path benchmarks/datasets/realvuln/_repos/code-injection-bench \
     --lang python \
     --name code-injection-bench
   ```
2. **Đợi quá trình quét hoàn tất**:
   *   VulnHunterX sẽ gọi CodeQL/Semgrep để quét tìm lỗ hổng tĩnh.
   *   Sau đó gọi LLM để đặt câu hỏi loại bỏ False Positive.
   *   Khi chạy xong, kết quả xác minh sẽ được xuất ra tại thư mục:
       `output/python/code-injection-bench/verification_results/`

---

## 5. BƯỚC 4: Chạy Pipeline Của Oraculum

Sau khi có dữ liệu quét lỗi từ VulnHunterX, chúng ta di chuyển sang thư mục **Oraculum** để tiến hành sinh fuzzer.

1. **Di chuyển sang thư mục Oraculum**:
   ```bash
   cd ../Oraculum
   source .venv/bin/activate
   ```
2. **Ingest: Nhập dữ liệu lỗ hổng (Stage 0)**:
   Lệnh này sẽ đọc dữ liệu từ VulnHunterX và phân tích cấu trúc mã nguồn để sinh ra tệp thông tin trung gian:
   ```bash
   oraculum ingest \
     --vhx-root ../VulnHunterX \
     --repo code-injection-bench \
     --output-dir output/python/ \
     --force
   ```
3. **Classify: Phân loại chiến lược giám sát (Stage 1)**:
   LLM sẽ phân tích lỗi xem nên giám sát bằng cách kiểm tra giá trị trả về (`return_value`), ghi nhận lệnh gọi hàm (`recorded_call`), hay giám sát hệ thống file (`filesystem_state`):
   ```bash
   oraculum classify \
     --repo code-injection-bench \
     --output-dir output/python/ \
     --log-file output/python/code-injection-bench/classify_log.md \
     --force
   ```
4. **Oracle: Tạo đặc tả Oracle Spec (Stage 2)**:
   Sinh ra file JSON chứa luật phát hiện hành vi xâm nhập độc hại (ví dụ: regex kiểm tra command injection):
   ```bash
   oraculum oracle \
     --repo code-injection-bench \
     --output-dir output/python/ \
     --force
   ```
5. **Harness: Sinh mã nguồn Fuzzer Target (Stage 3)**:
   Tự động sinh mã nguồn Python chạy Atheris fuzzer và seed corpus ban đầu:
   ```bash
   oraculum harness \
     --repo code-injection-bench \
     --output-dir output/python/ \
     --force
   ```
   *Mã nguồn các file fuzzing sẽ nằm trong thư mục:*
   `output/python/code-injection-bench/fuzz_targets/`

---

## 6. BƯỚC 5: Chạy Fuzzer Tìm Lỗi (Fuzz Run)

Ở bước này, chúng ta sẽ cho fuzzer chạy thực tế để xem nó có phát hiện và báo lỗi lỗ hổng bảo mật hay không.

### 1. Kiểm tra biên dịch (Smoke Test)
Chạy fuzzer với tham số `-runs=1` để xem file fuzzer có lỗi import hay lỗi cú pháp nào không:
```bash
python output/python/code-injection-bench/fuzz_targets/<tên_file_harness>.py -runs=1
```
*   **Nếu thành công**: Chương trình chạy qua 1 lượt và thoát với mã lỗi `0`.
*   **Nếu thất bại**: Báo lỗi `ImportError` hoặc lỗi cú pháp (SyntaxError). Cần note lại lỗi này vào bảng đánh giá.

### 2. Chạy Fuzzing thực tế (Bug Verification)
Chạy fuzzer không giới hạn số lượt (hoặc giới hạn thời gian ví dụ 2-5 phút) để xem fuzzer có đột biến ra dữ liệu kích hoạt lỗi hay không:
```bash
python output/python/code-injection-bench/fuzz_targets/<tên_file_harness>.py
```
*   **Bắt được lỗi (SUCCESS)**: Fuzzer phát hiện ra dữ liệu độc hại chèn vào hàm, dừng chương trình đột ngột, in ra stack trace và thoát với mã lỗi `77` (hoặc raise ngoại lệ `RuntimeError: Command injection detected`).
*   **Không bắt được lỗi (FAILURE)**: Fuzzer chạy mãi mãi không tìm ra lỗi, hoặc bị lỗi crash hệ thống do cấu hình mock sai.

---

## 7. BƯỚC 6: Bảng Ghi Nhận Kết Quả (Evaluation Template)

Sau khi hoàn tất, hãy điền kết quả vào bảng dưới đây để tổng hợp báo cáo.

### A. Thông Tin Chung
*   **Người thực hiện**: `[Tên của bạn/Partner]`
*   **Ngày thực hiện**: `[YYYY-MM-DD]`
*   **Mô hình LLM sử dụng**: `[Ví dụ: qwen3-coder:480b-cloud]`
*   **Dự án kiểm thử**: `code-injection-bench`

---

### B. Nhật Ký Chạy Thử Nghiệm Chi Tiết
Điền thông tin cho từng file harness được sinh ra trong thư mục `fuzz_targets/`:

| Finding ID | CWE / Loại Lỗi | Chiến Lược Oracle | Biên Dịch OK? (Y/N) | Smoke Test (Pass/Fail) | Bắt Được Bug? (Y/N) | Thời Gian / Lượt Chạy Ra Bug | Chi Tiết Lỗi / Ghi Chú Nếu Thất Bại |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| `0` | CWE-94 (Code Injection) | `recorded_call` | Y | Pass | Y | 1.5s (500 runs) | None. Triggered oracle injection check. |
| `1` | CWE-78 (Cmd Injection) | `recorded_call` | Y | Pass | N | - | Chạy 5 phút không ra, do seed corpus thiếu gợi ý. |
| `2` | CWE-22 (Path Traversal) | `filesystem_state` | N | Fail | N | - | Bị lỗi ImportError đối với thư mục test target. |
| `[ID]` | `[CWE]` | `[Strategy]` | `[Y/N]` | `[Pass/Fail]` | `[Y/N]` | `[Thời gian]` | `[Mô tả lỗi import, lỗi mock, lặp vô tận...]` |

---

### C. Chỉ Số Đánh Giá Tổng Hợp
Sau khi điền xong bảng nhật ký, hãy tính toán các chỉ số sau:

1.  **Tổng số findings đem test**: `[Số lượng]`
2.  **Tỷ lệ sinh harness thành công (Compile Rate)**: `[Số lượng harness compile OK] / [Tổng số findings] * 100%`
3.  **Tỷ lệ xác minh bug thành công (Fuzzing Success Rate)**: `[Số lượng bắt được bug] / [Tổng số findings] * 100%`
4.  **Các nguyên nhân thất bại phổ biến (Failure Modes)**:
    *   *Lỗi import thư mục cục bộ*: `...%`
    *   *Mocking hàm không trúng*: `...%`
    *   *LLM sinh sai cú pháp python*: `...%`
    *   *Fuzzer không vượt qua cấu trúc tham số phức tạp*: `...%`
