# Oraculum: Kế hoạch hoàn thiện Stages & Xây dựng Benchmark kiểm thử

Tài liệu này xác nhận hiện trạng dự án trên nhánh `main`, giải thích chi tiết hoạt động của Stage 1, và cung cấp checklist chi tiết để hoàn thiện các Stage còn lại (Stage 2 & Stage 3) cùng kế hoạch thiết lập một Benchmark kiểm thử và đo lường hiệu năng.

---

## 1. Hiện trạng trên nhánh `main`

* **Stage 0 (Ingest)**: Đã hoàn thành, chuyển đổi kết quả verify từ VulnHunterX (VHX) thành *enriched findings*.
* **Stage 1 (Classification)**: Đã hoàn thành, phân loại các findings thành đúng 3 chiến lược chuẩn: `recorded_call`, `return_value`, và `filesystem_state`.

### 🔍 Cách hoạt động của Stage 1 (Classification)
Để đưa ra quyết định chọn chiến lược (Strategy) và xây dựng hướng dẫn giả lập (`mock_guidance`), Stage 1 sử dụng LLM với các thông tin sau:
1. **Dữ liệu đầu vào (Input Evidence)**:
   * `rule_id` & `rule_slug`: Định danh lỗ hổng bảo mật (ví dụ: `py/sql-injection`).
   * `data_flow`: Luồng truyền dữ liệu từ nguồn (source) $\rightarrow$ các bước trung gian $\rightarrow$ hàm đích (sink).
   * `answers`: Các câu trả lời xác nhận từ VulnHunterX (ví dụ: tham số có bị nhiễm độc không, có hàm dọn dẹp dữ liệu/sanitize không).
   * `reasoning`: Phần phân tích/suy luận chi tiết của VulnHunterX giải thích tại sao đây là một lỗ hổng thực tế.
   * `returns`: Tín hiệu phân tích tĩnh về kiểu dữ liệu trả về của hàm (có trả về giá trị hay không, kiểu gì).
2. **Quy trình suy luận của LLM (Decision Tree)**:
   LLM sẽ trả lời tuần tự 3 câu hỏi logic sau:
   * **Q1. Chạy hàm sink nguy hiểm có rủi ro không?** (Gửi request mạng, chạy lệnh shell, ghi database...).
     * Nếu **Có (YES)** $\rightarrow$ Bắt buộc chọn `recorded_call` để mock sink (đảm bảo an toàn).
     * Nếu **Không (NO)** $\rightarrow$ Đi tiếp tới Q2.
   * **Q2. Hành vi vi phạm có thể quan sát được sau khi hàm kết thúc không?**
     * Nếu **Không (NO)** $\rightarrow$ Chọn `recorded_call` (mock để hứng tham số sink).
     * Nếu **Có (YES)** $\rightarrow$ Đi tiếp tới Q3.
   * **Q3. Kết quả vi phạm có nằm trên bộ nhớ lúc return không?**
     * Nếu **Có (YES)** $\rightarrow$ Chọn `return_value`.
     * Nếu **Không (NO)** $\rightarrow$ Chọn `filesystem_state` (vi phạm ghi ra ổ đĩa).
3. **Cách xây dựng `mock_guidance`**:
   * Chỉ dựng cho chiến lược `recorded_call`.
   * LLM tự động suy luận: Hàm nào cần mock, tham số nào chứa payload cần capture, và mock đó cần trả về giá trị giả gì để hàm mục tiêu chạy tiếp bình thường.

---

## 2. Checklist hoàn thiện các Stages còn lại

Chúng ta sẽ thống nhất sử dụng duy nhất 3 tên chiến lược: **`recorded_call`**, **`return_value`**, và **`filesystem_state`** xuyên suốt toàn bộ codebase (không dùng tên cũ `patch_call` hay `inspect_return` nữa).

### ☑️ Giai đoạn 1: Chuẩn hóa tên Chiến lược (Strategy Naming Cleanup)
* [x] Xóa bỏ toàn bộ tên cũ (`patch_call`, `inspect_return`, `catch_exception`) trong:
  * Validator của oracle và harness.
  * Các prompt cũ trong `config/prompts/`.
  * Các cấu trúc xử lý kết quả ở tầng runner.

### ☑️ Giai đoạn 2: Tích hợp đầu ra Stage 1 vào Stage 2 (Oracle Research)
* [x] Cập nhật Stage 2 runner ([oracle/runner.py](file:///home/tuonglnc/repo/Oraculum/src/oraculum/oracle/runner.py)):
  * Đọc file classification JSON tương ứng từ thư mục classifications (`output/python/<repo>/classifications/<target_id>.json`) dựa theo `target_id`.
  * Trích xuất trực tiếp `strategy` và `mock_guidance` từ file JSON đó để làm đầu vào cho LLM ở Stage 2.
* [x] Xây dựng cơ chế điều hướng Prompt (Prompt Routing) dựa trên 3 chiến lược:
  * Tải prompt hệ thống tương ứng cho mỗi chiến lược:
    * [oracle_system_recorded_call.txt](file:///home/tuonglnc/repo/Oraculum/config/prompts/oracle_system_recorded_call.txt)
    * [oracle_system_return_value.txt](file:///home/tuonglnc/repo/Oraculum/config/prompts/oracle_system_return_value.txt)
    * [oracle_system_filesystem_state.txt](file:///home/tuonglnc/repo/Oraculum/config/prompts/oracle_system_filesystem_state.txt)
* [x] Tích hợp `mock_guidance` vào User Prompt của LLM khi strategy là `recorded_call` để hướng dẫn LLM sinh spec mock chuẩn xác.
* [x] Viết unit tests kiểm tra tích hợp và prompt routing tại `tests/test_oracle.py`.

### ☑️ Giai đoạn 3: Tối ưu & Dọn dẹp Template sinh Harness (Stage 3)
* [x] Cải tạo và dọn dẹp file template [base_harness.j2](file:///home/tuonglnc/repo/Oraculum/src/oraculum/harness/templates/base_harness.j2):
  * Cấu trúc lại file rõ ràng thành 3 block độc lập tương ứng với 3 chiến lược mới:
    * **`recorded_call` Block**: Dựng mock bằng `unittest.mock.patch`, hứng tham số kiểm tra regex, trả về giá trị giả lập.
    * **`return_value` Block**: Gọi trực tiếp, kiểm tra giá trị trả về của hàm bằng regex.
    * **`filesystem_state` Block**: Thêm setup snapshot thư mục trước khi fuzz, gọi hàm, quét diff thư mục phát hiện file lạ, và bắt buộc cleanup thư mục tạm trong khối `finally`.
  * Loại bỏ các comment rác, tối ưu cách phân chia dữ liệu fuzz (`FuzzedDataProvider`) khi target function có nhiều tham số.
  * Tối ưu hóa khối `try/except`: Không swallow các ngoại lệ liên quan tới Oracle (ví dụ `RuntimeError`), đảm bảo fuzzer crash đúng lúc phát hiện bug.
* [x] Viết prompt sinh harness tương ứng cho 3 chiến lược mới:
  * `harness_system_recorded_call.txt`
  * `harness_system_return_value.txt`
  * `harness_system_filesystem_state.txt`
* [x] Cập nhật Stage 3 runner ([harness/runner.py](file:///home/tuonglnc/repo/Oraculum/src/oraculum/harness/runner.py)) để nạp đúng prompt sinh harness dựa theo strategy có trong oracle spec.

### ⬜ Giai đoạn 4: Viết End-to-End Pipeline Test
* [ ] Tạo file `tests/test_pipeline.py` chạy tuần tự:
  `ingest` $\rightarrow$ `classify` $\rightarrow$ `oracle` $\rightarrow$ `harness` trên dữ liệu giả lập (mocked LLM responses) để bảo vệ toàn vẹn luồng dữ liệu.

---

## 3. Kế hoạch xây dựng Benchmark kiểm thử nhỏ (Mini-Benchmark)

Để chứng minh Oraculum hoạt động ổn định và sinh ra được harness có khả năng phát hiện lỗi thực tế, chúng ta sẽ xây dựng một dự án test nhỏ độc lập.

### Bước 1: Tạo dự án mục tiêu (Target Project)
Tạo một thư mục test tại `tests/mini_benchmark/` chứa code Python có lỗ hổng bảo mật thật:
1. **Hàm `run_shell(cmd_input)`** (Lỗi Command Injection $\rightarrow$ Test `recorded_call`):
   * Nhận đầu vào, thực hiện gọi trực tiếp `subprocess.run(cmd_input, shell=True)`.
2. **Hàm `get_safe_url(user_url)`** (Lỗi Open Redirect $\rightarrow$ Test `return_value`):
   * Nhận URL người dùng, kiểm tra lỏng lẻo và trả về URL đó để redirect.
3. **Hàm `write_log(filename, content)`** (Lỗi Path Traversal $\rightarrow$ Test `filesystem_state`):
   * Nhận tên file ghi log từ người dùng, thực hiện mở file ghi log mà không validate đường dẫn (cho phép ghi file ra ngoài thư mục log chỉ định).

### Bước 2: Giả lập Đầu ra của VulnHunterX (Mock VHX Results)
Tạo file JSON giả lập kết quả verify của VHX cho 3 lỗ hổng trên (chứa `data_flow` cụ thể, `rule_id`, vị trí file và dòng code bị lỗi).

### Bước 3: Chạy thử nghiệm toàn bộ Pipeline
Chạy các dòng lệnh tuần tự để tạo mã nguồn fuzzer:
```bash
# 1. Ingest kết quả VHX giả lập
oraculum ingest --repo mini-bench --summary tests/mini_benchmark/vhx_summary.json

# 2. Phân loại chiến lược
oraculum classify --repo mini-bench

# 3. Sinh đặc tả Oracle
oraculum oracle --repo mini-bench

# 4. Sinh Atheris harness fuzzer
oraculum harness --repo mini-bench
```

### Bước 4: Chạy thử nghiệm và Chứng minh Hoạt động (Verification)
1. **Kiểm tra tính đúng đắn của mã nguồn sinh ra (Smoke Test)**:
   * Chạy harness với tham số `-runs=1` để chứng minh Atheris khởi tạo thành công, không gặp lỗi cú pháp hay import.
2. **Chứng minh Fuzzer phát hiện được Bug (Crash / Oracle Violation)**:
   * Chạy fuzzer với payload độc hại nằm trong thư mục Seed Corpus được tự động tạo ra.
   * Kết quả mong muốn: Fuzzer phải dừng lại ngay lập tức và raise đúng ngoại lệ cấu hình (ví dụ: `RuntimeError: COMMAND_INJECTION` hoặc `RuntimeError: PATH_TRAVERSAL`), chứng minh Oracle hoạt động chính xác.

---

## 4. Kế hoạch Nâng cấp Benchmark & Hệ thống Chỉ số đo lường (Tương lai)

Khi dự án Oraculum đã ổn định, chúng ta sẽ mở rộng quy mô kiểm thử bằng cách nâng cấp từ Mini-Benchmark lên các Dataset chuẩn công nghiệp và xây dựng bộ chỉ số đo lường hiệu năng (Metrics).

### ⬜ Mở rộng Dataset kiểm thử (OWASP Benchmark Python)
* [ ] **Tích hợp OWASP Benchmark cho Python**:
  * OWASP Benchmark là bộ test-suite chuẩn chứa hàng nghìn trường hợp kiểm thử lỗ hổng bảo mật thực tế lẫn nhân tạo (SQLi, Path Traversal, Command Injection, XSS...).
  * Tải và thiết lập OWASP Python Benchmark làm repository mục tiêu đầu vào cho VulnHunterX $\rightarrow$ Oraculum.
* [ ] **Phân nhóm TestCase theo Strategy**:
  * Ánh xạ các CWE trong OWASP Benchmark vào 3 Strategy tương ứng của Oraculum để kiểm tra khả năng phủ (Coverage).

### ⬜ Xây dựng Bộ chỉ số Đo lường (Evaluation Metrics)
Chúng ta sẽ viết script tự động thu thập và xuất báo cáo hiệu năng dựa trên 3 nhóm chỉ số sau:

1. **Syntax & Compilation Validity Rate (Tỷ lệ biên dịch thành công)**:
   * Công thức: $Validity = \frac{\text{Số harness compile thành công (py\_compile)}}{\text{Tổng số harness sinh ra}} \times 100\%$
   * Đo lường khả năng sinh mã Python chuẩn của LLM.
2. **Detection Rate / Recall (Tỷ lệ phát hiện lỗi)**:
   * Công thức: $Recall = \frac{\text{Số lỗ hổng True Positive gây crash/oracle violation}}{\text{Tổng số lỗ hổng True Positive thực tế}} \times 100\%$
   * Đo lường khả năng phát hiện lỗi bảo mật của các custom oracle được chèn vào.
3. **Fuzzing Overhead (Độ trễ do Oracle chèn vào)**:
   * Đo lường thông lượng fuzzing (executions per second) của:
     * Harness thông thường (không chèn check).
     * Harness chèn Oracle (đặc biệt là nhóm `filesystem_state` và `recorded_call` vì có I/O hoặc mock overhead).
   * Mục tiêu: Đảm bảo Oracle Overhead $< 15\%$ để không làm giảm hiệu suất của Atheris.

### ⬜ Script tự động hóa báo cáo (Benchmark Runner & Reporter)
* [ ] Viết tệp script `scripts/run_benchmark.py` thực hiện:
  1. Chạy tự động pipeline Oraculum trên toàn bộ dataset OWASP.
  2. Khởi chạy Atheris với thời gian giới hạn (ví dụ: 30 giây mỗi target).
  3. Thu thập logs: Target nào compile fail, target nào tìm thấy bug, tốc độ fuzzing trung bình.
  4. Xuất ra tệp báo cáo dạng Markdown/CSV hiển thị bảng so sánh chi tiết.
