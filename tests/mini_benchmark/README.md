# Oraculum Mini-Benchmark

Thư mục này chứa một bộ Benchmark nhỏ để phục vụ cho việc kiểm thử và tích hợp toàn bộ các Stage của Oraculum (từ Stage 0 đến Stage 3).

---

## 1. Cấu trúc thư mục
Môi trường giả lập VulnHunterX (VHX Workspace) nằm tại `tests/mini_benchmark/vhx_root`:
* `repos/python/mini-bench/target_app.py`: Mã nguồn Python chứa 3 hàm lỗi mục tiêu để fuzzing.
* `output/python/mini-bench/context/`: Các tệp bối cảnh (context) CSV (`functions.csv` chứa thông tin ánh xạ dòng code vào hàm).
* `output/python/mini-bench/verification_results/`: Tệp summary kết quả xác minh True Positive của VHX.

---

## 2. Hướng dẫn sử dụng cho nhà phát triển (Stage 2 & Stage 3)

Khi phát triển Stage 2 và Stage 3, các bạn có thể sử dụng bộ dữ liệu này để chạy thử và xác minh kết quả.

> [!IMPORTANT]
> Trước khi chạy các lệnh `oraculum`, hãy kích hoạt môi trường ảo (virtual environment):
> ```bash
> source .venv/bin/activate
> ```

> [!NOTE]
> Bộ benchmark này đã đi kèm với dữ liệu findings được ingest sẵn tại `tests/mini_benchmark/oraculum_output/`. Bạn có thể bỏ qua **Bước 0** và bắt đầu chạy trực tiếp từ **Bước 1** mà không cần phụ thuộc vào `vhx-root`.

### Bước 1: Classify (Phân loại Chiến lược)
Chạy lệnh sau để LLM phân loại chiến lược cho các finding:
```bash
oraculum classify \
  --repo mini-bench \
  --output-dir tests/mini_benchmark/oraculum_output \
  --log-file tests/mini_benchmark/classify_log.md \
  --force
```
* **Mục tiêu**: Phân loại thành công 3 finding tương ứng với 3 chiến lược chuẩn:
  1. `py_command_line_injection` $\rightarrow$ `recorded_call`
  2. `py_url_redirection` $\rightarrow$ `return_value`
  3. `py_path_injection` $\rightarrow$ `recorded_call`

---

### Không bắt buộc: Bước 0: Ingest (Nhập dữ liệu VHX)
Nếu muốn tự import lại dữ liệu từ VHX Workspace giả lập vào Oraculum (yêu cầu cài đặt/cấu hình `vhx-root`):
```bash
oraculum ingest \
  --vhx-root tests/mini_benchmark/vhx_root \
  --repo mini-bench \
  --output-dir tests/mini_benchmark/oraculum_output \
  --force
```
* **Mục tiêu**: Đọc finding gốc từ VHX và lưu cấu trúc enriched finding thành công tại:
  `tests/mini_benchmark/oraculum_output/python/mini-bench/verification_results/findings/`

---

### Bước 2: Oracle Research (Phát triển Stage 2)
Sau khi hoàn thiện code Stage 2, chạy lệnh sau:
```bash
oraculum oracle \
  --repo mini-bench \
  --output-dir tests/mini_benchmark/oraculum_output \
  --force
```
* **Nhiệm vụ của Stage 2**:
  * Đọc file classification JSON tương ứng tại thư mục `classifications/` của target.
  * Tải đúng system prompt đặc thù theo strategy được classify.
  * Trích xuất `strategy` và `mock_guidance` truyền làm gợi ý trong prompt để LLM sinh ra cấu trúc đặc tả Oracle spec JSON tại thư mục:
    `tests/mini_benchmark/oraculum_output/python/mini-bench/fuzz_oracles/`

---

### Bước 3: Harness Generation (Phát triển Stage 3)
Sau khi hoàn thiện code Stage 3, chạy lệnh sau:
```bash
oraculum harness \
  --repo mini-bench \
  --output-dir tests/mini_benchmark/oraculum_output \
  --force
```
* **Nhiệm vụ của Stage 3**:
  * Đọc đặc tả oracle từ thư mục `fuzz_oracles/`.
  * Áp dụng template Jinja2 tương ứng với chiến lược để sinh ra mã nguồn fuzzing harness hoàn chỉnh lưu tại:
    `tests/mini_benchmark/oraculum_output/python/mini-bench/fuzz_targets/`
  * Sinh các seed corpus thích hợp tại:
    `tests/mini_benchmark/oraculum_output/python/mini-bench/fuzz_corpus/`

---

### Bước 4: Chạy xác minh Fuzzer (Smoke test & Violation)
* **Smoke test**: Chạy harness với tham số `-runs=1` để kiểm tra lỗi cú pháp/import:
  ```bash
  python tests/mini_benchmark/oraculum_output/python/mini-bench/fuzz_targets/<target_harness>.py -runs=1
  ```
* **Bug verification**: Chạy fuzzer để kiểm tra xem nó có phát hiện ra lỗ hổng bảo mật và raise ngoại lệ mong muốn khi gặp seed độc hại hay không.
