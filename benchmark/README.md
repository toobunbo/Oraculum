# Hướng dẫn chạy và đánh giá Benchmark & Metrics cho Oraculum

Thư mục này chứa toàn bộ tài nguyên, kịch bản (scripts) và bài kiểm thử để chạy benchmark và đo lường các chỉ số hiệu năng, bảo mật của các Atheris fuzz-harness sinh ra từ Oraculum.

---

## 1. Cấu trúc thư mục

```
benchmark/
├── benchmark-python/      # Bản sao lưu dataset OWASP Python Benchmark (33 targets)
├── mini_benchmark/       # Target project nhỏ chứa 3 hàm lỗi để smoke test cục bộ
├── run_benchmark.py      # Script chính chạy benchmark và đo lường chỉ số
├── test_benchmark.py     # Bộ unit tests tự động cho run_benchmark.py
└── README.md             # Tài liệu hướng dẫn này
```

---

## 2. Các chỉ số đo lường (Core Metrics)

Hệ thống đánh giá Oraculum dựa trên 3 chỉ số cốt lõi sau:

1. **Validity Rate (Tỷ lệ biên dịch thành công)**:
   * **Mục tiêu**: Đo lường khả năng sinh mã Python chuẩn cú pháp của LLM.
   * **Cách đo**: Sử dụng module `py_compile` để biên dịch thử các harness.

2. **Recall Rate (Tỷ lệ phát hiện lỗi)**:
   * **Mục tiêu**: Đo lường xem Oracle check chèn vào harness có bắt đúng lỗi khi lỗ hổng bị kích hoạt hay không.
   * **Cách đo**: Chạy fuzzer kèm theo seed corpus chứa payload độc hại (trong tối đa 10 giây). Nếu fuzzer crash và quăng đúng exception `ORACULUM_VIOLATION` (hoặc RuntimeError tương ứng), lượt test được tính là thành công (Recall = 1).

3. **Fuzzing Overhead (Độ trễ do Oracle check)**:
   * **Mục tiêu**: Đo lường xem các check của Oracle (như mock hàm, snapshot filesystem) có làm chậm tốc độ fuzzing của Atheris nhiều không.
   * **Cách đo**:
     * Script tự động tạo ra một bản sao tạm của harness và loại bỏ phần Oracle check (thay bằng `pass`), đồng thời làm rỗng seed corpus để chạy fuzz ngẫu nhiên không bị crash.
     * Chạy cả harness gốc (có check) và harness tạm (không check) trong vòng 20,000 lần chạy ngẫu nhiên để so sánh thông lượng thực thi (executions/sec).
     * Công thức: $Overhead = \frac{t_{\text{with\_oracle}} - t_{\text{no\_oracle}}}{t_{\text{no\_oracle}}} \times 100\%$
     * Mục tiêu: Đảm bảo độ trễ $< 15\%$.

---

## 3. Cách chạy Benchmark (Usage)

Trước khi chạy, hãy đảm bảo bạn đã kích hoạt virtual environment của dự án.

### Chạy benchmark mặc định trên OWASP Python Benchmark
Mặc định script sẽ chạy trên toàn bộ 33 target của dataset `benchmark-python` bằng các harness đã sinh sẵn:
```bash
.venv/bin/python benchmark/run_benchmark.py
```

### Chạy benchmark nhanh trên tập dữ liệu nhỏ `mini-bench`
Để test thử nhanh các tính năng hoặc khôi phục dữ liệu cục bộ:
```bash
.venv/bin/python benchmark/run_benchmark.py \
  --repo mini-bench \
  --output-dir benchmark/mini_benchmark/oraculum_output \
  --runs 5000
```

### Chạy lại toàn bộ Pipeline trước khi đo
Nếu bạn muốn chạy lại các Stage (ingest -> classify -> oracle -> harness) trước khi benchmark để cập nhật mã nguồn sinh ra mới nhất:
```bash
.venv/bin/python benchmark/run_benchmark.py --run-pipeline --force
```

### Các tùy chọn dòng lệnh chính (CLI Arguments)
* `--repo`: Tên thư mục dataset cần chạy (mặc định: `benchmark-python`).
* `--output-dir`: Thư mục chứa kết quả Oraculum (mặc định: `output`).
* `--run-pipeline`: Chạy lại toàn bộ pipeline Oraculum trước khi benchmark.
* `--runs`: Số lượt chạy fuzzing ngẫu nhiên để đo đạc Overhead (mặc định: `20000`).
* `--timeout`: Thời gian tối đa (giây) chờ fuzzer crash kích hoạt lỗi Recall (mặc định: `10.0`).

---

## 4. Kết quả đầu ra (Outputs)

Sau khi chạy xong, script sẽ xuất ra 2 tệp tin báo cáo ở thư mục gốc của dự án:
1. **`benchmark_report.md`**: Báo cáo dạng Markdown hiển thị bảng tổng kết (Executive Summary) và bảng chi tiết từng Target ID bao gồm Trạng thái biên dịch, Trạng thái Recall, Thông lượng và Overhead.
2. **`benchmark_report.csv`**: Báo cáo thô dạng CSV hiển thị đầy đủ thông số chạy để dễ dàng nạp vào Excel hay các công cụ phân tích khác.

---

## 5. Chạy các bài kiểm thử tự động (Unit Tests)

Bộ unit tests đi kèm tự động kiểm tra tính chính xác của script benchmark. Để chạy toàn bộ testcases của dự án (bao gồm cả test của benchmark runner):
```bash
.venv/bin/pytest
```
Để chỉ chạy riêng các test của benchmark runner:
```bash
.venv/bin/pytest benchmark/test_benchmark.py
```
