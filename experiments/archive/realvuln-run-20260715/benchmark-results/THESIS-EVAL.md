# Oraculum — Đánh giá Fuzz-Confirmation (tóm tắt cho báo cáo)

**Câu hỏi:** Harness + oracle Oraculum tự sinh có phát hiện được bug thật ở runtime không?

**Dataset:** 33 lỗ hổng OWASP Benchmark for Python do VulnHunterX xác nhận — gồm **17 bug thật + 16 báo-sai** (theo nhãn gốc OWASP).

**Kết quả chính:** Oraculum bắt đúng **14/17 bug thật**, chỉ báo sai **3/16**.

---

## Số liệu định lượng

| Chỉ số | Giá trị | Ý nghĩa định tính |
|---|---|---|
| **Recall** | 14/17 = **82.4%** | tỉ lệ bug thật bị phát hiện |
| **Precision** | 14/(14+3) = **82.4%** | trong các báo bug, tỉ lệ đúng |
| **F1** | **82.4%** | tổng hợp (cân bằng) |
| Bug thật bỏ sót | **3** | 00159, 00270, 00930 |
| Báo sai | **3** | (xem phân tích FP bên dưới) |

> Đo lặp 3 lần, kết quả đồng nhất (±0). Chỉ tính "phát hiện của oracle" (RuntimeError `ORACULUM_VIOLATION`); các crash do code test tự văng (8) tính riêng, không gộp.

## So sánh với fuzzing thường (ablation)

Cùng harness, chỉ bật/tắt oracle:

| Cấu hình | Bug thật bắt | Báo sai |
|---|---|---|
| Atheris thường (chỉ bắt crash) | 9/17 (53%) | 7 |
| **Oraculum (có oracle)** | **14/17 (82%)** | **3** |

→ Oracle Oraculum **bắt thêm 5 bug thật** (recall 53%→82%) **và giảm báo sai** (7→3). Đây là đóng góp đo được, cô lập.

## Thiết lập (ai cũng tái lập được)

- **Mô hình LLM:** qwen3-coder (Ollama Cloud).
- **Harness:** 33/33 sinh thành công + biên dịch OK (Flask `init(app)` framework-support deterministic).
- **Fuzz:** 10 000 input mỗi lần × lặp 3 lần. Corpus chỉ chứa seed, làm mới mỗi lần (kiểm soát biến, không nhiễm chéo).
- **Cách đo:** đếm oracle-violation; crash do handler (không phải oracle) để riêng.

## Hạn chế (phải công khai)

1. **Chưa test trên tập mới** *(quan trọng nhất)*: các chữ ký/seed exploit được thiết kế trên đúng 33 lỗ hổng này → 82% là số trên **tập đã biết**, chưa chứng minh tổng quát. Cần chạy trên tập khác (gradio/requests/pyyaml) để khẳng định.
2. **Mẫu nhỏ**: 33 lỗ hổng, 1 benchmark, 1 mô hình → không ý nghĩa thống kê mạnh.
3. **3 bug thật bỏ sót**: logic oracle đúng (verify riêng) nhưng fuzzer chưa sinh được input tới đúng sink trong budget (~thiếu budget hoặc input cần encoding đặc biệt).
4. **Ground-truth**: một số "báo sai" thực ra là ranh giới định nghĩa bug (vd `eval` chạy-vs-trả-chuỗi), không hẳn lỗi oracle.

## Kết luận 1 dòng

Oraculum fuzz-confirmation **chạy được end-to-end** (0→33/33 harness), phát hiện **82% bug thật** và **hơn fuzzing thường 29 điểm recall** — nhưng kết quả này trên tập phát triển, cần tập hold-out để khẳng định tổng quát.
