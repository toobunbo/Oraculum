# Vấn đề Import các Route lồng (Nested Routes) trong OWASP Python Benchmark

Tài liệu này ghi nhận lại vấn đề lỗi `ImportError` xảy ra khi chạy benchmark trên dataset **`benchmark-python`** (OWASP Python Benchmark) và giải pháp khắc phục đề xuất.

---

## 1. Mô tả lỗi (Problem Statement)

Khi chạy benchmark trên các harness sinh ra cho `benchmark-python`, fuzzer lập tức gặp lỗi:
```
ImportError: cannot import name 'BenchmarkTestXXXXX_post' from 'testcode.BenchmarkTestXXXXX'
```

### Nguyên nhân:
Trong cấu trúc của OWASP Python Benchmark, tất cả các hàm view/route phục vụ Flask đều được định nghĩa **lồng bên trong** hàm khởi tạo `init(app)` ở cấp độ module:
```python
def init(app):
    @app.route('/benchmark/codeinj-00/BenchmarkTest00073', methods=['POST'])
    def BenchmarkTest00073_post():
        # Logic xử lý của view
        ...
```
Trong ngôn ngữ Python, các hàm được định nghĩa bên trong một hàm khác (nested function) chỉ tồn tại trong phạm vi cục bộ (local scope) của hàm cha khi hàm cha đang thực thi. Cú pháp `import` của Python không thể truy cập trực tiếp các hàm này từ bên ngoài module.

---

## 2. Giải pháp khắc phục đề xuất (Proposed Solution)

Thay vì import trực tiếp, chúng ta có thể tận dụng cơ chế đăng ký route của Flask bằng cách tạo một **Mock Flask App** giả lập, truyền nó vào hàm `init` để thu thập các view function.

### Cách thức hoạt động:
1. Tạo một đối tượng Mock thay thế cho `app` của Flask.
2. Thiết lập thuộc tính `route` của mock app là một decorator thu thập hàm (decorator collector).
3. Gọi hàm `init(mock_app)` để chạy qua các decorator đăng ký route.
4. Lấy hàm view đã đăng ký ra từ bộ nhớ tạm để fuzzing.

### Mã nguồn kiểm thử thành công:
```python
from unittest.mock import MagicMock
import testcode.BenchmarkTest00073 as target_module

# 1. Khởi tạo bộ thu thập hàm view
_registered_funcs = {}
_mock_app = MagicMock()

# 2. Định nghĩa decorator giả lập thu thập hàm khi app.route() được gọi
_mock_app.route = lambda rule, **opts: lambda f: _registered_funcs.setdefault(f.__name__, f) or f

# 3. Kích hoạt đăng ký
target_module.init(_mock_app)

# 4. Trích xuất hàm mong muốn thành công
BenchmarkTest00073_post = _registered_funcs.get("BenchmarkTest00073_post")
```

---

## 3. Kế hoạch triển khai (Next Steps)

Cần nâng cấp Stage 3 (Harness Generation) của Oraculum để tự động phát hiện các view function lồng và sinh ra cấu trúc trích xuất động thay vì sinh câu lệnh `import` tĩnh.

### Đoạn mã import tĩnh hiện tại (Lỗi):
```python
from testcode.BenchmarkTest00073 import BenchmarkTest00073_post
```

### Đoạn mã đề xuất thay thế trong Template Harness:
```python
from unittest.mock import MagicMock
import testcode.BenchmarkTest00073 as target_module

_registered_funcs = {}
_mock_app = MagicMock()
_mock_app.route = lambda rule, **opts: lambda f: _registered_funcs.setdefault(f.__name__, f) or f
target_module.init(_mock_app)

BenchmarkTest00073_post = _registered_funcs.get("BenchmarkTest00073_post")
if not BenchmarkTest00073_post:
    raise ImportError("Không thể trích xuất hàm BenchmarkTest00073_post bằng Mock App")
```
