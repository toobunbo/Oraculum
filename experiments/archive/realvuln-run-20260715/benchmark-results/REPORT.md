# Benchmark Report: OWASP Benchmark for Python (benchmark-python)

- **Date:** 2026-06-14
- **SAST Tool:** CodeQL
- **VHX Model:** `ollama_chat/qwen3-coder:480b-cloud`
- **Total Findings:** 33

> **Nguồn:** `Oraculum/benchmark-python/verification_results/findings/` (33 enriched findings, ingest từ `summary_benchmark-python_filtered_20260610_105228.json`).  
> **Ground truth:** `expectedresults-0.1.csv` (OWASP Benchmark for Python, 1230 rows: 452 TP / 778 FP).  
> **⚠️ Tính hợp lệ phép đo:** `summary.json` ghi `total_verdicts: 45, selected: 33, skipped: 12, verdict_filter: TP` → cả 33 đều verdict `True Positive` (TP), nên 'Accuracy' thực chất là **precision** của VHX; **không đo được recall/FN** (12 finding bị skip không có trên máy).

## Summary

| Metric | Value |
|--------|-------|
| Total Findings | 33 |
| Matched Ground Truth | 17 (Yes=13, Partial=4) |
| Mismatched (FN) | 0 |
| Mismatched (FP) | 16 |
| Accuracy (precision) | **51.5%** (17/33) |

*Verdict: TP ×33 (tất cả True Positive). Confidence: High ×26, Low ×6, Medium ×1. Ground-truth: 17 TP + 16 FP.  
`Partial` (verdict đúng hướng, confidence Low) tính vào Matched. 'Accuracy' = precision (dataset TP-only).*

> **Test case trùng:** `BenchmarkTest00460` flag 2 lần (xml-bomb + xxe) → 32 test case phân biệt / 33 findings. Theo test case: 16/32 = 50.0%.

## Detailed Results

| # | Rule ID | File | VHX Verdict | OWASP GT | Match? | Tại sao VHX sai |
|---|---|---|---|---|---|---|
| 1 | `py/code-injection` | `BenchmarkTest00073.py:54` | TP | FP | No | `đánh giá sai sanitizer là bypassable`: VHX thấy guard nhưng cho là bypassable ("craft input maintaining quote structure with malicious code"). Sai về ngữ nghĩa Python: `eval("'x'")` của plain string literal chỉ trả về chuỗi, không có context thực thi — không thể inject nếu không chèn được "'", mà guard `[1:-1]` chặn hết. |
| 2 | `py/code-injection` | `BenchmarkTest00156.py:44` | TP | FP | No | `dead-branch (điều kiện hằng số)`: VHX tính ĐÚNG điều kiện `7*42-86=208>200` luôn True (answers), nhưng tự mâu thuẫn: kết luận "the tainted value being used" trong khi nhánh True gán HẰNG SỐ `This_should_always_happen`; `param` nằm ở nhánh else (dead). VHX đọc sai nhánh nào chứa taint. |
| 3 | `py/code-injection` | `BenchmarkTest00158.py:56` | TP | FP | No | `đánh giá sai sanitizer là bypassable`: VHX đánh giá sai guard quote-literal là bypassable (giống 00073); thực tế plain string literal không có context thực thi. |
| 4 | `py/code-injection` | `BenchmarkTest00159.py:45` | TP | TP | Yes |  |
| 5 | `py/command-line-injection` | `BenchmarkTest00165.py:57` | TP | TP | Yes |  |
| 6 | `py/command-line-injection` | `BenchmarkTest00167.py:53` | TP | TP | Yes |  |
| 7 | `py/command-line-injection` | `BenchmarkTest00168.py:60` | TP | TP | Yes |  |
| 8 | `py/command-line-injection` | `BenchmarkTest00267.py:55` | TP | TP | Yes |  |
| 9 | `py/path-injection` | `BenchmarkTest00001.py:47` | TP | TP | Yes |  |
| 10 | `py/path-injection` | `BenchmarkTest00002.py:49` | TP | TP | Yes |  |
| 11 | `py/path-injection` | `BenchmarkTest00005.py:60` | TP (Low) | FP | No | `sink không nhìn thấy → nương CodeQL precision`: VHX KHÔNG nhìn thấy sink/guard (reasoning: "the sink code is not visible") nhưng vẫn chốt TP vì nương vào "CodeQL high precision". Đây là lỗi evidence-anchored: kết luận mà không thấy defense. (Bổ sung: guard `../`+unquote_plus cũng chặn URL-encoding — test `%2e%2f` decode thành `../` bị reject.) |
| 12 | `py/reflective-xss` | `BenchmarkTest00150.py:44` | TP | FP | No | `nhầm attack surface (header ≠ xss body)`: Reflective XSS yêu cầu payload reflection vào HTML body để browser render; custom response header không render → không XSS. VHX nhầm header-injection/response-splitting với reflective-xss. |
| 13 | `py/reflective-xss` | `BenchmarkTest00256.py:48` | TP | FP | No | `dead-branch (điều kiện hằng số)`: VHX cho taint tới header nhưng `param` ở nhánh dead; thực ra `bar` là hằng số. |
| 14 | `py/reflective-xss` | `BenchmarkTest00257.py:44` | TP (Low) | FP | No | `nhầm attack surface (header ≠ xss body)`: Taint tới header (slice có khôi phục param), nhưng header không phải reflective-xss body. VHX nhầm attack surface. |
| 15 | `py/reflective-xss` | `BenchmarkTest00591.py:48` | TP | FP | No | `nhầm attack surface (header ≠ xss body)`: Header ≠ HTML body → không reflective XSS. VHX nhầm surface. |
| 16 | `py/reflective-xss` | `BenchmarkTest01083.py:45` | TP | FP | No | `nhầm attack surface (header ≠ xss body)`: Header ≠ HTML body → không reflective XSS. VHX nhầm surface. |
| 17 | `py/unsafe-deserialization` | `BenchmarkTest00078.py:53` | TP (Low) | TP | Partial | đúng hướng (TP/TP), confidence Low → calibration, không sai hướng |
| 18 | `py/unsafe-deserialization` | `BenchmarkTest00164.py:47` | TP | TP | Yes |  |
| 19 | `py/unsafe-deserialization` | `BenchmarkTest00270.py:41` | TP | TP | Yes |  |
| 20 | `py/unsafe-deserialization` | `BenchmarkTest00507.py:55` | TP | TP | Yes |  |
| 21 | `py/url-redirection` | `BenchmarkTest00067.py:47` | TP (Low) | TP | Partial | đúng hướng (TP/TP), confidence Low → calibration, không sai hướng |
| 22 | `py/url-redirection` | `BenchmarkTest00068.py:49` | TP | TP | Yes |  |
| 23 | `py/url-redirection` | `BenchmarkTest00151.py:64` | TP | FP | No | `đọc sai logic boolean của guard`: VHX đọc sai logic boolean: cho rằng `or` phải là `and`. Nhưng `or` trong điều kiện REJECT là ĐÚNG (De Morgan: reject nếu một trong hai fail). Guard chỉ cho phép redirect tới google.com → safe. VHX nhầm reject-condition với allow-condition. |
| 24 | `py/url-redirection` | `BenchmarkTest00258.py:40` | TP (Low) | TP | Partial | đúng hướng (TP/TP), confidence Low → calibration, không sai hướng |
| 25 | `py/xml-bomb` | `BenchmarkTest00017.py:52` | TP | FP | No | `default-config safety (empirically refuted)`: VHX yêu cầu defusedxml/disable-entity, cho default SAX nguy hiểm ("No defenses against XML entity expansion"). Empirically: billion-laughs payload qua `xml.dom.minidom.parseString(bomb, xml.sax.make_parser())` parse trong 0.28s, ~43MB → KHÔNG DoS. Claim default-SAX-danger của VHX không có căn cứ ở Python/expat này. |
| 26 | `py/xml-bomb` | `BenchmarkTest00204.py:52` | TP | FP | No | `default-config safety (empirically refuted)`: Taint tới parser (bar=param), nhưng default SAX empirically không vulnerable billion-laughs (test: 0.28s/43MB). VHX yêu cầu hardening không cần thiết. |
| 27 | `py/xml-bomb` | `BenchmarkTest00459.py:51` | TP | FP | No | `taint bị cắt (off-by-one list index)`: VHX cho "user input flows into XML parser" nhưng `bar='moresafe'` do chọn `lst[1]` sai (off-by-one sau `pop(0)`); taint bị cắt, parser nhận hằng số. |
| 28 | `py/xml-bomb` | `BenchmarkTest00460.py:45` | TP | TP | Yes |  |
| 29 | `py/xml-bomb` | `BenchmarkTest00539.py:49` | TP | FP | No | `default-config safety (empirically refuted)`: Taint tới parser (qua slice), nhưng default SAX empirically không vulnerable billion-laughs (giống 00017/00204). |
| 30 | `py/xpath-injection` | `BenchmarkTest00021.py:58` | TP (Medium) | FP | No | `đánh giá sai sanitizer là bypassable`: Trong context attribute XPath trích dẫn đơn, block "'" là đủ chống breakout (giống SQL string-context). VHX cho "apostrophe check only" là insufficient — sai về context-adequacy của sanitizer. |
| 31 | `py/xxe` | `BenchmarkTest00460.py:45` | TP | TP | Yes |  |
| 32 | `py/xxe` | `BenchmarkTest00679.py:52` | TP | FP | No | `taint bị cắt (off-by-one list index)`: VHX ĐÚNG khi thấy `feature_external_ges=True` nguy hiểm, nhưng SAI khi cho `bar` là user-controlled. Thực ra `bar='moresafe'` (off-by-one sau `pop(0)`) → content parse là hằng số, không có input tấn công. |
| 33 | `py/xxe` | `BenchmarkTest00930.py:56` | TP (Low) | TP | Partial | đúng hướng (TP/TP), confidence Low → calibration, không sai hướng |

## Mismatch Analysis

| # | Rule ID | File | Error Type | Mode (cơ chế sai) | Guard thật trong source | Tại sao VHX xác nhận sai |
|---|---|---|---|---|---|---|
| 1 | `py/code-injection` | `BenchmarkTest00073.py:54` | FP | `đánh giá sai sanitizer là bypassable` | Guard ép `bar` là plain string literal (`startswith/endswith "'"` + không "'" ở giữa) ngay trước `eval(bar)`. | VHX thấy guard nhưng cho là bypassable ("craft input maintaining quote structure with malicious code"). Sai về ngữ nghĩa Python: `eval("'x'")` của plain string literal chỉ trả về chuỗi, không có context thực thi — không thể inject nếu không chèn được "'", mà guard `[1:-1]` chặn hết. |
| 2 | `py/code-injection` | `BenchmarkTest00156.py:44` | FP | `dead-branch (điều kiện hằng số)` | Điều kiện hằng số `if 7*42-86>200` (=208>200, luôn True) → `bar='This_should_always_happen'`; nhánh `bar=param` là dead code. | VHX tính ĐÚNG điều kiện `7*42-86=208>200` luôn True (answers), nhưng tự mâu thuẫn: kết luận "the tainted value being used" trong khi nhánh True gán HẰNG SỐ `This_should_always_happen`; `param` nằm ở nhánh else (dead). VHX đọc sai nhánh nào chứa taint. |
| 3 | `py/code-injection` | `BenchmarkTest00158.py:56` | FP | `đánh giá sai sanitizer là bypassable` | Cùng quote-literal guard như 00073 (kiểm tra trước `eval`). | VHX đánh giá sai guard quote-literal là bypassable (giống 00073); thực tế plain string literal không có context thực thi. |
| 4 | `py/path-injection` | `BenchmarkTest00005.py:60` | FP | `sink không nhìn thấy → nương CodeQL precision` | `if "../" in bar: reject` chạy sau `urllib.parse.unquote_plus()`; `bar` chỉ được concat vào path dưới TESTFILES_DIR. | VHX KHÔNG nhìn thấy sink/guard (reasoning: "the sink code is not visible") nhưng vẫn chốt TP vì nương vào "CodeQL high precision". Đây là lỗi evidence-anchored: kết luận mà không thấy defense. (Bổ sung: guard `../`+unquote_plus cũng chặn URL-encoding — test `%2e%2f` decode thành `../` bị reject.) |
| 5 | `py/reflective-xss` | `BenchmarkTest00150.py:44` | FP | `nhầm attack surface (header ≠ xss body)` | `bar` đi vào **HTTP response header** (custom header `yourBenchmarkTest00150`), không phải HTML body. | Reflective XSS yêu cầu payload reflection vào HTML body để browser render; custom response header không render → không XSS. VHX nhầm header-injection/response-splitting với reflective-xss. |
| 6 | `py/reflective-xss` | `BenchmarkTest00256.py:48` | FP | `dead-branch (điều kiện hằng số)` | Cùng dead-branch `if 7*42-86>200` luôn True → `bar=constant`. | VHX cho taint tới header nhưng `param` ở nhánh dead; thực ra `bar` là hằng số. |
| 7 | `py/reflective-xss` | `BenchmarkTest00257.py:44` | FP | `nhầm attack surface (header ≠ xss body)` | Slice `superstring[5:-5]` khôi phục lại `param`, nhưng `bar` đi vào response **HEADER**. | Taint tới header (slice có khôi phục param), nhưng header không phải reflective-xss body. VHX nhầm attack surface. |
| 8 | `py/reflective-xss` | `BenchmarkTest00591.py:48` | FP | `nhầm attack surface (header ≠ xss body)` | `bar=param` (qua map dict) đi vào response **HEADER**. | Header ≠ HTML body → không reflective XSS. VHX nhầm surface. |
| 9 | `py/reflective-xss` | `BenchmarkTest01083.py:45` | FP | `nhầm attack surface (header ≠ xss body)` | `bar=param.split(" ")[0]` đi vào response **HEADER**. | Header ≠ HTML body → không reflective XSS. VHX nhầm surface. |
| 10 | `py/url-redirection` | `BenchmarkTest00151.py:64` | FP | `đọc sai logic boolean của guard` | Guard `if url.netloc not in [google.com] OR url.scheme != "https": reject` — chỉ cho redirect tới `https://google.com`. | VHX đọc sai logic boolean: cho rằng `or` phải là `and`. Nhưng `or` trong điều kiện REJECT là ĐÚNG (De Morgan: reject nếu một trong hai fail). Guard chỉ cho phép redirect tới google.com → safe. VHX nhầm reject-condition với allow-condition. |
| 11 | `py/xml-bomb` | `BenchmarkTest00017.py:52` | FP | `default-config safety (empirically refuted)` | SAX parser `xml.sax.make_parser()` kèm comment "all features are disabled by default". | VHX yêu cầu defusedxml/disable-entity, cho default SAX nguy hiểm ("No defenses against XML entity expansion"). Empirically: billion-laughs payload qua `xml.dom.minidom.parseString(bomb, xml.sax.make_parser())` parse trong 0.28s, ~43MB → KHÔNG DoS. Claim default-SAX-danger của VHX không có căn cứ ở Python/expat này. |
| 12 | `py/xml-bomb` | `BenchmarkTest00204.py:52` | FP | `default-config safety (empirically refuted)` | Default SAX parser (`bar=param` tới parser). | Taint tới parser (bar=param), nhưng default SAX empirically không vulnerable billion-laughs (test: 0.28s/43MB). VHX yêu cầu hardening không cần thiết. |
| 13 | `py/xml-bomb` | `BenchmarkTest00459.py:51` | FP | `taint bị cắt (off-by-one list index)` | `lst=['safe',param,'moresafe']; lst.pop(0); bar=lst[1]='moresafe'` — HẰNG SỐ. | VHX cho "user input flows into XML parser" nhưng `bar='moresafe'` do chọn `lst[1]` sai (off-by-one sau `pop(0)`); taint bị cắt, parser nhận hằng số. |
| 14 | `py/xml-bomb` | `BenchmarkTest00539.py:49` | FP | `default-config safety (empirically refuted)` | Default SAX parser (`bar=param` qua string slice tới parser). | Taint tới parser (qua slice), nhưng default SAX empirically không vulnerable billion-laughs (giống 00017/00204). |
| 15 | `py/xpath-injection` | `BenchmarkTest00021.py:58` | FP | `đánh giá sai sanitizer là bypassable` | Guard `if "'" in bar: reject` — block mọi single-quote trước khi nhúng vào XPath `...[@emplid='{bar}']`. | Trong context attribute XPath trích dẫn đơn, block "'" là đủ chống breakout (giống SQL string-context). VHX cho "apostrophe check only" là insufficient — sai về context-adequacy của sanitizer. |
| 16 | `py/xxe` | `BenchmarkTest00679.py:52` | FP | `taint bị cắt (off-by-one list index)` | `lst=['safe',param,'moresafe']; lst.pop(0); bar=lst[1]='moresafe'` — HẰNG SỐ, dù `feature_external_ges=True`. | VHX ĐÚNG khi thấy `feature_external_ges=True` nguy hiểm, nhưng SAI khi cho `bar` là user-controlled. Thực ra `bar='moresafe'` (off-by-one sau `pop(0)`) → content parse là hằng số, không có input tấn công. |

*FN = VHX bỏ sót, FP = VHX báo sai.*

## Taxonomy — 7 cơ chế VHX xác nhận sai (16 FP)

- **đánh giá sai sanitizer là bypassable** (3): BenchmarkTest00073, BenchmarkTest00158, BenchmarkTest00021 — VHX thấy sanitizer/validation nhưng đánh giá là bypassable, trong khi nó adequate cho context cụ thể (string-literal, quote-context, sau-decode).
- **nhầm attack surface (header ≠ xss body)** (4): BenchmarkTest00150, BenchmarkTest00257, BenchmarkTest00591, BenchmarkTest01083 — VHX nhầm attack surface: input vào HTTP response **header** bị flag là reflective-xss, nhưng XSS cần reflection vào HTML **body**.
- **dead-branch (điều kiện hằng số)** (2): BenchmarkTest00156, BenchmarkTest00256 — VHX không phân tích điều kiện hằng số thời gian compile → cho taint tới sink qua nhánh dead code không bao giờ chạy.
- **taint bị cắt (off-by-one list index)** (2): BenchmarkTest00459, BenchmarkTest00679 — VHX theo dõi taint sai do off-by-one list index sau `pop(0)` → tưởng input tới sink nhưng thực ra sink nhận hằng số.
- **đọc sai logic boolean của guard** (1): BenchmarkTest00151 — VHX đọc sai logic boolean của guard (nhầm reject-condition với allow-condition).
- **sink không nhìn thấy → nương CodeQL precision** (1): BenchmarkTest00005 — VHX không thấy sink/guard nhưng vẫn chốt TP dựa trên "CodeQL high precision".
- **default-config safety (empirically refuted)** (3): BenchmarkTest00017, BenchmarkTest00204, BenchmarkTest00539 — VHX yêu cầu hardening (defusedxml/entity limits) nhưng billion-laughs test chứng minh default SAX không DoS ở Python/expat này.

## Đọc hiểu kết quả

- **Precision 17/33=51.5%**: VHX chốt True Positive cả 33, OWASP chỉ công nhận 17. **16 FP** chia thành 7 cơ chế (xem taxonomy) — nhiều nhất là **nhầm surface header/xss** (4); các nhóm còn lại từ 1–3 case.
- **Không đo recall** (12 skip không có trên máy); FN=0 là hệ quả filter TP, không phải kết luận VHX không bỏ sót.
- **Insight cho Oraculum:** các cơ chế `dead-branch` và `taint-killed-index` (4 case) là lỗi reasoning mà một oracle runtime (chạy harness thật) sẽ **bắt được ngay** — payload không bao giờ tới sink → oracle không trigger. Đây là động lực cho hướng fuzz-confirm của Oraculum: xác nhận động vượt phán xét tĩnh của LLM.

## Verification

- 33 finding, model đồng nhất `qwen3-coder:480b-cloud`, verdict 33/33 True Positive (khớp `verdict_filter: TP`).
- Join `expectedresults-0.1.csv` theo `BenchmarkTest\d{5}`: 33/33 khớp, 0 unmatched.
- **Category cross-validation** xác nhận join đúng: mỗi `rule_id` ↔ đúng 1 OWASP `category` ngữ nghĩa (py/code-injection↔codeinj, py/xxe↔xxe, ...); `basename==test name` 0 mismatch → `benchmark-python` = OWASP Benchmark for Python.
- Số học: Yes(13)+Partial(4)+FP(16)=33. GT split 17 TP/16 FP. Precision 17/33=51.5% (finding) / 16/32=50.0% (test case phân biệt).
- **Root cause của 16 FP được rút từ source code thật** tại `~/VulnHunterX/repos/python/Benchmark/testcode/` (đọc guard từng case), không suy đoán.
