# Oraculum: Bug Oracle Framework — harness generation agent  

**Document type:** Architecture reference  
**Scope:** Bug Oracle Framework — harness generation agent  
**Status:** Draft for team review

## Hướng dẫn chạy thử nghiệm Pipeline các Stages (0 đến 3)

Oraculum cung cấp giao diện dòng lệnh (CLI) để chạy các Stage của pipeline. 

Đầu vào của **Stage 1 (Classification)** là các *enriched findings* (tệp JSON chứa siêu dữ liệu lỗ hổng, mã nguồn và suy luận xác minh từ VulnHunterX) cùng với file tóm tắt `summary.json` liên kết chúng.

* **Đối với thử nghiệm với benchmark mẫu:** Oraculum đã đi kèm sẵn các tệp findings đã được ingest tại `tests/mini_benchmark/oraculum_output/`. Do đó, Stage 0 là tùy chọn (optional) và bạn có thể bắt đầu trực tiếp từ **Stage 1 (Classify)** mà không cần cài đặt hay phụ thuộc vào VulnHunterX (`vhx-root`).
* **Đối với quét các phát hiện mới:** Bạn bắt buộc phải chạy **Stage 0 (Ingest)** trước để import và làm giàu dữ liệu trước khi chuyển sang Stage 1.

Dưới đây là hướng dẫn chạy từ đầu đến cuối sử dụng dữ liệu mini-benchmark có sẵn:

### 0. Thiết lập môi trường
Copy file `env.example` thành `.env` và cấu hình các biến môi trường cho LLM Provider của bạn. Sau đó kích hoạt môi trường ảo:
```bash
source .venv/bin/activate
```

### 1. Ingest: Nhập kết quả xác minh từ VulnHunterX (Stage 0)
Đọc kết quả True Positive findings từ VulnHunterX và cấu trúc lại dưới dạng *enriched findings*:
```bash
oraculum ingest \
  --vhx-root tests/mini_benchmark/vhx_root \
  --repo mini-bench \
  --output-dir tests/mini_benchmark/oraculum_output \
  --force
```

### 2. Classify: Phân loại Chiến lược (Stage 1)
LLM phân tích enriched findings để đưa ra chiến lược giám sát thích hợp (`recorded_call`, `return_value`, hoặc `filesystem_state`):
```bash
oraculum classify \
  --repo mini-bench \
  --output-dir tests/mini_benchmark/oraculum_output \
  --log-file tests/mini_benchmark/classify_log.md \
  --force
```

### 3. Oracle: Sinh Đặc tả Oracle (Stage 2)
Nạp kết quả phân loại, LLM sẽ tải prompt của chiến lược tương ứng để sinh đặc tả Oracle Spec chi tiết:
```bash
oraculum oracle \
  --repo mini-bench \
  --output-dir tests/mini_benchmark/oraculum_output \
  --force
```

### 4. Harness: Sinh Atheris Harness Fuzzer (Stage 3)
LLM sinh mã nguồn fuzzer Atheris hoàn chỉnh và seed corpus mutation dựa trên Oracle Spec và template:
```bash
oraculum harness \
  --repo mini-bench \
  --output-dir tests/mini_benchmark/oraculum_output \
  --force
```
Các tệp harness sau khi sinh sẽ nằm tại:
`tests/mini_benchmark/oraculum_output/python/mini-bench/fuzz_targets/`

### 5. Chạy thử nghiệm và xác minh Harness
* **Smoke test**: Chạy thử fuzzer 1 lần (`-runs=1`) để kiểm tra cú pháp và import:
  ```bash
  python tests/mini_benchmark/oraculum_output/python/mini-bench/fuzz_targets/py_command_line_injection_target_app_py_4.py -runs=1
  ```
* **Phát hiện bug**: Chạy fuzzer để xem nó có phát hiện lỗ hổng thành công và ném ra đúng lỗi cấu hình khi gặp payload độc hại trong Seed Corpus hay không.

---

## Abstract

Bài báo này đề xuất một framework tự động sinh bug oracle cho Atheris dựa trên kết quả xác minh của VulnHunterX — một pipeline phân tích tĩnh kết hợp LLM giúp giảm thiểu dương tính giả của SAST. Với đầu vào là output của giai đoạn verification của VHX, bao gồm `data_flow`, `verification.answers`, `verification.reasoning`, `rule_id` và `function_name`, LLM sinh oracle theo một trong hai chiến lược: *patch\_call*, cấy mã tại sink để giám sát xem payload do fuzzer kiểm soát có đến được hàm nguy hiểm mà chưa qua sanitization hay không; và *inspect\_return*, kiểm tra giá trị trả về hoặc trạng thái hệ thống dựa trên tính chất bảo mật suy ra từ ngữ cảnh lỗ hổng. Toàn bộ quá trình sinh oracle diễn ra ngoại tuyến trước vòng lặp fuzzing, giúp Atheris phát hiện hiệu quả các lỗi logic bảo mật mà vẫn bảo toàn tối đa thông lượng fuzzing.

Kết quả thực nghiệm trên *(benchmark)* cho thấy *(kết quả chính)*.

---

## 1. Tổng quan kiến trúc

Oraculum nhận **verified finding** từ VulnHunterX và sinh **Atheris harness** phát hiện những lỗi bảo mật mà oracle mặc định của Atheris (crash / unhandled exception) không bắt được. Artifact chảy qua pipeline như sau:

```
 verified         enriched          {strategy,         oracle            Atheris          crash /
 finding    ──►   finding    ──►    mock_guidance} ─►   spec       ──►    harness   ──►    violation
 (VHX verify)     (ingest)          (Stage 1:          (Stage 2:         (Stage 3:        (fuzz-run)
                                     Classify)          Research)         Harness)
```

Mỗi stage tiêu thụ output có cấu trúc của stage trước; không stage nào sinh mã harness cho đến Stage 3. Tài liệu này đặc tả **Stage 1 (Classification)**; ingest, Stage 2 và Stage 3 có tài liệu riêng.

## 2. Stage 1: Classification

Stage 1 nhận một **enriched finding** (user prompt) cùng một bộ chỉ dẫn cố định (**system prompt**), suy luận theo decision procedure, và xuất ra `{strategy, mock_guidance}` — không sinh mã. Sơ đồ quyết định:

```
                       enriched finding
                              │
                              ▼
              ┌─────────────────────────────┐
              │  Q1: sink nguy hiểm khi      │
              │  execute trong test env?     │
              └───────┬─────────────┬────────┘
                     YES            NO
                      │             │
                 build mock         ▼
                      │   ┌────────────────────────────┐
                      │   │  Q2: violation observable   │
                      │   │  sau khi hàm return?         │
                      │   └──────┬───────────────┬──────┘
                      │        YES               NO
                      │         │                │
                      │         ▼                ▼
                      │  ┌──────────────┐   recorded_call
                      │  │ Q3: result    │   (mock để quan sát)
                      │  │ in memory?    │
                      │  └───┬───────┬──┘
                      │    YES       NO
                      │     │         │
                      │     ▼         ▼
                      │ return_    filesystem_
                      │ value      state
                      │
                      ▼
                 recorded_call
                 (mock để an toàn)
```

### 2.1 System prompt

```text
ROLE
You classify ONE VulnHunterX verified finding into an Atheris oracle
strategy. You do not write code. Output strict JSON only.

DECIDE THE STRATEGY  (use only data_flow, answers, and the `returns` signal)
Q1  Is executing the sink dangerous in a test env (network, shell, DB
    write, RCE)?
      YES → build a mock → strategy = recorded_call
      NO  → go to Q2
Q2  Is the violation observable after the function returns?
      NO  → strategy = recorded_call   (mock to observe the sink argument)
      YES → go to Q3
Q3  Is the result accessible in memory on return?  (read `returns`)
      YES → strategy = return_value
      NO  → strategy = filesystem_state

MOCK GUIDANCE  (only when recorded_call is selected)
Free-form guidance describing what sink/call to mock or record, what argument
or state to capture, and what fake behavior lets execution continue safely.

OUTPUT
{ "strategy": "return_value | recorded_call | filesystem_state",
  "mock_guidance": "<object when recorded_call, otherwise null>" }

RULES
Ground every decision in the finding's sink and data flow — never in
general CWE knowledge.
```

### 2.2 User prompt

The verified finding (post-verification schema):

```json
{
  "rule_id": "py/xxe",
  "tags": ["external/cwe/cwe-611"],
  "start_line": 58,
  "end_line": 58,
  "verdict": "True Positive",
  "confidence_score": 0.97,
  "reasoning": "<LLM explanation of why this is a true positive>",
  "data_flow": "source (...) → transform (...) → sink (...)",
  "answers": {
    "sink_identity": "...",
    "taint_confirmed": "...",
    "sanitization_absent": "...",
    "safe_library_absent": "...",
    "exploit_possible": "...",
    "dtd_unrestricted": "..."
  },
  "returns": { "kind": "value | none | mixed | unknown", "exprs": ["..."] }
}
```

### 2.3 Output

```json
{
  "strategy": "return_value | recorded_call | filesystem_state",
  "mock_guidance": {
    "required": true,
    "target": "<sink/call guidance>",
    "capture": "<argument/state to record>",
    "fake_behavior": "<safe fake behavior>",
    "notes": []
  }
}
```

Với `return_value` và `filesystem_state`, `mock_guidance` là `null`.

### 2.4 Chạy classification

Sau khi đã chạy `oraculum ingest` và có `output/python/<repo>/verification_results/summary.json`, chạy Stage 1:

```bash
oraculum classify \
  --repo Benchmark \
  --lang python \
  --log-file output/python/Benchmark/classifications/classification.md
```

Chạy lại và overwrite classification cũ:

```bash
oraculum classify \
  --repo Benchmark \
  --lang python \
  --force \
  --log-file output/python/Benchmark/classifications/classification.md
```

Chỉ classify một finding:

```bash
oraculum classify \
  --repo Benchmark \
  --lang python \
  --finding-id 0
```

Output:

```text
output/python/<repo>/classifications/status.json
output/python/<repo>/classifications/<target_id>.json
```

Model được resolve theo thứ tự:

```text
--model
LLM_PROVIDER + LLM_MODEL
LLM_MODEL
config/classification.yaml
```

---

## 3. Stage 2: Oracle Research

Stage 2 nhận `{strategy, mock_guidance}` + finding, **route theo strategy** để nạp đúng prompt, rồi sinh **oracle spec** cho Stage 3.

```
        {strategy, mock_guidance} + enriched finding + function source
                               │
                               ▼
                   ┌────────────────────────┐
                   │    route on strategy     │
                   └──┬──────────┬──────────┬─┘
                      │          │          │
              return_value  recorded_call  filesystem_state
                      │          │          │
                      ▼          ▼          ▼
                ┌──────────┐ ┌──────────┐ ┌──────────┐
                │ strategy  │ │ strategy  │ │ strategy  │
                │ prompt    │ │ prompt    │ │ prompt    │
                └────┬─────┘ └────┬─────┘ └────┬─────┘
                     │            │            │
                     │            ▼            │
                     │     ┌─────────────┐     │
                     │     │ mock_guidance│     │
                     │     │ prompt       │     │
                     │     │ http_client /│     │
                     │     │ subprocess / │     │
                     │     │ db_engine    │     │
                     │     └──────┬──────┘     │
                     │            │            │
                     └────────────┼────────────┘
                                  ▼
                             oracle spec
                              (→ Stage 3)
```

---

## 5. Bug Class Applicability

**Nhóm `return value` — Q1 NO → Q2 YES → Q3 YES**

| Bug class | Q3 inspects | Lý do |
|---|---|---|
| Open redirect (CWE-601) | URL in return value | Domain check là exact signal |
| HTTP response splitting (CWE-113) | Header value string | CRLF check là exact |
| Log injection (CWE-117) | Log record string | Newline check là exact |
| Reflected XSS (CWE-79) | HTML body string | Canary check reliable — caveat duy nhất là JS context |
| Path traversal (CWE-22) | Return path string | Khi function trả về path; realpath check là đủ |

**Nhóm `recorded call` (mock for safety) — Q1 YES → build mock → Q2 NO**

| Bug class | Mock target | Lý do |
|---|---|---|
| SSRF (CWE-918) | `requests.get`, `urllib.urlopen` | URL argument rõ ràng, fake response dễ construct |
| Command injection (CWE-78) | `subprocess.run`, `os.system` | Command string captured, return empty stdout là đủ |
| SQL injection write (CWE-89) | `cursor.execute` | Query string captured hoàn toàn, fake result set dễ return |
| LDAP injection (CWE-90) | LDAP client search | Filter string captured, return empty result |
| XPath injection (CWE-643) | `lxml.etree.xpath`, `ElementTree.find` | Expression string captured |

**Nhóm `recorded call` (mock for observability) — Q1 NO → Q2 NO**

| Bug class | Mock target | Lý do |
|---|---|---|
| SQL injection read (CWE-89) | `cursor.execute` | Query string không có trong return value; mock để capture |

**Nhóm `filesystem state` — Q1 NO → Q2 YES → Q3 NO**

| Bug class | Inspects | Lý do |
|---|---|---|
| Path traversal (CWE-22) | Files created outside allowed dir | Khi function return `None`; violation nằm trên disk |

**Hoạt động được nhưng có caveat đáng kể**

| Bug class | Vấn đề |
|---|---|
| XXE (CWE-611) | Entity resolution xảy ra *bên trong* XML parser — không phải một external call độc lập. Mock được entity resolver nhưng interface trong Python's `xml.sax` phức tạp và không nhất quán giữa các parser backends |
| Template injection (CWE-94) | Inspect rendered output được, nhưng payload không phải lúc nào cũng để lại artifact rõ ràng. `{{7*7}}` → `49` detect được; payload đọc internal config mà không print ra thì không |

**Không hoạt động — structural incompatibility**

| Bug class | Lý do cụ thể |
|---|---|
| Insecure deserialization (CWE-502) | Dangerous execution xảy ra *bên trong* `pickle.loads` — không có external call nào để mock. Deserialization IS the sink và IS the exploit |
| Stored XSS | Cần read-write cycle qua persistence layer. Taint bị cắt bởi DB round-trip — single execution không đủ |
| Race condition (CWE-362) | Non-deterministic; requires thread scheduling control |
| Timing attack (CWE-208) | Statistical signal; single execution không đủ |
| Weak crypto (CWE-327) | Output hợp lệ; insecurity là property của algorithm, không observable từ output |
---

## 8. Prompting Strategy

This section describes the planned prompt pipeline. Detailed prompt content is covered in separate documents per agent.

### Overview

Oracle strategy selection is decomposed into a pipeline of agents. Each agent has a narrow, well-defined responsibility and produces a structured JSON object consumed by the next stage. No agent generates harness code — code generation is the final stage downstream.

```
VHX verified finding
        │
        ▼
┌───────────────────────┐
│  Strategy Selection   │  answers Q1, Q2, Q3
│  Agent                │  outputs: oracle_approach, build_mock, confidence
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│  Oracle Research      │  branch on oracle_approach
│  Agent                │  outputs: what to inspect / what mock captures
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│  Harness Generation   │  consumes research output
│  Agent                │  outputs: Atheris harness code
└───────────────────────┘
```

### Strategy Selection Agent

Responsible for answering Q1, Q2, Q3 from the verified finding input. The prompt must:

- Ground each answer strictly in `data_flow`, `answers`, and `reasoning` fields — not in general CWE knowledge
- Produce the structured output contract defined in Section 6
- Refuse to proceed and set `confidence: low` when taint state is `destroyed` or the finding is ambiguous

### Oracle Research Agent — `recorded_call` branch

Responsible for determining mock design when `oracle_approach` is `recorded_call`. The prompt must reason about:

- Exact sink to mock and which argument carries taint
- What fake return value allows the application to continue normally
- What predicate on the captured argument confirms an active payload
- Alias and async risks that could cause the mock to be bypassed

### Oracle Research Agent — `return_value` branch

Responsible for determining the security invariant when `oracle_approach` is `return_value`. The prompt must reason about:

- Which field of the return value or response object to inspect
- What constitutes a violation (exact invariant condition)
- Known bypass cases for the invariant (encoding, normalization edge cases)
- Whether a fuzz canary survives the transform chain to the return value

### Oracle Research Agent — `filesystem_state` branch

Responsible for determining the state diff check when `oracle_approach` is `filesystem_state`. The prompt must reason about:

- Which directories to snapshot before the call
- What constitutes a new file appearing outside the allowed boundary
- Cleanup strategy to prevent disk exhaustion across fuzz iterations
- Symlink and race condition caveats


