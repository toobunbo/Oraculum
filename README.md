# Oraculum: Bug Oracle Framework — harness generation agent  

**Document type:** Architecture reference  
**Scope:** Bug Oracle Framework — harness generation agent  
**Status:** Draft for team review

---

## Abstract

Bài báo này đề xuất một framework tự động sinh bug oracle cho Atheris dựa trên kết quả xác minh của VulnHunterX — một pipeline phân tích tĩnh kết hợp LLM giúp giảm thiểu dương tính giả của SAST. Với đầu vào là output của giai đoạn verification của VHX, bao gồm `data_flow`, `verification.answers`, `verification.reasoning`, `rule_id` và `function_name`, LLM sinh oracle theo ba chiến lược xuyên suốt pipeline: `recorded_call`, capture argument tại sink boundary; `return_value`, kiểm tra giá trị trả về; và `filesystem_state`, kiểm tra trạng thái filesystem sau khi hàm chạy xong. Stage 2 giữ nguyên tên strategy này trong oracle spec, rồi Stage 3 sinh Atheris harness từ spec đó. Toàn bộ quá trình sinh oracle diễn ra ngoại tuyến trước vòng lặp fuzzing, giúp Atheris phát hiện hiệu quả các lỗi logic bảo mật mà vẫn bảo toàn tối đa thông lượng fuzzing.

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

Mỗi stage tiêu thụ output có cấu trúc của stage trước; không stage nào sinh mã harness cho đến Stage 3. Tài liệu này mô tả kiến trúc, cách cấu hình, cách chạy full pipeline, và contract chính giữa các stage.

## 2. Chạy full pipeline

### 2.1 Cài đặt

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

Nếu chỉ chạy CLI không cần dev tools:

```bash
pip install -e .
```

### 2.2 Cấu hình môi trường

Tạo `.env` ở root repo hoặc export trực tiếp:

```bash
LLM_PROVIDER=openai
LLM_MODEL=gpt-4.1
OPENAI_API_KEY=...
ORACULUM_VHX_ROOT=/path/to/VulnHunterX
```

Provider/model được resolve theo thứ tự:

```text
--model
LLM_PROVIDER + LLM_MODEL
LLM_MODEL
config/<stage>.yaml
```

Kiểm tra môi trường:

```bash
oraculum check-env
```

### 2.3 Chạy đầy đủ 4 stage

Ví dụ repo benchmark tên `Benchmark`, language `python`:

```bash
oraculum ingest \
  --vhx-root "$ORACULUM_VHX_ROOT" \
  --repo Benchmark \
  --lang python \
  --force

oraculum classify \
  --repo Benchmark \
  --lang python \
  --force \
  --log-file logs/classify.md

oraculum oracle \
  --repo Benchmark \
  --lang python \
  --force \
  --log-file logs/oracle.md

oraculum harness \
  --repo Benchmark \
  --lang python \
  --force \
  --log-file logs/harness.md
```

`oraculum oracle` mặc định sẽ đọc classification status ở:

```text
output/python/<repo>/classifications/status.json
```

Nếu file này không tồn tại, Oracle vẫn chạy backward-compatible theo prompt chung cũ. Nếu muốn ép dùng classification cụ thể:

```bash
oraculum oracle \
  --repo Benchmark \
  --classification-status output/python/Benchmark/classifications/status.json
```

Hoặc debug một finding + một classification JSON:

```bash
oraculum oracle \
  --repo Benchmark \
  --finding output/python/Benchmark/verification_results/findings/finding_0_py_xss.json \
  --classification output/python/Benchmark/classifications/py_xss_pkg_app_py_42.json \
  --force
```

### 2.4 Output chính

```text
output/python/<repo>/verification_results/summary.json
output/python/<repo>/verification_results/findings/<finding>.json
output/python/<repo>/classifications/status.json
output/python/<repo>/classifications/<target_id>.json
output/python/<repo>/fuzz_oracles/status.json
output/python/<repo>/fuzz_oracles/<target_id>.json
output/python/<repo>/fuzz_targets/status.json
output/python/<repo>/fuzz_targets/<target_id>.py
output/python/<repo>/fuzz_corpus/<target_id>/seed_*
```

### 2.5 Chạy harness

Sau khi Stage 3 sinh target:

```bash
python output/python/Benchmark/fuzz_targets/<target_id>.py
```

Hoặc compile-check toàn bộ harness:

```bash
for f in output/python/Benchmark/fuzz_targets/*.py; do python -m py_compile "$f"; done
```

### 2.6 Kiểm thử Oraculum

```bash
python3 -m compileall -q src tests
pytest tests/ -v
ruff check src tests
```

### 2.7 Run report: `benchmark-python`

Lần chạy hoàn chỉnh gần nhất được thực hiện bằng `.venv/bin/oraculum` trên dataset đã có trong `output/python/benchmark-python`.

Commands đã chạy:

```bash
.venv/bin/oraculum ingest \
  --vhx-root /home/tuonglnc/repo/VulnHunterX \
  --repo benchmark-python \
  --lang python \
  --output-dir output \
  --force

.venv/bin/oraculum classify \
  --repo benchmark-python \
  --lang python \
  --output-dir output \
  --force \
  --log-file logs/benchmark-python-classify.md

.venv/bin/oraculum oracle \
  --repo benchmark-python \
  --lang python \
  --output-dir output \
  --classification-status output/python/benchmark-python/classifications/status.json \
  --force \
  --log-file logs/benchmark-python-oracle.md

.venv/bin/oraculum harness \
  --repo benchmark-python \
  --lang python \
  --output-dir output \
  --oracle-status output/python/benchmark-python/fuzz_oracles/status.json \
  --force \
  --log-file logs/benchmark-python-harness.md
```

Kết quả:

| Stage | Selected | Generated/Enriched | Skipped | Failed |
|---|---:|---:|---:|---:|
| Ingest | 33 | 33 enriched | 12 | 0 |
| Classification | 33 | 33 generated | 0 | 0 |
| Oracle Research | 33 | 33 generated | 0 | 0 |
| Harness Generation | 33 | 33 generated | 0 | 0 |

Artifacts:

```text
output/python/benchmark-python/classifications/*.json = 33
output/python/benchmark-python/fuzz_oracles/*.json    = 33
output/python/benchmark-python/fuzz_targets/*.py      = 33
```

Strategy distribution của lần chạy này:

```text
classification: recorded_call = 33
oracle:         recorded_call = 33
harness:        recorded_call = 33
```

Generated harness compile-check:

```bash
for f in output/python/benchmark-python/fuzz_targets/*.py; do .venv/bin/python -m py_compile "$f"; done
```

Kết quả: tất cả 33 generated harness compile thành công.

## 3. Stage 1: Classification

Stage 1 nhận một **enriched finding** (user prompt) cùng một bộ chỉ dẫn cố định (**system prompt**), suy luận theo decision procedure, và xuất ra `{strategy, mock_guidance}` — không sinh mã.

`strategy` trả lời câu hỏi: **oracle nên quan sát violation ở đâu?**

`mock_guidance` trả lời câu hỏi độc lập: **có cần patch/mock/stub gì để chạy harness an toàn, ổn định, hoặc đủ quan sát không?**

Vì vậy `sink dangerous` không tự động đồng nghĩa với `strategy = recorded_call`. Nó chỉ quyết định có cần `mock_guidance` hay không. `recorded_call` chỉ được chọn khi violation không quan sát được qua return value hoặc trạng thái sau khi hàm chạy xong, và cách quan sát tốt nhất là capture call/argument tại sink boundary.

```
                       enriched finding
                              │
                              ▼
              ┌─────────────────────────────┐
              │ Q1: violation observable     │
              │ sau khi target function       │
              │ returns, không cần intercept  │
              │ sink boundary?                │
              └───────┬─────────────┬────────┘
                     YES            NO
                      │             │
                      ▼             ▼
              ┌──────────────┐  recorded_call
              │ Q2: evidence  │  (capture call/
              │ nằm trong     │   argument/state
              │ return value? │   tại sink boundary)
              └───┬──────┬───┘
                YES      NO
                 │        │
                 ▼        ▼
           return_value  filesystem_state
                 │        │
                 └───┬────┘
                     ▼
              ┌─────────────────────────────┐
              │ Q3: executing real sink /    │
              │ external operation safe and  │
              │ deterministic in fuzz env?   │
              └───────┬─────────────┬───────┘
                     YES            NO
                      │             │
                      ▼             ▼
              mock_guidance=null   build mock_guidance
                                   (safety/determinism)
```

### 3.1 System prompt

```text
ROLE
You classify ONE VulnHunterX verified finding into an Atheris oracle
strategy. You do not write code. Output strict JSON only.

DECIDE THE STRATEGY  (use only data_flow, answers, and the `returns` signal)
Q1  Is the violation observable after the target function returns, without
    intercepting the sink/call boundary?
      YES → go to Q2
      NO  → strategy = recorded_call

Q2  Is the evidence accessible in memory through the returned value/object?
    Use `returns.kind` and `returns.exprs` as primary evidence, but also
    consider whether the finding describes a response/header/body object that
    is returned.
      YES → strategy = return_value
      NO  → strategy = filesystem_state

DECIDE EXECUTION CONTROL  (does not change strategy)
Q3  Is executing the real sink or external operation safe and deterministic
    in the fuzz environment?
    Dangerous or unstable means shell/RCE, network I/O, DB writes, irreversible
    filesystem writes, unsafe parser external resolution, timeouts, or external
    services.
      YES → mock_guidance = null, unless strategy = recorded_call
      NO  → build mock_guidance for safety/determinism

MOCK GUIDANCE
For recorded_call, mock_guidance describes what call/sink boundary to record
and which argument/state proves tainted payload reachability.

For return_value and filesystem_state, mock_guidance is normally null, but may
be an object when the real sink/external operation must be stubbed for safety
or determinism while preserving the selected observation strategy.

OUTPUT
{ "strategy": "return_value | recorded_call | filesystem_state",
  "mock_guidance": "<object when execution control is needed, otherwise null>" }

RULES
Ground every decision in the finding's sink and data flow — never in
general CWE knowledge.
Do not choose recorded_call merely because the sink is dangerous. Choose
recorded_call only when the violation is not observable after return and must
be observed at the call boundary.
```

### 3.2 User prompt

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

### 3.3 Output

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

Với `return_value` và `filesystem_state`, `mock_guidance` thường là `null`. Nếu cần patch/mock/stub để chạy an toàn hoặc ổn định, vẫn giữ nguyên `strategy` đã chọn và điền `mock_guidance`.

### 3.4 Chạy classification

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

## 4. Stage 2: Oracle Research

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

### 4.1 Strategy routing

Classification, Oracle Research, và Harness dùng cùng một bộ strategy:

| Strategy | Oracle system prompt | Harness system prompt |
|---|---|---|
| `recorded_call` | `oracle_system_recorded_call.txt` | `harness_system_recorded_call.txt` |
| `return_value` | `oracle_system_return_value.txt` | `harness_system_return_value.txt` |
| `filesystem_state` | `oracle_system_filesystem_state.txt` | `harness_system_filesystem_state.txt` |

Stage 2 ghi `classification_strategy`, `classification_confidence`, và `mock_guidance` vào `_meta` của oracle spec để Stage 3 có đủ context.

### 4.2 Chạy Oracle Research

```bash
oraculum oracle \
  --repo Benchmark \
  --lang python \
  --classification-status output/python/Benchmark/classifications/status.json \
  --force \
  --log-file logs/oracle.md
```

Chỉ chạy một finding:

```bash
oraculum oracle \
  --repo Benchmark \
  --lang python \
  --finding-id 0 \
  --force
```

Output:

```text
output/python/<repo>/fuzz_oracles/status.json
output/python/<repo>/fuzz_oracles/<target_id>.json
```

## 5. Stage 3: Harness Generation

Stage 3 nhận oracle spec từ Stage 2, dựng skeleton theo `monitor.strategy`, rồi gọi LLM hoàn thiện Atheris harness.

Supported monitor strategies:

| Strategy | Harness behavior |
|---|---|
| `recorded_call` | Patch/mock sink call, inspect captured call arguments |
| `return_value` | Call target directly, inspect returned value |
| `filesystem_state` | Isolate filesystem state, call target, inspect state diff, cleanup |

Chạy toàn bộ harness generation:

```bash
oraculum harness \
  --repo Benchmark \
  --lang python \
  --oracle-status output/python/Benchmark/fuzz_oracles/status.json \
  --force \
  --log-file logs/harness.md
```

Chỉ sinh một target:

```bash
oraculum harness \
  --repo Benchmark \
  --target-id py_xss_pkg_app_py_42 \
  --force
```

Output:

```text
output/python/<repo>/fuzz_targets/status.json
output/python/<repo>/fuzz_targets/<target_id>.py
output/python/<repo>/fuzz_corpus/<target_id>/seed_*
```

## 6. Bug Class Applicability

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

## 7. Prompting Strategy

This section describes the implemented prompt pipeline. Detailed prompt content is covered in separate prompt files per agent.

### Overview

Oracle strategy selection is decomposed into a pipeline of agents. Each agent has a narrow, well-defined responsibility and produces a structured JSON object consumed by the next stage. No agent generates harness code — code generation is the final stage downstream.

```
VHX verified finding
        │
        ▼
┌───────────────────────┐
│  Strategy Selection   │  answers Q1, Q2, Q3
│  Agent                │  outputs: strategy, mock_guidance, confidence
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│  Oracle Research      │  branch on strategy
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
- Produce the structured output contract defined in Section 3
- Refuse to proceed and set `confidence: low` when taint state is `destroyed` or the finding is ambiguous

### Oracle Research Agent — `recorded_call` branch

Responsible for determining mock design when `strategy` is `recorded_call`. The prompt must reason about:

- Exact sink to mock and which argument carries taint
- What fake return value allows the application to continue normally
- What predicate on the captured argument confirms an active payload
- Alias and async risks that could cause the mock to be bypassed

### Oracle Research Agent — `return_value` branch

Responsible for determining the security invariant when `strategy` is `return_value`. The prompt must reason about:

- Which field of the return value or response object to inspect
- What constitutes a violation (exact invariant condition)
- Known bypass cases for the invariant (encoding, normalization edge cases)
- Whether a fuzz canary survives the transform chain to the return value

### Oracle Research Agent — `filesystem_state` branch

Responsible for determining the state diff check when `strategy` is `filesystem_state`. The prompt must reason about:

- Which directories to snapshot before the call
- What constitutes a new file appearing outside the allowed boundary
- Cleanup strategy to prevent disk exhaustion across fuzz iterations
- Symlink and race condition caveats
