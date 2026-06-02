# Oraculum: Bug Oracle Framework — harness generation agent  

**Document type:** Architecture reference  
**Scope:** Bug Oracle Framework — harness generation agent  
**Status:** Draft for team review

---

## Abstract

Bài báo này đề xuất một framework tự động sinh bug oracle cho Atheris dựa trên kết quả xác minh của VulnHunterX — một pipeline phân tích tĩnh kết hợp LLM giúp giảm thiểu dương tính giả của SAST. Với đầu vào là output của giai đoạn verification của VHX, bao gồm `data_flow`, `verification.answers`, `verification.reasoning`, `rule_id` và `function_name`, LLM sinh oracle theo một trong hai chiến lược: *patch\_call*, cấy mã tại sink để giám sát xem payload do fuzzer kiểm soát có đến được hàm nguy hiểm mà chưa qua sanitization hay không; và *inspect\_return*, kiểm tra giá trị trả về hoặc trạng thái hệ thống dựa trên tính chất bảo mật suy ra từ ngữ cảnh lỗ hổng. Toàn bộ quá trình sinh oracle diễn ra ngoại tuyến trước vòng lặp fuzzing, giúp Atheris phát hiện hiệu quả các lỗi logic bảo mật mà vẫn bảo toàn tối đa thông lượng fuzzing.

Kết quả thực nghiệm trên *(benchmark)* cho thấy *(kết quả chính)*.

---

## 1. Tổng quan kiến trúc

Oraculum nhận **verified finding** từ VulnHunterX và sinh **Atheris harness** phát hiện những lỗi bảo mật mà oracle mặc định của Atheris (crash / unhandled exception) không bắt được. Artifact chảy qua pipeline như sau:

```
 verified         enriched          {strategy,         oracle            Atheris          crash /
 finding    ──►   finding    ──►    mock_type}   ──►   spec       ──►    harness   ──►    violation
 (VHX verify)     (ingest)          (Stage 1:          (Stage 2:         (Stage 3:        (fuzz-run)
                                     Classify)          Research)         Harness)
```

Mỗi stage tiêu thụ output có cấu trúc của stage trước; không stage nào sinh mã harness cho đến Stage 3. Tài liệu này đặc tả **Stage 1 (Classification)**; ingest, Stage 2 và Stage 3 có tài liệu riêng.

## 2. Stage 1: Classification

Stage 1 nhận một **enriched finding** (user prompt) cùng một bộ chỉ dẫn cố định (**system prompt**), suy luận theo decision procedure, và xuất ra `{strategy, mock_type}` — không sinh mã. Sơ đồ quyết định:

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

MOCK TYPE  (only when a mock is built)
<partner-defined enum — TBD>

OUTPUT
{ "strategy": "return_value | recorded_call | filesystem_state",
  "mock_type": "<mock type> | null" }

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
  "returns": { "kind": "value | none", "exprs": ["..."], "persists_to_disk": false }
}
```

### 2.3 Output

```json
{
  "strategy": "return_value | recorded_call | filesystem_state",
  "mock_type": "<mock type do partner định nghĩa, hoặc null>"
}
```

---

## 3. Stage 2: Oracle Research

Stage 2 nhận `{strategy, mock_type}` + finding, **route theo strategy** để nạp đúng prompt, rồi sinh **oracle spec** cho Stage 3.

```
        {strategy, mock_type} + enriched finding + function source
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
                     │     │ mock_type    │     │
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
