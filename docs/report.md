# Oraculum: Bug Oracle Framework — harness generation agent  

**Document type:** Architecture reference  
**Scope:** Bug Oracle Framework — harness generation agent  
**Status:** Draft for team review

---

## Abstract

Bài báo này đề xuất một framework tự động sinh bug oracle cho Atheris dựa trên kết quả xác minh của VulnHunterX — một pipeline phân tích tĩnh kết hợp LLM giúp giảm thiểu dương tính giả của SAST. Với đầu vào là output của giai đoạn verification của VHX, bao gồm `data_flow`, `verification.answers`, `verification.reasoning`, `rule_id` và `function_name`, LLM sinh oracle theo một trong hai chiến lược: *patch\_call*, cấy mã tại sink để giám sát xem payload do fuzzer kiểm soát có đến được hàm nguy hiểm mà chưa qua sanitization hay không; và *inspect\_return*, kiểm tra giá trị trả về hoặc trạng thái hệ thống dựa trên tính chất bảo mật suy ra từ ngữ cảnh lỗ hổng. Toàn bộ quá trình sinh oracle diễn ra ngoại tuyến trước vòng lặp fuzzing, giúp Atheris phát hiện hiệu quả các lỗi logic bảo mật mà vẫn bảo toàn tối đa thông lượng fuzzing.

Kết quả thực nghiệm trên *(benchmark)* cho thấy *(kết quả chính)*.

---

## 1. Context

The framework generates Atheris fuzz harnesses that detect security bugs which the default Atheris oracle (crash / unhandled exception) cannot catch. For each verified finding, the agent must choose one of two oracle strategies before generating harness code:

| Strategy | Mechanism |
|---|---|
|
| `inspect_return` | Allow the target function to run to completion. Inspect the return value or post-execution state against a security invariant. |

The choice between the two is **not a stylistic preference** — it is determined by objective properties of the sink and the data flow. This document defines the decision procedure only. How the oracle is implemented after the strategy is chosen is a separate concern, covered in a subsequent document.

---

## 2. Input Available to the Agent

For each finding, the agent receives the following fields (post-verification, trimmed schema):

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
  }
}
```

The agent grounds its answers to Q1, Q2, Q3 strictly on these fields — not on general knowledge about CWE types.

---

## 3. The Three-Question Decision Procedure



### Q1 — Is executing the sink dangerous in a test environment?
### Q2 — Is the security violation observable after the function returns?
### Q3 — Is the result accessible in memory on return?

---

## 4. Decision Tree

```
┌───────────────────────────────────────────────────────────────────────────┐
│              START: verified finding with data_flow + answers             │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      │
                                      ▼
                      ┌───────────────────────────────┐
                      │  Q1: Is the sink dangerous    │
                      │  to execute in test env?      │
                      │  (I/O, network, shell, RCE)   │
                      └───────────────────────────────┘
                               │               │
                              YES               NO
                               │               │
                 ┌─────────────────────────┐  ┌────────────┐
                 │        build mock       │  │  no mock   │
                 ├─────────────────────────┤  └─────┬──────┘
                 │ · sink qualified name   │        |
                 └────────────┬────────────┘        │
                              │                     │
                              └──────────┬──────────┘
                                         │
                                         ▼
                      ┌───────────────────────────────┐
                      │  Q2: Is the violation         │
                      │  observable after return?     │
                      └───────────────────────────────┘
                               │               │
                              YES               NO
                               │               │
                               ▼               ▼
                  ┌──────────────────────┐  ┌──────────────────────┐
                  │  Q3: Is the result   │  │    recorded call     │
                  │  accessible in       │  └──────────────────────┘
                  │  memory on return?   │    · SSRF
                  └──────────────────────┘      mock requests.get
                         │           │        · Command injection
                        YES           NO        mock subprocess.run
                         │           │        · SQL write
                         ▼           ▼          mock cursor.execute
                ┌──────────────┐  ┌──────────────┐
                │ return value │  │  filesystem  │
                └──────────────┘  │    state     │
                · Open redirect   └──────────────┘
                · Reflected XSS   · Path traversal
                · Log injection     (returns None)
                · HTTP resp split
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
