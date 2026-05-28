# Oracle Strategy Selection: `patch_call` vs `inspect_return`

**Document type:** Architecture reference  
**Scope:** Bug Oracle Framework — harness generation agent  
**Status:** Draft for team review

---

## 1. Context

The framework generates Atheris fuzz harnesses that detect security bugs which the default Atheris oracle (crash / unhandled exception) cannot catch. For each verified finding, the agent must choose one of two oracle strategies before generating harness code:

| Strategy | Mechanism |
|---|---|
| `patch_call` | Intercept the dangerous sink **before** it executes. Check whether the argument arriving at the sink contains an active exploit payload. Raise an oracle exception if confirmed. |
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

The agent answers three questions in strict order. The first question that resolves to a conclusion terminates the procedure.

```
Q1 → Q2 → Q3
```

### Q1 — Is executing the sink dangerous or irreversible in a test environment?

> **"If the sink runs as-is during fuzzing, does it cause side effects that are unacceptable in a test loop running millions of iterations?"**

Dangerous side effects include:

- File system reads/writes **outside** the sandbox
- Network I/O (DNS lookup, HTTP request, SSRF)
- Shell command execution
- Database writes
- Arbitrary code execution within the fuzzer process

**If YES → `patch_call` immediately. Do not proceed to Q2.**

Rationale: allowing a dangerous sink to execute in a fuzz loop running millions of iterations is not acceptable regardless of observability.

**If NO → proceed to Q2.**

---

### Q2 — Is the security violation observable in the return value or post-execution state?

> **"After the target function returns, can the oracle determine whether a security violation occurred — using the return value, an output parameter, or a directly inspectable state change?"**

Observable signals include:

- A file path string returned by the function
- A URL or Location header value in the response object
- An HTML body string that reflects the input
- A log record that can be read back

Not observable:

- A DOM object that does not expose which entities were resolved
- A query result set that does not reveal whether injection altered the query
- A `None` / `True` return from a write-only operation

**If YES → `inspect_return`.**

**If NO → `patch_call`.**

---

### Q3 — Is the taint preserved unmodified through the transform chain to the sink?

> **"Does the fuzz input arrive at the sink in a form that a predicate can still match against?"**

This question does **not** change the oracle type. It characterizes the difficulty of the check that will be written in the next step.

| Taint state at sink | Implication |
|---|---|
| Fully preserved (direct assignment chain) | Simple check is sufficient |
| Partially transformed (concatenated, interpolated) | Check must account for surrounding context |
| Encoded (URL-encoded, base64, HTML-entity) | Check must operate on decoded form |
| Destroyed (hashed, encrypted) | Oracle will be structurally unreliable — flag as low-confidence |

---

## 4. Decision Tree

```
┌─────────────────────────────────────────────────────────────────┐
│  START: verified finding with data_flow + answers               │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
          ┌───────────────────────────────┐
          │  Q1: Is executing the sink    │
          │  dangerous in test env?       │
          │  (I/O, network, shell, RCE)   │
          └───────────────────────────────┘
                 │              │
                YES              NO
                 │              │
                 ▼              ▼
          ┌──────────┐  ┌───────────────────────────────┐
          │patch_call│  │  Q2: Is the violation          │
          └──────────┘  │  observable after return?      │
                        └───────────────────────────────┘
                               │              │
                              YES              NO
                               │              │
                               ▼              ▼
                        ┌──────────────┐ ┌──────────┐
                        │inspect_return│ │patch_call│
                        └──────────────┘ └──────────┘
                               │              │
                               └──────┬───────┘
                                      │
                                      ▼
                        ┌─────────────────────────────────┐
                        │  Q3: Is taint preserved?         │
                        │  → characterizes check difficulty│
                        │    only, does not change strategy│
                        └─────────────────────────────────┘
```

---

## 5. Worked Examples

### Example A — XXE (CWE-611) → `patch_call`

**Input (trimmed):**

```json
{
  "rule_id": "py/xxe",
  "tags": ["external/cwe/cwe-611"],
  "data_flow": "request.headers.getlist('BenchmarkTest00540')[0] → param → bar → xml.dom.minidom.parseString(bar, parser)",
  "answers": {
    "sink_identity": "xml.dom.minidom.parseString() with a SAX parser passed as second argument",
    "sanitization_absent": "No. parser.setFeature(xml.sax.handler.feature_external_ges, True) explicitly enables external entity resolution on line 53.",
    "exploit_possible": "Yes. An attacker can inject <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]> to read arbitrary local files."
  }
}
```

**Agent reasoning:**

- **Q1:** `parseString()` with `feature_external_ges=True` will resolve any `SYSTEM` URI present in the XML. In a fuzz loop this means real file reads or network requests on every iteration that contains a DOCTYPE declaration. → **YES, dangerous.**
- **Conclusion: `patch_call`.** Q2 not evaluated.
- **Q3:** `bar = param = headers[0]` — three direct assignments with no transformation. Taint fully preserved at sink. → Simple check sufficient.

---

### Example B — Path Traversal (CWE-22) → `inspect_return`

**Input (trimmed):**

```json
{
  "rule_id": "py/path-injection",
  "tags": ["external/cwe/cwe-22"],
  "data_flow": "request.args.get('filename') → filename → os.path.join(UPLOAD_DIR, filename) → open(path, 'w') → return path",
  "answers": {
    "sink_identity": "open() called with a path constructed from os.path.join(UPLOAD_DIR, user_input)",
    "sanitization_absent": "No path normalization or prefix validation is applied.",
    "exploit_possible": "Yes. Input '../../../etc/cron.d/evil' escapes UPLOAD_DIR."
  }
}
```

**Agent reasoning:**

- **Q1:** `open(path, 'w')` writes a file. In a sandboxed test environment with a temporary directory, writing to an unexpected path is recoverable. Not irreversible at test scale. → **NO.**
- **Q2:** The function returns `path` — the actual string passed to `open()`. The resolved path can be checked against the allowed root after the function returns. → **YES, observable.**
- **Conclusion: `inspect_return`.**
- **Q3:** `path = os.path.join(UPLOAD_DIR, filename)` — `os.path.join` with a user-supplied absolute path silently discards the base prefix. The taint reaches the return value unmodified. → Simple prefix check sufficient.

---

### Example C — SQL Injection (CWE-89) → context-dependent

**Input (trimmed):**

```json
{
  "rule_id": "py/sql-injection",
  "tags": ["external/cwe/cwe-89"],
  "data_flow": "request.form['username'] → username → 'SELECT * FROM users WHERE name=\\'' + username + '\\'' → cursor.execute(query)",
  "answers": {
    "sink_identity": "cursor.execute() called with a string-concatenated query",
    "sanitization_absent": "No parameterized query. Direct string concatenation.",
    "exploit_possible": "Yes. Input \"' OR '1'='1\" returns all rows."
  }
}
```

**Agent reasoning:**

- **Q1:** For this `SELECT` query on an isolated test database, execution is a read operation with no mutation. Acceptable at test scale. → **NO for read queries.** For `INSERT` / `UPDATE` / `DELETE`: answer is YES → `patch_call` immediately.
- **Q2:** The function returns fetched rows. A tautology injection causes more rows to be returned than expected — this is observable in principle, but the signal is weak: it depends entirely on the test database state and is not structurally guaranteed. → **Marginal YES — low confidence.**
- **Conclusion: `patch_call` as safe default.** `inspect_return` is viable only when the test DB state is fully controlled and deterministic.
- **Q3:** String concatenation embeds the injection payload directly in the query string. Taint preserved in context. → Check must account for surrounding SQL syntax.

---

### Example D — Reflected XSS (CWE-79) → `inspect_return`

**Input (trimmed):**

```json
{
  "rule_id": "py/reflected-xss",
  "tags": ["external/cwe/cwe-79"],
  "data_flow": "request.args.get('q') → q → render_template('search.html', query=q) → return response",
  "answers": {
    "sink_identity": "Jinja2 render_template() with user input passed as a template variable",
    "sanitization_absent": "The variable is rendered with {{ query }} — no |e filter or autoescape override applied.",
    "exploit_possible": "Yes. Input <script>alert(1)</script> is reflected raw in the HTML body."
  }
}
```

**Agent reasoning:**

- **Q1:** `render_template()` produces an HTML string in memory. No I/O, no network call, no shell execution. → **NO.**
- **Q2:** The function returns a response object containing the rendered HTML body. Whether the input was reflected without encoding is directly checkable from this return value. → **YES, observable.**
- **Conclusion: `inspect_return`.**
- **Q3:** The query variable passes through Jinja2's rendering pipeline. With `autoescape` off and no `|e` filter (confirmed by `answers.sanitization_absent`), the raw input is embedded in the output unchanged. → Taint preserved; check against response body is reliable.

---

## 6. Classification Reference Table

| CWE | Vulnerability | Q1 | Q2 | Oracle | Notes |
|---|---|---|---|---|---|
| CWE-611 | XXE | YES | N/A | `patch_call` | DNS/file I/O on parse |
| CWE-78 | Command injection | YES | N/A | `patch_call` | Shell exec in process |
| CWE-89 | SQL injection (write) | YES | N/A | `patch_call` | DB mutation |
| CWE-918 | SSRF | YES | N/A | `patch_call` | Network call |
| CWE-90 | LDAP injection | YES | N/A | `patch_call` | Directory query |
| CWE-502 | Insecure deserialization | YES | N/A | `patch_call` | RCE in fuzzer process |
| CWE-643 | XPath injection | NO | NO | `patch_call` | Result set opaque |
| CWE-89 | SQL injection (read) | NO | marginal | `patch_call` | `inspect_return` only if DB state controlled |
| CWE-22 | Path traversal | NO | YES | `inspect_return` | Return path checkable |
| CWE-601 | Open redirect | NO | YES | `inspect_return` | Return URL checkable |
| CWE-79 | Reflected XSS | NO | YES | `inspect_return` | HTML body checkable |
| CWE-113 | HTTP response splitting | NO | YES | `inspect_return` | Header value checkable |
| CWE-117 | Log injection | NO | YES | `inspect_return` | Log record checkable |
| CWE-94 | Template injection | YES (render) | YES (output) | hybrid | Patch at compile; inspect output as secondary |

---

## 7. Agent Output Contract

The agent must produce a structured decision object as its output. This object is the sole input to the next step (oracle implementation). No harness code is produced at this stage.

```json
{
  "q1_dangerous_sink": true,
  "q1_evidence": "parser.setFeature(feature_external_ges, True) — external entity resolution active; file/network I/O will occur on every parse call",
  "q2_observable": null,
  "q2_evidence": null,
  "q3_taint_preserved": true,
  "q3_transform_chain": "direct assignment only: headers[0] → param → bar → parseString(bar)",
  "q3_taint_state": "fully_preserved",
  "oracle_strategy": "patch_call",
  "confidence": "high"
}
```

**Field rules:**

- `q2_*` fields are `null` when Q1 is YES — Q2 was not evaluated and must not be inferred
- `oracle_strategy` must be one of: `patch_call`, `inspect_return`, `hybrid`
- `q3_taint_state` must be one of: `fully_preserved`, `transformed`, `encoded`, `destroyed`
- `confidence` must be one of: `high`, `medium`, `low`
- When `confidence` is `low`, the agent **must not proceed** to oracle implementation — escalate for human review

---

## 8. Known Decision Ambiguities

These are cases where the three questions do not yield a clean answer and the agent must apply the documented fallback.

| Case | Ambiguity | Fallback |
|---|---|---|
| SQL injection — read query | Q1 is NO but Q2 signal is weak (row count depends on DB state) | Default to `patch_call`; note in `q2_evidence` that signal is marginal |
| Command injection via `subprocess.run(capture_output=True)` | Q1 is YES (shell exec) but stdout is also observable | `patch_call` takes precedence — Q1 YES always wins |
| Template injection (Jinja2) | Q1 YES at render; Q2 YES on output | `hybrid` — patch at compile time, inspect output as secondary signal |
| Function returns `None` | Q2 cannot be evaluated from return value | Treat as NO → `patch_call` |
| Taint state is `destroyed` | Q3 signals oracle is unreliable regardless of strategy | Set `confidence: low`; escalate |

---

## 9. Out of Scope

The following bug classes are structurally incompatible with both oracle strategies and are explicitly excluded:

| CWE | Reason |
|---|---|
| CWE-362 Race condition | Non-deterministic; requires thread scheduling control |
| CWE-208 Timing attack | Statistical signal; single execution is insufficient |
| CWE-327 Weak cryptography | Insecurity is latent; not detectable from output at runtime |
| Stored XSS | Requires a read-write cycle across a persistence boundary |
| DOM XSS | No server-side response to inspect; requires browser execution |
| Second-order injection (any) | Taint broken by storage round-trip; single-execution oracle cannot confirm |