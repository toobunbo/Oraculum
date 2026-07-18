# Oraculum Classification Run

- Started: `2026-07-13T04:54:31`
- Repo: `python/gradio`
- Output dir: `output`

## [1/1] py/full-ssrf

- File: `gradio/image_utils.py:252`
- Target: `py_full_ssrf_gradio_image_utils_py_252`
- Artifact: `output/python/gradio/verification_results/findings/finding_1_py_full-ssrf.json`

### System Prompt

````text
ROLE
You classify ONE verified finding into a runtime oracle strategy.
You do not write harness code. You do not write oracle trigger patterns.
Output strict JSON only.

DECISION PROCEDURE
Use only these input fields:
- rule_id
- function_name
- data_flow
- answers
- reasoning
- returns

Ask exactly these three questions, in order. Stop when the decision tree
selects a strategy.

Q1. Is executing the sink dangerous in a test environment?
    Dangerous means network I/O, shell execution, DB write, RCE, unsafe parser
    external resolution, or irreversible side effects.
    YES -> strategy = recorded_call.
    NO  -> answer Q2.

Q2. Is the violation observable after the function returns?
    YES -> answer Q3.
    NO  -> strategy = recorded_call.

Q3. Is the result accessible in memory on return?
    Use returns.kind and returns.exprs as the primary evidence for this answer.
    YES -> strategy = return_value.
    NO  -> strategy = filesystem_state.

MOCK GUIDANCE
For recorded_call, provide free-form mock_guidance. This is not an enum. It
should describe what sink/call should be mocked or recorded, what argument or
state should be captured, and what fake behavior may let execution continue.
For return_value and filesystem_state, mock_guidance must be null.

RULES
- Ground every answer in data_flow, answers, reasoning, and returns. Do not
  classify from rule_id alone.
- If Q1 or Q2 is ambiguous, choose recorded_call and set confidence low.
- If Q3 is ambiguous but Q2 is clearly YES, use returns.kind:
  value or mixed -> return_value; none -> filesystem_state; unknown -> choose
  the better-supported strategy and set confidence low.
- Do not invent exact import paths unless they are present in the evidence.
- Do not output markdown or explanations outside JSON.

OUTPUT SCHEMA
Return exactly one JSON object with this shape:

{
  "schema_version": "1.0",
  "strategy": "return_value | recorded_call | filesystem_state",
  "decision": {
    "q1_sink_dangerous": {
      "answer": true,
      "evidence": "short evidence from input"
    },
    "q2_observable_after_return": {
      "answer": false,
      "evidence": "short evidence from input"
    },
    "q3_result_in_memory": {
      "answer": null,
      "evidence": "short evidence from returns"
    }
  },
  "mock_guidance": {
    "required": true,
    "target": "free-form sink/call guidance",
    "capture": "free-form captured argument/state guidance",
    "fake_behavior": "free-form fake behavior guidance",
    "notes": ["free-form implementation notes"]
  },
  "confidence": "high | medium | low",
  "warnings": []
}

For return_value and filesystem_state, mock_guidance must be null.
For recorded_call, mock_guidance must be an object with required=true.
Use JSON booleans/null only: true, false, null. Do not use YES/NO or any other strings in the "answer" fields.
````


### User Prompt

````text
## Classification Input

```json
{
  "rule_id": "py/full-ssrf",
  "function_name": "extract_svg_content",
  "data_flow": "user-provided Attribute (lines 12/13/17/21, not visible) → multiple intermediate transforms (lines 9-341, not visible) → image_file parameter (line 242) → str(image_file) (line 243) → is_http_url_like check (line 244, insufficient) → httpx.get(image_file) sink (line 252)",
  "answers": [
    "The source is user-provided input. According to the dataflow paths, the data originates from Attributes on lines 13, 21, 12, and 17 (referenced as `original_video`, `audio`, `video`, `original_image` in other parts of the file not shown here). These ultimately flow into the `image_file` parameter of `extract_svg_content`.",
    "The visible portion of the flow is: `image_file` parameter (line 242, implicit) → `image_file = str(image_file)` (line 243) → `is_http_url_like(image_file)` check (line 244) → `httpx.get(image_file)` (line 252). The upstream transformations (lines 9-341) are not visible in the provided code snippet.",
    "The only validation visible is `is_http_url_like(image_file)` on line 244. This is a regex/format check that only verifies whether the string looks like an HTTP URL. It does NOT validate the *host* portion of the URL (e.g., it does not restrict to allowed domains, block internal/private IPs like 127.0.0.1 or 10.x.x.x, or prevent SSRF targets). This is INSUFFICIENT for preventing SSRF.",
    "The sink is `httpx.get(image_file)` on line 252, where the user-controlled full URL is passed directly to an HTTP client to make a server-side request.",
    "The only visible transformation is `str(image_file)` on line 243, which is a simple type conversion. No encoding, decoding, or serialization occurs that would alter the URL semantics or bypass any URL-based checks.",
    "The `httpx` library does NOT provide automatic SSRF protections. It does not block requests to internal IP addresses or restricted domains by default. No framework-level protection is visible.",
    "Not visible in the provided context. The function signature `extract_svg_content(image_file: str | Path)` does not indicate any authentication requirements, but the callers (not shown) would determine this.",
    "Not visible in the provided context. The function appears to be a utility function in `gradio/image_utils.py`, not a test file or debug path.",
    "Server-Side Request Forgery (SSRF). An attacker can supply a URL pointing to internal services (e.g., http://169.254.169.254/latest/meta-data/ for cloud metadata, or internal APIs) and the server will make the request, potentially leading to information disclosure, internal port scanning, or remote code execution via internal services.",
    "The weakest link is the lack of host/destination validation. The `is_http_url_like` check only confirms the string is an HTTP URL format but does nothing to restrict the target host, IP address range, or scheme, leaving the `httpx.get()` call on line 252 fully controllable by the attacker."
  ],
  "reasoning": "The `extract_svg_content` function takes a user-controlled URL and passes it directly to `httpx.get()` on line 252. The only guard is `is_http_url_like()` on line 244, which merely checks URL format without restricting the target host or IP range, making this a clear Server-Side Request Forgery (SSRF) vulnerability with no adequate sanitization.",
  "returns": {
    "kind": "value",
    "exprs": [
      "response.text",
      "svg_content"
    ]
  }
}
```

Classify this finding using the three-question decision procedure from the
system prompt. Output strict JSON only.
````


### LLM Response (Iteration 1)

````text
{
  "schema_version": "1.0",
  "strategy": "recorded_call",
  "decision": {
    "q1_sink_dangerous": {
      "answer": true,
      "evidence": "The sink is httpx.get(image_file) which performs network I/O and can lead to SSRF, making it dangerous in a test environment."
    },
    "q2_observable_after_return": {
      "answer": null,
      "evidence": null
    },
    "q3_result_in_memory": {
      "answer": null,
      "evidence": null
    }
  },
  "mock_guidance": {
    "required": true,
    "target": "httpx.get() call",
    "capture": "the image_file parameter value",
    "fake_behavior": "return a mock response with safe, predefined content to prevent actual network requests",
    "notes": ["The httpx.get call should be mocked to prevent SSRF during testing", "Capture the URL being requested to verify it's not an internal/private IP"]
  },
  "confidence": "high",
  "warnings": []
}
````

- Result: `failed`
- Error: `classification.decision.q2_observable_after_return.evidence must be a string`

## Summary

- Selected: `1`
- Generated: `0`
- Skipped: `0`
- Failed: `1`
- Status: `output/python/gradio/classifications/status.json`
