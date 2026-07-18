# Oraculum Oracle Run

- Started: `2026-07-13T04:56:42`
- Repo: `python/gradio`
- Output dir: `output`

## [1/1] py/full-ssrf

- File: `gradio/image_utils.py:252`
- Target: `py_full_ssrf_gradio_image_utils_py_252`
- Artifact: `output/python/gradio/verification_results/findings/finding_1_py_full-ssrf.json`

### System Prompt

````text
You are a fuzzing oracle designer for Python security vulnerabilities specializing in sink-mocking (recorded_call) strategy.

## Task
Given a verified security finding context, target source code, and classification guidance, output the `oracle_spec` JSON that describes how an Atheris harness should mock the sink and check the payload at runtime.

Before outputting JSON, you MUST deduce the attack patterns using ONLY the provided finding data.

## Input Fields
1. rule_id        -> vulnerability class; useful secondary hint.
2. message        -> CodeQL sink/source description.
3. answers        -> pre-traced data flow describing: the tainted parameter,
                     the flow path to the sink, the absent validation, the sink
                     mechanism, and the attack scenario.
4. input_strategy -> "direct_params" | "flask_view"
5. Classification Result -> contains strategy (recorded_call) and mock_guidance.

## STEP 1: STRICT CONTEXT-DRIVEN REASONING
Do NOT rely on external knowledge. Read `message`, `answers`, and `mock_guidance` holistically.
Write a short paragraph starting with "THINKING:" and answer these 3 questions sequentially based ONLY on the input:

1. THE GOAL: What exact objective is the attacker trying to achieve according to the attack scenario in answers or message? Extract exact keywords — internal IPs, file paths, command strings, injected fragments — as mentioned in the finding.

2. THE SINK: What is the exact function executed at the end of the tainted flow, and what role does it play? Identify which argument of the sink receives the tainted payload — by index (0-based) and by keyword name if available.
   Refer to `mock_guidance` to see what sink target and argument needs to be captured.

3. THE SYNTHESIS: Given THE GOAL, THE SINK, and `mock_guidance`, what exact string snippets MUST exist in the payload when it reaches the sink argument to confirm exploitation? Be specific — derive from the bypass or missing validation described in answers.

## STEP 2: DEFINE MONITOR SPEC
The monitor strategy must be exactly `"recorded_call"`.

-> strategy        : "recorded_call"
-> patch_target    : fully qualified name of the sink as imported inside the
                     target module — NOT the stdlib canonical path.
                     GOOD: "app.db.query.cursor.execute"
                     GOOD: "server.file_handler.open"
                     BAD : "sqlite3.Cursor.execute"
                     Look at the target module imports and target source code.
-> target_arg_index: 0-based index of the sink argument that receives the
                     tainted payload. Derive from the sink call in answers and mock_guidance.
                     Example: cursor.execute(sql, params) -> sql is index 0
-> target_arg_name : keyword name of that argument in the sink's signature.
                     Example: httpx.get(url=...) -> "url"
                     Use null if the sink only accepts positional arguments.
-> trigger_patterns: regex list matching the dangerous payload that MUST
                     appear in the sink's argument to confirm exploitation.
                     Derived from THE SYNTHESIS. MUST NOT BE EMPTY.

## trigger_patterns Rules
- ALWAYS populate trigger_patterns with valid Python regex.
- Each entry MUST be a valid Python regex — test mentally:
  re.search(pattern, some_string) must be able to return a match object.
- Patterns match what the tainted payload looks like when it reaches the sink argument.
- Include encoding or case variants ONLY when the finding explicitly describes them.
- NEVER copy a description sentence into the array.
- NEVER use ".*" as a standalone pattern.
- NEVER derive patterns from rule_id alone.

## STEP 2.5: FUZZ GUIDANCE
Based on THE SYNTHESIS from Step 1, populate fuzz_guidance:

- seed_corpus   : 3-6 concrete string examples that would trigger the
                  vulnerability. Each seed MUST match at least one
                  trigger_pattern. Derive directly from the attack scenario
                  and bypass patterns described in answers.
- skip_condition: A single Python boolean expression using the tainted param
                  name that returns True when the input is irrelevant and the
                  harness should skip early. Write it so that
                  `if skip_condition: return` is valid Python inside
                  TestOneInput.
                  Use "False" if all inputs are potentially relevant.

## Output Schema
Return exactly one JSON object with this shape:
{
  "monitor": {
    "strategy": "recorded_call",
    "patch_target": "<fully.qualified.name of sink to patch>",
    "target_arg_index": <0-based int>,
    "target_arg_name": "<keyword name or null>",
    "capture_what": "<describe what is captured: e.g. path passed to open>",
    "additional_imports": ["<module if needed, else []>"]
  },
  "oracle_check": {
    "condition_description": "<precise boolean condition that confirms exploitation>",
    "trigger_patterns": ["<regex — MUST NOT BE EMPTY>"],
    "raise_type": "RuntimeError",
    "raise_message_template": "<RULE_ID_UPPER: short description — captured={captured} pattern={matched_pattern}>"
  },
  "fuzz_guidance": {
    "seed_corpus": ["<concrete exploit string>", "..."],
    "skip_condition": "<python boolean expression or 'False'>"
  },
  "_meta": {
    "function": "<function_name>",
    "file": "<file path>",
    "input_strategy": "<direct_params | flask_view>",
    "function_signature": "<def function_name(params with types)>",
    "tainted_params": [
      {
        "name": "<param name>",
        "index": <int>,
        "type": "<type>"
      }
    ]
  }
}
````


### User Prompt

````text
## Security Finding

{
  "id": "1",
  "rule_slug": "py_full-ssrf",
  "source": {
    "vhx_root": "/home/trieudai/VulnHunterX",
    "vhx_repo_root": "/home/trieudai/VulnHunterX/repos/python/gradio",
    "vhx_output_root": "/home/trieudai/VulnHunterX/output/python/gradio",
    "summary_path": "/home/trieudai/VulnHunterX/output/python/gradio/verification_results/summary_gradio_20260521_072136.json"
  },
  "finding": {
    "rule_id": "py/full-ssrf",
    "message": "The full URL of this request depends on a [user-provided value](1).\nThe full URL of this request depends on a [user-provided value](2).\nThe full URL of this request depends on a [user-provided value](3).\nThe full URL of this request depends on a [user-provided value](4).\nThe full URL of this request depends on a [user-provided value](5).\nThe full URL of this request depends on a [user-provided value](6).\nThe full URL of this request depends on a [user-provided value](7).\nThe full URL of this request depends on a [user-provided value](8).\nThe full URL of this request depends on a [user-provided value](9).\nThe full URL of this request depends on a [user-provided value](10).",
    "file": "gradio/image_utils.py",
    "start_line": 252,
    "end_line": 252,
    "repo_name": "gradio",
    "lang": "python",
    "sarif_path": "/home/trieudai/VULNHUNTER_CLONE/VulnHunterX/output/python/gradio/gradio.sarif",
    "tool": "CodeQL",
    "dataflow_path": [
      "--- Flow 1 ---",
      "line 13: ControlFlowNode for Attribute()",
      "line 9: ControlFlowNode for original_video",
      "line 10: ControlFlowNode for original_video",
      "line 64: ControlFlowNode for value",
      "line 188: ControlFlowNode for value",
      "line 378: ControlFlowNode for kwargs [Dictionary element at key value]",
      "line 379: ControlFlowNode for kwargs [Dictionary element at key value]",
      "line 135: ControlFlowNode for value",
      "line 207: ControlFlowNode for value",
      "line 243: ControlFlowNode for value",
      "line 248: ControlFlowNode for load_fn",
      "line 252: ControlFlowNode for Tuple",
      "line 207: ControlFlowNode for Attribute()",
      "line 207: ControlFlowNode for initial_value",
      "line 208: ControlFlowNode for initial_value",
      "line 212: ControlFlowNode for value",
      "line 221: ControlFlowNode for value",
      "line 324: ControlFlowNode for value",
      "line 341: ControlFlowNode for value",
      "line 242: ControlFlowNode for image_file",
      "line 250: ControlFlowNode for image_file",
      "line 252: ControlFlowNode for image_file",
      "--- Flow 2 ---",
      "line 21: ControlFlowNode for Attribute()",
      "line 11: ControlFlowNode for audio",
      "line 15: ControlFlowNode for audio",
      "line 84: ControlFlowNode for value",
      "line 205: ControlFlowNode for value",
      "line 405: ControlFlowNode for kwargs [Dictionary element at key value]",
      "line 406: ControlFlowNode for kwargs [Dictionary element at key value]",
      "line 135: ControlFlowNode for value",
      "line 207: ControlFlowNode for value",
      "line 243: ControlFlowNode for value",
      "line 248: ControlFlowNode for load_fn",
      "line 252: ControlFlowNode for Tuple",
      "line 207: ControlFlowNode for Attribute()",
      "line 207: ControlFlowNode for initial_value",
      "line 208: ControlFlowNode for initial_value",
      "line 212: ControlFlowNode for value",
      "line 221: ControlFlowNode for value",
      "line 324: ControlFlowNode for value",
      "line 341: ControlFlowNode for value",
      "line 242: ControlFlowNode for image_file",
      "line 250: ControlFlowNode for image_file",
      "line 252: ControlFlowNode for image_file",
      "--- Flow 3 ---",
      "line 12: ControlFlowNode for Attribute()",
      "line 4: ControlFlowNode for video",
      "line 7: ControlFlowNode for video",
      "line 64: ControlFlowNode for value",
      "line 188: ControlFlowNode for value",
      "line 378: ControlFlowNode for kwargs [Dictionary element at key value]",
      "line 379: ControlFlowNode for kwargs [Dictionary element at key value]",
      "line 135: ControlFlowNode for value",
      "line 207: ControlFlowNode for value",
      "line 243: ControlFlowNode for value",
      "line 248: ControlFlowNode for load_fn",
      "line 252: ControlFlowNode for Tuple",
      "line 207: ControlFlowNode for Attribute()",
      "line 207: ControlFlowNode for initial_value",
      "line 208: ControlFlowNode for initial_value",
      "line 212: ControlFlowNode for value",
      "line 221: ControlFlowNode for value",
      "line 324: ControlFlowNode for value",
      "line 341: ControlFlowNode for value",
      "line 242: ControlFlowNode for image_file",
      "line 250: ControlFlowNode for image_file",
      "line 252: ControlFlowNode for image_file",
      "--- Flow 4 ---",
      "line 17: ControlFlowNode for Attribute()",
      "line 13: ControlFlowNode for original_image",
      "line 14: ControlFlowNode for original_image",
      "line 57: ControlFlowNode for value",
      "line 182: ControlFlowNode for value",
      "line 405: ControlFlowNode for kwargs [Dictionary element at key value]",
      "line 406: ControlFlowNode for kwargs [Dictionary element at key value]",
      "line 135: ControlFlowNode for value",
      "line 207: ControlFlowNode for value",
      "line 243: ControlFlowNode for value",
      "line 248: ControlFlowNode for load_fn",
      "line 252: ControlFlowNode for Tuple",
      "line 207: ControlFlowNode for Attribute()",
      "line 207: ControlFlowNode for initial_value",
      "line 208: ControlFlowNode for initial_value",
      "line 212: ControlFlowNode for value",
      "line 221: ControlFlowNode for value",
      "line 324: ControlFlowNode for value",
      "line 341: ControlFlowNode for value",
      "line 242: ControlFlowNode for image_file",
      "line 250: ControlFlowNode for image_file",
      "line 252: ControlFlowNode for image_file"
    ],
    "severity": "9.1",
    "precision": "high",
    "cwe_ids": [],
    "tags": [
      "security",
      "external/cwe/cwe-918"
    ],
    "related_locations": []
  },
  "verification": {
    "cached_input_tokens": 0,
    "timestamp": "2026-05-21T07:20:22.345208",
    "tokens_used": 4782,
    "output_tokens": 825,
    "confidence": "High",
    "verdict": "True Positive",
    "reasoning": "The `extract_svg_content` function takes a user-controlled URL and passes it directly to `httpx.get()` on line 252. The only guard is `is_http_url_like()` on line 244, which merely checks URL format without restricting the target host or IP range, making this a clear Server-Side Request Forgery (SSRF) vulnerability with no adequate sanitization.",
    "model": "glm-5-turbo",
    "elapsed_seconds": 70.33487272262573,
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
    "iterations": 1,
    "cost_usd": 0.0,
    "data_flow": "user-provided Attribute (lines 12/13/17/21, not visible) → multiple intermediate transforms (lines 9-341, not visible) → image_file parameter (line 242) → str(image_file) (line 243) → is_http_url_like check (line 244, insufficient) → httpx.get(image_file) sink (line 252)",
    "input_tokens": 3957,
    "context_needed": [],
    "confidence_score": 0.95
  },
  "function": {
    "name": "extract_svg_content",
    "file": "gradio/image_utils.py",
    "start_line": 242,
    "end_line": 258,
    "scope": ""
  },
  "web_params": []
}

## Answers (pre-traced data flow)

- The source is user-provided input. According to the dataflow paths, the data originates from Attributes on lines 13, 21, 12, and 17 (referenced as `original_video`, `audio`, `video`, `original_image` in other parts of the file not shown here). These ultimately flow into the `image_file` parameter of `extract_svg_content`.
- The visible portion of the flow is: `image_file` parameter (line 242, implicit) → `image_file = str(image_file)` (line 243) → `is_http_url_like(image_file)` check (line 244) → `httpx.get(image_file)` (line 252). The upstream transformations (lines 9-341) are not visible in the provided code snippet.
- The only validation visible is `is_http_url_like(image_file)` on line 244. This is a regex/format check that only verifies whether the string looks like an HTTP URL. It does NOT validate the *host* portion of the URL (e.g., it does not restrict to allowed domains, block internal/private IPs like 127.0.0.1 or 10.x.x.x, or prevent SSRF targets). This is INSUFFICIENT for preventing SSRF.
- The sink is `httpx.get(image_file)` on line 252, where the user-controlled full URL is passed directly to an HTTP client to make a server-side request.
- The only visible transformation is `str(image_file)` on line 243, which is a simple type conversion. No encoding, decoding, or serialization occurs that would alter the URL semantics or bypass any URL-based checks.
- The `httpx` library does NOT provide automatic SSRF protections. It does not block requests to internal IP addresses or restricted domains by default. No framework-level protection is visible.
- Not visible in the provided context. The function signature `extract_svg_content(image_file: str | Path)` does not indicate any authentication requirements, but the callers (not shown) would determine this.
- Not visible in the provided context. The function appears to be a utility function in `gradio/image_utils.py`, not a test file or debug path.
- Server-Side Request Forgery (SSRF). An attacker can supply a URL pointing to internal services (e.g., http://169.254.169.254/latest/meta-data/ for cloud metadata, or internal APIs) and the server will make the request, potentially leading to information disclosure, internal port scanning, or remote code execution via internal services.
- The weakest link is the lack of host/destination validation. The `is_http_url_like` check only confirms the string is an HTTP URL format but does nothing to restrict the target host, IP address range, or scheme, leaving the `httpx.get()` call on line 252 fully controllable by the attacker.

## Target Function Signature

def extract_svg_content(image_file: str | Path)

## Input Strategy: direct_params

Produce oracle_spec JSON only.


## Classification Result
- Strategy: recorded_call
- Mock Guidance: {
  "required": true,
  "target": "httpx.get() call",
  "capture": "the image_file parameter value",
  "fake_behavior": "return a mock response with safe, predefined content to prevent actual network requests",
  "notes": [
    "The httpx.get call should be mocked to prevent SSRF during testing",
    "Capture the URL being requested to verify it's not an internal/private IP"
  ]
}
````


### LLM Response (Iteration 1)

````text
{
  "monitor": {
    "strategy": "recorded_call",
    "patch_target": "httpx.get",
    "target_arg_index": 0,
    "target_arg_name": "url",
    "capture_what": "URL passed to httpx.get",
    "additional_imports": []
  },
  "oracle_check": {
    "condition_description": "URL matches SSRF attack patterns targeting internal services or metadata endpoints",
    "trigger_patterns": [
      "http://169\\.254\\.169\\.254.*",
      "http://127\\.0\\.0\\.1.*",
      "http://localhost.*",
      "http://\\[::1\\].*",
      "http://10\\.\\d+\\.\\d+\\.\\d+.*",
      "http://172\\.(1[6-9]|2\\d|3[01])\\.\\d+\\.\\d+.*",
      "http://192\\.168\\.\\d+\\.\\d+.*"
    ],
    "raise_type": "RuntimeError",
    "raise_message_template": "PY_FULL-SSRF: SSRF attempt detected - captured={captured} pattern={matched_pattern}"
  },
  "fuzz_guidance": {
    "seed_corpus": [
      "http://169.254.169.254/latest/meta-data/",
      "http://127.0.0.1:8080/admin",
      "http://localhost:22/.ssh/id_rsa",
      "http://10.0.0.1:80/internal",
      "http://192.168.1.1:3306/db"
    ],
    "skip_condition": "False"
  },
  "_meta": {
    "function": "extract_svg_content",
    "file": "gradio/image_utils.py",
    "input_strategy": "direct_params",
    "function_signature": "def extract_svg_content(image_file: str | Path)",
    "tainted_params": [
      {
        "name": "image_file",
        "index": 0,
        "type": "str | Path"
      }
    ]
  }
}
````

- Result: `generated`
- Strategy: `recorded_call`

## Summary

- Selected: `1`
- Generated: `1`
- Skipped: `0`
- Failed: `0`
- Status: `output/python/gradio/fuzz_oracles/status.json`
