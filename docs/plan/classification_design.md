## Plan: Oraculum Classification Stage

**TL;DR** - Add an `oraculum classify` command between `ingest` and `oracle`. It reads enriched findings from ingest, derives a compact `returns` signal from source when possible, asks the LLM to choose one of the new README strategies, and writes a per-finding classification artifact under `output/python/<repo>/classifications/`. This stage does not generate oracle specs, does not generate harness code, and does not decide trigger regexes.

## Goal

The new pipeline is:

```text
VulnHunterX verify
  -> oraculum ingest
  -> oraculum classify
  -> oraculum oracle
  -> oraculum harness
```

Classification is responsible for strategy selection only:

```json
{
  "strategy": "return_value | recorded_call | filesystem_state",
  "mock_guidance": {
    "required": true,
    "target": "free-form sink or patch target guidance",
    "capture": "free-form captured argument guidance",
    "fake_behavior": "free-form fake return/side-effect guidance",
    "notes": ["free-form implementation notes"]
  }
}
```

`mock_guidance` replaces the older `mock_type` idea. It is not an enum. The agent should explain what to mock and how to keep execution safe/observable, using the provided evidence.

## Non-Goals

- Do not generate Atheris harness code.
- Do not generate final oracle trigger patterns.
- Do not mutate VulnHunterX output.
- Do not require full function body in the LLM prompt.
- Do not refactor the existing `oracle` and `harness` stages in this first step, except for future-compatible path/status contracts.

## Strategy Contract

### `recorded_call`

Use when either:

- Q1 is YES: executing the sink is dangerous in a fuzzing test environment.
- Q2 is NO: the violation is not observable after the function returns.

This strategy means a later stage should mock or patch a sink, record what reaches it, and inspect the recorded argument.

`mock_guidance` must be present for `recorded_call`.

Examples:

- SSRF: record URL passed to `requests.get`.
- Command injection: record command passed to `subprocess.run` or `os.system`.
- SQL read/write where the query string is the best signal: record SQL passed to `cursor.execute`.
- XXE where parser execution may resolve external entities: record parser input or resolver interaction when feasible.

### `return_value`

Use when:

- Q1 is NO: executing the sink is acceptable in the test environment.
- Q2 is YES: the violation is observable after the target function returns.
- Q3 is YES: the relevant result is accessible in memory from the return value or returned object.

This strategy means a later stage should call the target function and inspect the returned value or in-memory response object.

`mock_guidance` must be `null`.

Examples:

- Open redirect returning an unsafe URL.
- Reflected XSS returning unsafe HTML.
- Response splitting returning unsafe header text.
- Path traversal returning the constructed path string.

### `filesystem_state`

Use when:

- Q1 is NO: executing the sink is acceptable when sandboxed.
- Q2 is YES: the violation is observable after execution.
- Q3 is NO: the signal is not in memory, but can be observed on disk.

This strategy means a later stage should run the target inside a controlled temporary filesystem context and inspect created/modified paths after return.

`mock_guidance` must be `null` unless the classifier needs to mention optional sandboxing notes. If notes are needed, put them in `warnings`, not `mock_guidance`.

Examples:

- Path traversal where the function writes a file and returns `None`.
- Unsafe archive extraction where created files can be inspected under a temporary directory.

## Decision Procedure

The system prompt should enforce the README decision tree:

```text
Q1. Is executing the sink dangerous in a test environment?
    YES -> strategy = recorded_call
    NO  -> Q2

Q2. Is the violation observable after the function returns?
    NO  -> strategy = recorded_call
    YES -> Q3

Q3. Is the result accessible in memory on return?
    YES -> strategy = return_value
    NO  -> strategy = filesystem_state
```

Rules:

- Ground every answer in `verification.data_flow`, `verification.answers`, `verification.reasoning`, and the derived `returns` signal.
- Do not classify from CWE or `rule_id` alone.
- If evidence is ambiguous, still choose the safest strategy, usually `recorded_call`, and set `confidence` to `low`.
- If taint appears destroyed by hashing/encryption/irreversible transformation, set `confidence` to `low` and explain in `warnings`.

## Input Fields

Classification consumes enriched finding artifacts written by ingest:

```text
output/python/<repo>/verification_results/summary.json
output/python/<repo>/verification_results/findings/finding_<id>_<rule_slug>.json
```

For each finding, build a minimal normalized prompt payload. The LLM does not
need the full enriched artifact for classification:

```json
{
  "rule_id": "py/xxe",
  "function_name": "target_function",
  "data_flow": "source -> transform -> sink",
  "answers": {},
  "reasoning": "verification reasoning",
  "returns": {
    "kind": "value | none | mixed | unknown",
    "exprs": ["return expression text"]
  }
}
```

The stage still needs the full artifact internally for path resolution,
target-id generation, status output, and source lookup. Those fields should not
be sent to the classifier prompt unless a later experiment shows they improve
accuracy.

The prompt should preserve `verification.answers` whether it is a list or an
object. Current code paths should not assume `answers` is only a list.

## Derived `returns` Signal

Add a deterministic helper before the LLM call:

```text
src/oraculum/classification/returns.py
```

Responsibilities:

1. Resolve source path:

   ```text
   <artifact.source.vhx_repo_root>/<artifact.function.file>
   ```

2. Parse the file with `ast`.

3. Locate the function by `function.name` and line range.

4. Inspect `return` statements in the target function body. Ignore returns
   inside nested functions, nested classes, and lambdas.

   - no `return` or only `return None` -> `kind: "none"`
   - only non-None returns -> `kind: "value"`
   - both None and non-None returns -> `kind: "mixed"`
   - parse/file lookup failure -> `kind: "unknown"`

5. Record `exprs` using `ast.unparse` for explicit return expressions.

### `returns.kind`

`returns.kind` is a compact summary of the target function's syntactic return
shape:

- `value`: the analyzer found one or more explicit return expressions that
  return an in-memory value, and found no explicit `return None` / bare
  `return`.
- `none`: the analyzer found no in-memory return expression. This includes no
  explicit return, bare `return`, and `return None`.
- `mixed`: the analyzer found both in-memory return expressions and explicit
  None-like returns.
- `unknown`: source parsing, source lookup, or function lookup failed.

Why it is needed:

- Q3 asks whether the result is accessible in memory on return.
- `data_flow`, `answers`, and `reasoning` often describe the sink but not the
  function's return shape.
- Without this signal, the classifier can confuse `return_value` and
  `filesystem_state`, especially for path traversal and write-file cases.

Accuracy:

- This signal is deterministic and high-precision for syntactic return
  expressions when the source file parses and the function is matched by name
  and line range.
- It is not a semantic proof that every runtime path returns a value, and it
  does not prove that the returned value contains the vulnerable data.
- If the analyzer cannot be confident, it must use `unknown` rather than guess.
- The LLM must treat `returns` as Q3 evidence only. Q1 and Q2 still come from
  `data_flow`, `answers`, and `reasoning`.

### `returns.exprs`

`returns.exprs` is a short list of explicit return expressions from the target
function, rendered with `ast.unparse`.

Examples:

```json
{ "kind": "value", "exprs": ["redirect_url"] }
{ "kind": "none", "exprs": [] }
{ "kind": "mixed", "exprs": ["None", "response"] }
{ "kind": "unknown", "exprs": [] }
```

Why it is needed:

- It lets the classifier see what kind of value is returned without seeing the
  full function body.
- It gives stronger evidence than `kind` alone when the expression is obvious,
  for example `return path`, `return response`, or `return rendered_html`.
- It keeps the prompt small while making Q3 less guessy.

## System Prompt

Add:

```text
config/prompts/classification_system.txt
```

Draft:

```text
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
```

## User Prompt

Add:

```text
config/prompts/classification_user.txt
```

Responsibilities:

- The user prompt is per-finding and data-only.
- It should not restate the strategy decision tree except for a short command
  to classify the provided input.
- It should not include the full enriched artifact.
- It should contain exactly one serialized `classification_payload_json`
  generated by `prompt_builder.py`.

Prompt payload fields:

```json
{
  "rule_id": "py/xxe",
  "function_name": "BenchmarkTest00460_post",
  "data_flow": "request header -> bar -> xml.dom.minidom.parseString(bar, parser)",
  "answers": {
    "sink_identity": "xml.dom.minidom.parseString() with attacker-controlled XML",
    "sanitization_absent": "No XML hardening is applied",
    "exploit_possible": "External entity declaration can be supplied"
  },
  "reasoning": "The verified finding reasoning from VulnHunterX",
  "returns": {
    "kind": "none",
    "exprs": []
  }
}
```

Draft template:

````text
## Classification Input

```json
{classification_payload_json}
```

Classify this finding using the three-question decision procedure from the
system prompt. Output strict JSON only.
````

Implementation notes:

- `classification_payload_json` must be formatted with `json.dumps(..., indent=2, ensure_ascii=False)`.
- `answers` must preserve the original shape from `verification.answers`; it may be a dict, list, string, or null.
- `reasoning` comes from `verification.reasoning`.
- `data_flow` comes from `verification.data_flow`.
- `function_name` comes from `artifact.function.name`.
- `returns` comes from `classification.returns`.

## Output Schema

Required per-finding classification artifact:

```json
{
  "schema_version": "1.0",
  "strategy": "recorded_call",
  "decision": {
    "q1_sink_dangerous": {
      "answer": true,
      "evidence": "parseString receives attacker-controlled XML and may resolve external entities"
    },
    "q2_observable_after_return": {
      "answer": null,
      "evidence": "not evaluated because Q1 was true"
    },
    "q3_result_in_memory": {
      "answer": null,
      "evidence": "not evaluated because Q1 was true"
    }
  },
  "mock_guidance": {
    "required": true,
    "target": "xml.dom.minidom.parseString if this is the call used by the target module",
    "capture": "record the XML string argument that receives tainted request data",
    "fake_behavior": "return a minimal DOM-like object or MagicMock sufficient for caller continuation",
    "notes": [
      "patch the name as used by the target module if imported under an alias",
      "do not execute real external entity resolution during fuzzing"
    ]
  },
  "confidence": "high",
  "warnings": []
}
```

Schema rules:

- `schema_version` must be `"1.0"`.
- `strategy` must be one of:

  ```text
  return_value
  recorded_call
  filesystem_state
  ```

- `decision.q1_sink_dangerous.answer`, `decision.q2_observable_after_return.answer`, and `decision.q3_result_in_memory.answer` must be `true`, `false`, or `null`.
- `mock_guidance` must be non-null only when `strategy == "recorded_call"`.
- `mock_guidance.required` must be `true` for `recorded_call`.
- `confidence` must be `high`, `medium`, or `low`.
- `warnings` must be a list of strings.

## Output Layout

Write classification artifacts to:

```text
output/python/<repo>/classifications/
  status.json
  <target_id>.json
```

Use the same `target_id` helper as oracle/harness:

```text
<rule_slug>_<file_slug>_<line>
```

Example status:

```json
{
  "stage": "classification",
  "repo": "Benchmark",
  "lang": "python",
  "model": "anthropic/claude-sonnet-4-5",
  "config": "config/classification.yaml",
  "source": {
    "ingest_summary_path": "output/python/Benchmark/verification_results/summary.json"
  },
  "counts": {
    "selected": 2,
    "generated": 2,
    "skipped": 0,
    "failed": 0
  },
  "classifications": [
    {
      "id": "0",
      "target_id": "py_xxe_testcode_BenchmarkTest00460_py_58",
      "rule_id": "py/xxe",
      "file": "testcode/BenchmarkTest00460.py",
      "start_line": "58",
      "function_name": "BenchmarkTest00460_post",
      "finding_artifact": "output/python/Benchmark/verification_results/findings/finding_0_py_xxe.json",
      "classification": "output/python/Benchmark/classifications/py_xxe_testcode_BenchmarkTest00460_py_58.json",
      "status": "generated",
      "strategy": "recorded_call",
      "confidence": "high"
    }
  ],
  "errors": []
}
```

## CLI Contract

Add:

```bash
oraculum classify \
  --repo Benchmark \
  --lang python
```

Arguments:

- `--repo`: required repository name.
- `--lang`: default `python`, only `python` initially.
- `--output-dir`: default `output`.
- `--ingest-summary`: explicit ingest summary path. Default: `output/<lang>/<repo>/verification_results/summary.json`.
- `--finding-id`: classify one ingest finding id.
- `--finding`: classify one explicit enriched finding JSON path.
- `--config`: default `config/classification.yaml`.
- `--model`: override model.
- `--force`: overwrite existing classification JSON.
- `--log-file`: optional Markdown audit log with system prompt, user prompt, and raw LLM response.

Model resolution should match current oracle/harness behavior:

```text
--model
LLM_PROVIDER + LLM_MODEL -> "<provider>/<model>"
LLM_MODEL
config/classification.yaml model
```

Load `.env` before model resolution and do not override exported shell variables.

CLI output:

```text
Generate Oraculum classifications
  Repo: python/Benchmark
  Ingest summary: output/python/Benchmark/verification_results/summary.json
  Model: anthropic/claude-sonnet-4-5

[1/2] py/xxe
  File: testcode/BenchmarkTest00460.py:58
  Target: py_xxe_testcode_BenchmarkTest00460_py_58
  Strategy: recorded_call

Done. selected=2 generated=2 skipped=0 failed=0
Output: output/python/Benchmark/classifications/status.json
```

## Module Layout

Add:

```text
src/oraculum/classification/
  __init__.py
  runner.py
  paths.py
  prompt_builder.py
  llm_client.py
  returns.py
```

Responsibilities:

- `runner.py`: batch orchestration, artifact selection, validation, status writing.
- `paths.py`: resolve default ingest summary and classification output paths.
- `prompt_builder.py`: load prompts and build normalized JSON payload.
- `llm_client.py`: LiteLLM call, JSON extraction, classification schema validation.
- `returns.py`: AST-derived `returns` signal.

Reuse existing helpers where possible:

- `oraculum.oracle.paths.target_id_for_artifact`
- `.env` and model resolution style from `cli.commands`
- JSON fence extraction style from `oracle.llm_client`

## Validation

The validator should reject:

- invalid JSON or non-object output
- missing `schema_version`
- unsupported strategy
- missing `decision`
- missing or invalid `confidence`
- `recorded_call` without `mock_guidance`
- `return_value` or `filesystem_state` with non-null `mock_guidance`
- non-list `warnings`

The validator should not enforce exact `mock_guidance.target` format. That field is intentionally free-form because import/patch resolution belongs to later stages.

## Overwrite Policy

Default behavior:

- If `<target_id>.json` already exists, skip and count as `skipped`.
- Always write/update `classifications/status.json` for the current run.

With `--force`:

- overwrite selected classification JSON files.
- do not delete oracle/harness artifacts.
- do not delete unrelated classification files.

## Error Handling

Each finding should fail independently. One bad LLM output must not abort the whole batch.

Failure cases:

- missing ingest summary
- missing finding artifact
- invalid enriched finding JSON
- source parse failure for `returns` analysis should not fail classification, use `returns.kind = "unknown"`
- LLM output not valid JSON
- schema validation failure

Record failures in `status.json`:

```json
{
  "id": "0",
  "target_id": "py_xxe_testcode_BenchmarkTest00460_py_58",
  "status": "failed",
  "errors": "short error message"
}
```

## Downstream Integration Plan

This stage can land before refactoring `oracle`.

Future `oracle` changes:

1. Add `--classification-status` and `--classification` inputs.
2. Require a classification artifact by default.
3. Stop asking the oracle prompt to choose strategy.
4. Route oracle research prompts by:

   ```text
   recorded_call    -> recorded-call oracle research
   return_value     -> return-value oracle research
   filesystem_state -> filesystem-state oracle research
   ```

5. Translate old internal monitor names only at the harness boundary if needed:

   ```text
   recorded_call -> patch_call
   return_value  -> inspect_return
   filesystem_state -> new filesystem-state harness support
   ```

The translation should be temporary. Long term, harness should understand the README strategy names directly.

## Tests

Add `tests/test_classification.py` with mocked LLM calls.

Unit tests:

- selects artifacts from default ingest summary.
- `--finding-id` selects one artifact.
- explicit `--finding` bypasses summary.
- existing output skips without `--force`.
- `--force` overwrites.
- parses fenced JSON response.
- rejects unsupported strategy.
- rejects `recorded_call` without `mock_guidance`.
- rejects `return_value` with non-null `mock_guidance`.
- preserves dict-shaped `verification.answers` in the prompt.
- derives `returns.kind = "value"` for a non-None return.
- derives `returns.kind = "none"` for no return or `return None`.
- derives `returns.kind = "mixed"` for mixed return paths.
- excludes nested function/class returns from `returns.exprs`.
- CLI smoke writes `classifications/status.json`.
- CLI `--log-file` writes prompts and raw response.

Verification:

```bash
python3 -m compileall -q src
pytest tests/test_classification.py
pytest
```

## Implementation Phases

### Phase 1: Files and CLI Skeleton

1. Add `classification` package.
2. Add `config/classification.yaml`.
3. Add classification prompts.
4. Add CLI subcommand in `src/oraculum/cli/main.py`.
5. Add `cmd_classify` in `src/oraculum/cli/commands.py`.

### Phase 2: Returns Analyzer

1. Implement AST function lookup by name and line range.
2. Implement return-kind extraction.
3. Implement conservative filesystem persistence heuristic.
4. Add focused tests without LLM.

### Phase 3: LLM and Schema

1. Implement prompt builder.
2. Implement LiteLLM wrapper and JSON extraction.
3. Implement strict output validation.
4. Add mocked LLM tests.

### Phase 4: Batch Runner

1. Implement default ingest summary selection.
2. Implement `--finding-id` and `--finding`.
3. Implement output writing and status aggregation.
4. Implement skip/force behavior.
5. Add CLI smoke tests.

### Phase 5: Documentation Sync

1. Update `docs/plan/architecture.md` pipeline to include classification.
2. Update `README.md` terminology only after the stage is implemented.
3. Mark old `patch_call`/`inspect_return` wording as legacy/internal until oracle is refactored.

## Decisions

- `mock_guidance` is the canonical field name.
- `mock_guidance` is structured enough for downstream stages but not an enum.
- Classification output uses README strategy names, not current internal monitor names.
- `returns` is derived deterministically before prompting.
- Full function body is not sent to the classification LLM by default.
- Ambiguous evidence should produce a low-confidence strategy instead of failing the stage.
