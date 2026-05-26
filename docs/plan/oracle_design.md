## Plan: Oraculum Oracle Stage

**TL;DR** - Add an `oraculum oracle` command that reads Oraculum ingest artifacts, builds a context-only prompt from verified finding evidence, asks the LLM for structured runtime oracle JSON, validates the spec strictly, and writes per-finding oracle artifacts under `output/python/<repo>/fuzz_oracles/`. The stage does not rerun VulnHunterX, does not need function body in the prompt, and does not generate or run fuzz harnesses.

**Steps**

### Phase 1: Oracle Module Contract

1. Refactor the prototype oracle code into a stage runner with this module shape:
   ```text
   src/oraculum/
   ├── oracle/
   │   ├── __init__.py
   │   ├── runner.py           # Orchestrates oracle generation
   │   ├── paths.py            # Resolves ingest and oracle output paths
   │   ├── prompt_builder.py   # Builds system/user prompts
   │   ├── llm_client.py       # LiteLLM call and JSON extraction
   │   ├── schema.py           # oracle_spec validation
   │   └── signature.py        # Builds lightweight function signature
   └── cli/
       ├── main.py
       └── commands.py
   ```

2. Keep the stage independent from VulnHunterX imports. Oracle consumes Oraculum ingest JSON and references VulnHunterX paths already captured in the ingest artifact.

3. Update the old prototype assumption:
   ```text
   old: finding.function_name
   new: artifact.function.name
   ```
   The VulnHunterX `finding` object must remain unchanged.

4. Keep Stage 1 prompt inputs limited to:
   - original `finding`
   - `verification` evidence from VulnHunterX
   - enriched `function` metadata from ingest
   - lightweight function signature and input strategy

5. Do not include full function body in the oracle prompt. If the implementation needs source access, use it only to derive a compact function signature.

### Phase 2: CLI Contract

6. Implement:
   ```bash
   oraculum oracle \
     --repo Benchmark \
     --lang python
   ```

7. Required args:
   - `--repo`: repo name under Oraculum output.
   - `--lang`: initially only `python`.

8. Optional args:
   - `--output-dir`: Oraculum output root. Default: `output`.
   - `--ingest-summary`: explicit ingest `summary.json`. Default: `output/<lang>/<repo>/verification_results/summary.json`.
   - `--finding-id`: generate oracle for one ingest finding id only.
   - `--finding`: explicit enriched finding JSON path. Useful for debugging.
   - `--config`: oracle config path. Default: `config/oracle.yaml`.
   - `--model`: override model for this run.
   - `--force`: overwrite existing oracle JSON.

9. Model resolution precedence:
   ```text
   --model
   LLM_PROVIDER + LLM_MODEL -> "<provider>/<model>"
   LLM_MODEL
   config/oracle.yaml model
   ```

10. Load `.env` before resolving LLM env vars. Do not override variables already exported in the shell.

11. CLI output should be compact:
   ```text
   Generate Oraculum oracle specs
     Repo: python/Benchmark
     Ingest summary: output/python/Benchmark/verification_results/summary.json
     Model: anthropic/claude-sonnet-4-5

   Done. selected=2 generated=2 skipped=0 failed=0
   Output: output/python/Benchmark/fuzz_oracles/status.json
   ```

### Phase 3: Input Artifact Resolution

12. Resolve default input:
   ```text
   output/python/<repo>/verification_results/summary.json
   ```

13. Read selected finding artifact paths from:
   ```json
   {
     "findings": [
       {
         "id": "0",
         "rule_id": "py/xxe",
         "artifact": "output/python/Benchmark/verification_results/findings/finding_0_py_xxe.json",
         "function_name": "BenchmarkTest00460_post"
       }
     ]
   }
   ```

14. If `--finding-id` is provided, select only the matching ingest finding.

15. If `--finding` is provided, bypass ingest summary selection and process only that file.

16. Validate each enriched finding artifact contains:
   - `id`
   - `rule_slug`
   - `source.vhx_repo_root`
   - `source.vhx_output_root`
   - `finding.rule_id`
   - `finding.file`
   - `finding.start_line`
   - `verification.verdict`
   - `verification.reasoning`
   - `function.name`
   - `function.file`
   - `function.start_line`
   - `function.end_line`

### Phase 4: Signature and Input Strategy

17. Build a compact target signature for the prompt. Preferred order:
   - parse the target Python file with `ast` and find the function by `function.name` and line range;
   - fallback to `def <function.name>(*args, **kwargs)` if AST parsing fails.

18. Source path comes from:
   ```text
   <artifact.source.vhx_repo_root>/<artifact.function.file>
   ```

19. The signature builder should include:
   - positional parameters
   - keyword-only parameters
   - default markers where easy to preserve
   - `*args` and `**kwargs`
   - simple annotations when present

20. Exclude `self` and `cls` from the fuzz-facing signature used for tainted parameter indexing. The harness stage can reintroduce object construction later.

21. Derive `input_strategy`:
   ```text
   direct_params  -> target function has at least one fuzz-facing parameter
   flask_view     -> no fuzz-facing parameter and function scope/class context indicates a framework view
   direct_params  -> fallback when uncertain
   ```

22. Do not require a function signatures CSV for Stage 1. VulnHunterX Python output may not provide it consistently.

### Phase 5: Prompt Construction

23. Reuse:
   ```text
   config/prompts/oracle_system.txt
   config/prompts/oracle_user.txt
   ```

24. Build the user prompt from a normalized payload:
   ```json
   {
     "id": "0",
     "rule_slug": "py_xxe",
     "finding": {},
     "verification": {},
     "function": {},
     "signature": "def target(user_input: str)",
     "input_strategy": "direct_params"
   }
   ```

25. Pass `verification.answers` as the primary pre-traced data-flow evidence. If `answers` is empty, include:
   - `verification.reasoning`
   - `verification.data_flow`
   - `finding.dataflow_path`
   - `finding.related_locations`

26. Prompt rule: the LLM must derive trigger patterns from finding evidence, not from `rule_id` alone.

27. Keep temperature deterministic by default:
   ```yaml
   temperature: 0.0
   ```

### Phase 6: Oracle Spec Schema

28. Required output file:
   ```text
   output/python/<repo>/fuzz_oracles/<rule_slug>_<file_slug>_<line>.json
   ```

29. Required top-level shape:
   ```json
   {
     "schema_version": "1.0",
     "monitor": {
       "strategy": "patch_call",
       "patch_target": "module.object.sink",
       "target_arg_index": 0,
       "target_arg_name": null,
       "capture_what": "sink argument",
       "additional_imports": []
     },
     "oracle_check": {
       "condition_description": "dangerous payload reaches the sink",
       "trigger_patterns": ["regex"],
       "raise_type": "RuntimeError",
       "raise_message_template": "PY_XXE: captured={captured} pattern={matched_pattern}"
     },
     "fuzz_guidance": {
       "seed_corpus": ["payload"],
       "skip_condition": "False"
     },
     "_meta": {
       "ingest_id": "0",
       "rule_id": "py/xxe",
       "rule_slug": "py_xxe",
       "repo": "Benchmark",
       "lang": "python",
       "function": "target",
       "file": "pkg/app.py",
       "input_strategy": "direct_params",
       "function_signature": "def target(user_input: str)",
       "tainted_params": [
         {
           "name": "user_input",
           "index": 0,
           "type": "str"
         }
       ],
       "model": "anthropic/claude-sonnet-4-5",
       "source_finding_artifact": "output/python/Benchmark/verification_results/findings/finding_0_py_xxe.json"
     }
   }
   ```

30. Supported monitor strategies:
   ```text
   inspect_return
   patch_call
   catch_exception
   ```

31. Strategy semantics:
   - `patch_call`: vulnerability is confirmed by inspecting a side-effect sink argument.
   - `inspect_return`: vulnerability is confirmed by inspecting the target function return value.
   - `catch_exception`: vulnerability is confirmed only by a catchable exception.

32. `trigger_patterns` rules:
   - required and non-empty for `patch_call`;
   - required and non-empty for `inspect_return`;
   - must be empty for `catch_exception`;
   - every pattern must compile with Python `re.compile`.

33. `fuzz_guidance.seed_corpus` rules:
   - required for `patch_call` and `inspect_return`;
   - should contain 3-6 concrete payloads when possible;
   - each seed should match at least one trigger pattern unless the context makes that impossible.

34. `fuzz_guidance.skip_condition` must parse as a Python expression. Use `"False"` when no cheap skip is known.

### Phase 7: LLM Call and JSON Parsing

35. Use LiteLLM through a thin wrapper:
   ```python
   completion(
       model=model,
       messages=[
           {"role": "system", "content": system_prompt},
           {"role": "user", "content": user_prompt},
       ],
       temperature=temperature,
       max_tokens=max_tokens,
       timeout=timeout,
   )
   ```

36. Parse LLM output in this order:
   - JSON fenced block;
   - first balanced JSON object;
   - fail with a clear parse error.

37. Preserve raw LLM output only when debugging is enabled later. Initial implementation should not write raw prompt/response by default because prompts may include sensitive source or finding evidence.

38. Add a retry only for parse/schema failure if needed later. Initial implementation should fail fast and record the error in oracle summary.

### Phase 8: Output Snapshot

39. Write per-finding output:
   ```text
   output/python/<repo>/fuzz_oracles/
   ├── status.json
   └── <rule_slug>_<file_slug>_<line>.json
   ```

40. Write aggregate oracle summary:
   ```text
   output/python/<repo>/fuzz_oracles/status.json
   ```

41. Summary shape:
   ```json
   {
     "stage": "oracle",
     "repo": "Benchmark",
     "lang": "python",
     "model": "anthropic/claude-sonnet-4-5",
     "source": {
       "ingest_summary_path": "output/python/Benchmark/verification_results/summary.json"
     },
     "counts": {
       "selected": 2,
       "generated": 2,
       "skipped": 0,
       "failed": 0
     },
     "oracles": [
       {
         "id": "0",
         "rule_id": "py/xxe",
         "oracle": "output/python/Benchmark/fuzz_oracles/py_xxe_testcode_BenchmarkTest00460_py_45.json",
         "strategy": "patch_call"
       }
     ],
     "errors": []
   }
   ```

42. Default overwrite behavior:
   - if oracle JSON already exists, skip it and count as `skipped`;
   - if all selected outputs already exist, exit 0 with `generated=0`;
   - with `--force`, overwrite selected oracle specs.

43. Do not delete ingest artifacts, harness artifacts, corpus, or run results.

### Phase 9: Error Handling

44. Per-finding failure should not stop the entire batch. Continue processing the remaining findings.

45. CLI exit code:
   - `0` when `failed == 0`;
   - `1` when one or more selected findings fail;
   - `1` for invalid input paths or missing ingest summary.

46. Error records must include:
   - ingest id
   - rule id
   - finding artifact path
   - error class/category
   - concise message

47. Expected error categories:
   ```text
   invalid_ingest_artifact
   missing_source_file
   signature_parse_error
   llm_error
   json_parse_error
   schema_validation_error
   output_exists
   ```

### Phase 10: Tests

48. Add focused unit tests in:
   ```text
   tests/test_oracle.py
   ```

49. Test fixtures should reuse the ingest-style artifact shape and avoid real LLM calls.

50. Unit tests:
   - default ingest summary path resolves correctly.
   - `--finding-id` selects exactly one finding.
   - explicit `--finding` bypasses summary selection.
   - enriched function metadata is read from sibling `function`, not `finding.function_name`.
   - AST signature extraction works for normal functions.
   - AST signature extraction excludes `self` and `cls`.
   - fallback signature is produced when source cannot be parsed.
   - model precedence uses CLI over env over config.
   - JSON fence extraction parses valid LLM output.
   - balanced JSON extraction parses output with thinking text before JSON.
   - invalid JSON records a per-finding error.
   - invalid schema records a per-finding error.
   - existing oracle JSON is skipped without `--force`.
   - `--force` overwrites oracle JSON.
   - aggregate `fuzz_oracles/status.json` records generated, skipped, and failed counts.

51. Mock LLM response example:
   ```json
   {
     "schema_version": "1.0",
     "monitor": {
       "strategy": "inspect_return",
       "patch_target": null,
       "target_arg_index": null,
       "target_arg_name": null,
       "capture_what": "return value",
       "additional_imports": []
     },
     "oracle_check": {
       "condition_description": "payload survives in return value",
       "trigger_patterns": ["<script"],
       "raise_type": "RuntimeError",
       "raise_message_template": "PY_XSS: captured={captured} pattern={matched_pattern}"
     },
     "fuzz_guidance": {
       "seed_corpus": ["<script>alert(1)</script>"],
       "skip_condition": "False"
     },
     "_meta": {
       "function": "target",
       "file": "pkg/app.py",
       "input_strategy": "direct_params",
       "function_signature": "def target(value: str)",
       "tainted_params": [{"name": "value", "index": 0, "type": "str"}]
     }
   }
   ```

### Phase 11: Integration Smoke Test

52. Run after ingest against the real local Benchmark output:
   ```bash
   oraculum oracle \
     --repo Benchmark \
     --lang python \
     --finding-id 0 \
     --output-dir /tmp/oraculum-oracle-smoke \
     --force
   ```

53. For a real LLM smoke test, ensure `.env` has:
   ```text
   LLM_PROVIDER=<provider>
   LLM_MODEL=<model>
   ```

54. Expected results:
   - command exits 0 when the LLM returns valid schema;
   - one oracle JSON is written;
   - `fuzz_oracles/status.json` records the selected finding id;
   - `monitor.strategy` is one of the supported strategies;
   - no VulnHunterX files are modified.

### Verification

- `python3 -m compileall -q src tests`
- `ruff check src tests`
- `pytest tests/test_oracle.py`
- `pytest tests/test_ingest.py tests/test_oracle.py`
- Manual smoke test with one Benchmark finding and a configured LLM model

### Decisions

- **Oracle consumes ingest artifacts**: Stage 1 never reads VulnHunterX summaries directly.
- **VulnHunterX finding remains immutable**: Oraculum metadata stays in sibling objects and `_meta`.
- **No function body in prompt**: source parsing is allowed only to build compact signature metadata.
- **No function signatures CSV requirement**: AST signature extraction is more stable for the current VulnHunterX Python output.
- **Default batch mode uses all ingested findings**: `--finding-id` is for debugging or targeted regeneration.
- **Existing oracle specs are skipped by default**: `--force` is required for overwrite.
- **Tests mock LLM calls**: CI must not depend on provider credentials or network access.
