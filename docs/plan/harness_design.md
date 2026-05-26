## Plan: Oraculum Harness Stage

**TL;DR** - Add an `oraculum harness` command that reads generated oracle JSON from `output/python/<repo>/fuzz_oracles/`, loads the corresponding enriched finding artifact from `verification_results/findings/`, reuses the existing FuzzGenG Stage 2 harness-generation logic, and writes Atheris harnesses under `output/python/<repo>/fuzz_targets/` with seed corpus under `output/python/<repo>/fuzz_corpus/`. This stage is mostly a pipeline/layout refactor, not a new harness-generation design.

**Steps**

### Phase 1: Harness Module Contract

1. Refactor the prototype harness code into a batch stage runner with this module shape:
   ```text
   src/oraculum/
   ├── harness/
   │   ├── __init__.py
   │   ├── runner.py           # Orchestrates harness generation
   │   ├── paths.py            # Resolves fuzz_oracles, fuzz_targets, fuzz_corpus
   │   ├── generator.py        # Backward-compatible single-target wrapper
   │   ├── template_builder.py # Builds deterministic harness skeleton
   │   ├── import_resolver.py  # Resolves target imports
   │   ├── llm_client.py       # LiteLLM call and Python extraction
   │   └── templates/
   │       └── base_harness.j2
   └── cli/
       ├── main.py
       └── commands.py
   ```

2. Keep Stage 2 independent from VulnHunterX imports. It should consume Oraculum artifacts and use paths captured during ingest.

3. Update old prototype assumptions:
   ```text
   old finding function: finding.function_name
   new finding function: artifact.function.name

   old oracle path: output/<lang>/<repo>/oraculum/finding_<id>_<rule>/oracle_spec.json
   new oracle path: output/<lang>/<repo>/fuzz_oracles/<target_id>.json

   old harness path: output/<lang>/<repo>/oraculum/finding_<id>_<rule>/harness.py
   new harness path: output/<lang>/<repo>/fuzz_targets/<target_id>.py
   ```

4. Treat `target_id` as the stable join key across:
   ```text
   fuzz_oracles/<target_id>.json
   fuzz_targets/<target_id>.py
   fuzz_corpus/<target_id>/
   fuzz_results/<target_id>/    # later
   ```

5. Preserve the existing Stage 2 technical approach:
   - deterministic Jinja2 skeleton
   - strategy-specific system prompt
   - LLM fills the narrow harness body
   - Python syntax validation before writing output
   - seed corpus from `oracle.fuzz_guidance.seed_corpus`

### Phase 2: CLI Contract

6. Implement:
   ```bash
   oraculum harness \
     --repo Benchmark \
     --lang python
   ```

7. Required args:
   - `--repo`: repo name under Oraculum output.
   - `--lang`: initially only `python`.

8. Optional args:
   - `--output-dir`: Oraculum output root. Default: `output`.
   - `--oracle-status`: explicit oracle status path. Default: `output/<lang>/<repo>/fuzz_oracles/status.json`.
   - `--target-id`: generate one target by target id.
   - `--finding-id`: generate all oracle entries matching one ingest finding id.
   - `--oracle`: explicit oracle JSON path. Useful for debugging one target.
   - `--config`: harness config path. Default: `config/harness.yaml`.
   - `--model`: override model for this run.
   - `--force`: overwrite existing harness and seed corpus.
   - `--log-file`: Markdown LLM audit log with system prompt, user prompt, and raw response.

9. Model resolution precedence should match oracle:
   ```text
   --model
   LLM_PROVIDER + LLM_MODEL -> "<provider>/<model>"
   LLM_MODEL
   config/harness.yaml model
   ```

10. Load `.env` before resolving model env vars. Do not override exported shell variables.

11. CLI output should mirror `oracle` and VulnHunterX progress style:
   ```text
   Generate Oraculum harnesses
     Repo: python/Benchmark
     Oracle status: output/python/Benchmark/fuzz_oracles/status.json
     Model: openai/glm-5.1

   [1/2] py/xxe
     File: testcode/BenchmarkTest00460.py:45
     Target: py_xxe_testcode_BenchmarkTest00460_py_45
     Harness: generated

   Done. selected=2 generated=2 skipped=0 failed=0
   Output: output/python/Benchmark/fuzz_targets/status.json
   ```

### Phase 3: Input Artifact Resolution

12. Default batch input:
   ```text
   output/python/<repo>/fuzz_oracles/status.json
   ```

13. Read oracle entries from:
   ```json
   {
     "stage": "oracle",
     "oracles": [
       {
         "id": "0",
         "target_id": "py_xxe_testcode_BenchmarkTest00460_py_45",
         "rule_id": "py/xxe",
         "file": "testcode/BenchmarkTest00460.py",
         "start_line": "45",
         "function_name": "BenchmarkTest00460_post",
         "finding_artifact": "output/python/Benchmark/verification_results/findings/finding_0_py_xxe.json",
         "oracle": "output/python/Benchmark/fuzz_oracles/py_xxe_testcode_BenchmarkTest00460_py_45.json",
         "status": "generated",
         "strategy": "patch_call"
       }
     ]
   }
   ```

14. Select only entries whose oracle stage status is `generated` by default.

15. If `--target-id` is provided, select only the matching target.

16. If `--finding-id` is provided, select oracle entries whose `id` matches that finding id.

17. If `--oracle` is provided, bypass status selection and process only that oracle file. In this mode:
   - derive `target_id` from `oracle._meta.target_id`;
   - derive finding artifact from `oracle._meta.source_finding_artifact`;
   - fail clearly if either is absent.

18. Validate each selected target has:
   - oracle JSON path
   - enriched finding artifact path
   - target id
   - rule id
   - file
   - start line

### Phase 4: Output Layout

19. Write harness files to:
   ```text
   output/python/<repo>/fuzz_targets/
   ├── status.json
   └── <target_id>.py
   ```

20. Write seed corpus to:
   ```text
   output/python/<repo>/fuzz_corpus/<target_id>/
   ├── seed_000
   ├── seed_001
   └── ...
   ```

21. Do not write corpus under `fuzz_targets/`. VulnHunterX already uses `fuzz_corpus` as the persistent corpus root for fuzz runs, so Oraculum should follow that name.

22. Write aggregate status:
   ```text
   output/python/<repo>/fuzz_targets/status.json
   ```

23. Status shape should stay close to VulnHunterX:
   ```json
   {
     "repo": "Benchmark",
     "harnesses": [
       {
         "target_id": "py_xxe_testcode_BenchmarkTest00460_py_45",
         "harness": "output/python/Benchmark/fuzz_targets/py_xxe_testcode_BenchmarkTest00460_py_45.py",
         "oracle": "output/python/Benchmark/fuzz_oracles/py_xxe_testcode_BenchmarkTest00460_py_45.json",
         "finding_artifact": "output/python/Benchmark/verification_results/findings/finding_0_py_xxe.json",
         "corpus": "output/python/Benchmark/fuzz_corpus/py_xxe_testcode_BenchmarkTest00460_py_45",
         "status": "generated",
         "errors": ""
       }
     ]
   }
   ```

24. Keep `errors` in each entry because VulnHunterX `fuzz_targets/status.json` uses the same field.

### Phase 5: Harness Skeleton Inputs

25. Build the skeleton from:
   - enriched finding artifact
   - oracle JSON
   - VulnHunterX source root from `artifact.source.vhx_repo_root`

26. The skeleton builder should use:
   ```text
   artifact.function.name
   artifact.finding.file
   oracle._meta.function_signature
   oracle._meta.input_strategy
   oracle._meta.tainted_params
   oracle.monitor
   oracle.oracle_check
   oracle.fuzz_guidance
   ```

27. Resolve imports relative to `artifact.source.vhx_repo_root`.

28. Generated harness should make the source checkout importable at runtime:
   ```python
   REPO_ROOT = "<artifact.source.vhx_repo_root>"
   if REPO_ROOT not in sys.path:
       sys.path.insert(0, REPO_ROOT)
   ```

29. Keep current strategy split:
   ```text
   patch_call      -> config/prompts/harness_system_patch_call.txt
   inspect_return  -> config/prompts/harness_system_inspect_return.txt
   catch_exception -> initially reuse inspect_return or add prompt only if needed
   ```

30. User prompt should continue to pass the deterministic skeleton:
   ```text
   config/prompts/harness_user.txt
   ```

### Phase 6: LLM Audit Log

31. `--log-file` for harness should match the oracle audit style:
   ```markdown
   ## [1/2] py/xxe

   - File: `testcode/BenchmarkTest00460.py:45`
   - Target: `py_xxe_testcode_BenchmarkTest00460_py_45`
   - Oracle: `output/python/Benchmark/fuzz_oracles/...json`

   ### System Prompt

   ````text
   ...
   ````

   ### User Prompt

   ````text
   ...
   ````

   ### LLM Response (Iteration 1)

   ````text
   ...
   ````

   - Result: `generated`
   - Harness: `output/python/Benchmark/fuzz_targets/...py`
   ```

32. Do not log API keys, environment variables, or full `.env` content.

33. It is acceptable for the user prompt to contain generated skeleton code and oracle details because that is exactly what the audit log is for.

### Phase 7: Overwrite Policy

34. Default behavior:
   - if `fuzz_targets/<target_id>.py` already exists, skip it and count as `skipped`;
   - if corpus already exists and harness is skipped, leave corpus unchanged.

35. With `--force`:
   - overwrite selected harness file;
   - rewrite selected corpus seeds from `oracle.fuzz_guidance.seed_corpus`;
   - do not delete unrelated corpus files unless we later add `--clean-corpus`.

36. Do not delete `fuzz_oracles/` artifacts from harness stage.

### Phase 8: Error Handling

37. Each target should fail independently. One bad harness generation must not stop the whole batch.

38. Record failed target entries in `fuzz_targets/status.json` with:
   ```json
   {
     "target_id": "...",
     "status": "failed",
     "errors": "short error message"
   }
   ```

39. Failure cases:
   - missing `fuzz_oracles/status.json`
   - missing oracle JSON
   - missing finding artifact
   - invalid oracle JSON schema
   - import resolver cannot derive module path
   - LLM output does not contain Python code
   - generated Python fails `ast.parse`

40. Keep error messages concise in status, and put raw LLM details in `--log-file`.

### Phase 9: Tests

41. Add fixtures that create:
   ```text
   output/python/demo/
   ├── verification_results/
   │   ├── summary.json
   │   └── findings/finding_0_py_path-injection.json
   └── fuzz_oracles/
       ├── status.json
       └── py_path_injection_pkg_app_py_2.json
   ```

42. Unit tests:
   - batch harness generation writes `fuzz_targets/<target_id>.py`.
   - seed corpus writes to `fuzz_corpus/<target_id>/`.
   - `fuzz_targets/status.json` records generated target.
   - existing harness is skipped without `--force`.
   - `--force` overwrites selected harness.
   - `--target-id` selects one target.
   - generated Python passes syntax validation.
   - `--log-file` contains system prompt, user prompt, and raw response.

43. Use mock LLM in tests. Do not call a real provider.

44. Keep tests focused on layout, orchestration, and contract migration. Do not retest every harness strategy in depth because FuzzGenG already covered the core technique.

### Phase 10: Smoke Test

45. End-to-end local smoke:
   ```bash
   oraculum ingest \
     --vhx-root /home/caterpie/VulnHunterX \
     --repo Benchmark \
     --lang python \
     --verdict TP \
     --force

   oraculum oracle \
     --repo Benchmark \
     --lang python \
     --force \
     --log-file logs/oracle_Benchmark.md

   oraculum harness \
     --repo Benchmark \
     --lang python \
     --force \
     --log-file logs/harness_Benchmark.md
   ```

46. Expected output:
   ```text
   output/python/Benchmark/fuzz_targets/status.json
   output/python/Benchmark/fuzz_targets/<target_id>.py
   output/python/Benchmark/fuzz_corpus/<target_id>/seed_000
   logs/harness_Benchmark.md
   ```

47. Verification:
   ```bash
   python3 -m compileall -q src
   ruff check src tests
   pytest
   python -m py_compile output/python/Benchmark/fuzz_targets/<target_id>.py
   ```

### Decisions

- **Use VulnHunterX naming**: `fuzz_targets`, `fuzz_corpus`, and later `fuzz_results`.
- **Keep one new Stage 1 directory only**: `fuzz_oracles`.
- **Use `target_id` as join key** across all fuzz artifacts.
- **Do not introduce a nested per-finding folder** under `fuzz_targets`.
- **Reference VulnHunterX source root** instead of copying source into Oraculum output.
- **Treat Stage 2 as a layout/pipeline refactor** of the existing FuzzGenG harness generator.

### Open Questions

- Whether `catch_exception` needs its own harness system prompt immediately or can share `inspect_return` for the first implementation.
- Whether generated harnesses should embed absolute `vhx_repo_root` or accept it via environment variable for portability.
- Whether `fuzz_targets/status.json` should include `model`, `config`, and `source.oracle_status_path` like oracle status, or stay minimal like VulnHunterX.
- Whether to add `build_log.json` later for Python harness syntax/runtime validation, analogous to VulnHunterX C/C++ harness build logs.
