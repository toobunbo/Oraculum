## Plan: Oraculum Ingest Stage

**TL;DR** - Add an `oraculum ingest` command that reads VulnHunterX `verify` output, filters selected Python verdicts, enriches each finding with `function_name` from `context/functions.csv`, and writes an Oraculum-owned snapshot under `output/python/<repo>/verification_results/`. The stage is file-only: it does not run SAST, does not call an LLM, does not generate oracles, and does not mutate VulnHunterX.

**Steps**

### Phase 1: Ingest Module Skeleton

1. Create the ingest module structure:
   ```text
   src/oraculum/
   ├── ingest/
   │   ├── __init__.py
   │   ├── runner.py          # Orchestrates ingest
   │   └── paths.py           # Resolves VulnHunterX and Oraculum paths
   ├── verification/
   │   └── reader.py          # Loads VulnHunterX verification summaries
   └── context/
       └── functions.py       # Loads functions.csv and maps line -> function
   ```

2. Add the CLI command in:
   ```text
   src/oraculum/cli/
   ├── main.py
   └── commands.py
   ```

3. Keep the implementation independent from VulnHunterX imports. Ingest should consume VulnHunterX artifacts as JSON/CSV files, so it remains stable even if VulnHunterX package internals change.

### Phase 2: CLI Contract

4. Implement the planned command:
   ```bash
   oraculum ingest \
     --vhx-root /home/caterpie/VulnHunterX \
     --repo Benchmark \
     --lang python \
     --verdict TP
   ```

5. Required args:
   - `--repo`: repo name under `VulnHunterX/output/<lang>/<repo>`.
   - `--lang`: initially only `python`.

6. Optional args:
   - `--vhx-root`: VulnHunterX repository root. If omitted, read `ORACULUM_VHX_ROOT`, then `VHX_ROOT`.
   - `--summary`: explicit VulnHunterX `summary_*.json`.
   - `--verdict`: `TP`, `FP`, `NMD`, or `all`. Default: `TP`.
   - `--output-dir`: Oraculum output root. Default: `output`.
   - `--force`: overwrite existing ingest snapshot.

7. CLI output should be compact:
   ```text
   Ingest Oraculum inputs
     VulnHunterX root: /home/caterpie/VulnHunterX
     Repo: python/Benchmark
     Summary: output/python/Benchmark/verification_results/summary_Benchmark_20260523_134754.json
     Verdict filter: TP

   Done. selected=2 enriched=2 skipped=0 failed=0
   Output: output/python/Benchmark/verification_results/summary.json
   ```

### Phase 3: VulnHunterX Artifact Resolution

8. Resolve these source paths from `--vhx-root`, `--lang`, and `--repo`:
   ```text
   <vhx-root>/repos/python/<repo>/
   <vhx-root>/output/python/<repo>/
   <vhx-root>/output/python/<repo>/verification_results/
   <vhx-root>/output/python/<repo>/context/
   <vhx-root>/output/python/<repo>/context/functions.csv
   ```

9. Do not require a function signatures CSV in ingest. Current VulnHunterX Python output guarantees `functions.csv`, `callers.csv`, and `classes.csv`; signatures can be handled later during oracle or harness generation.

10. Summary selection:
    - If `--summary` is provided, accept absolute paths, paths relative to Oraculum cwd, and paths relative to `--vhx-root`.
    - If omitted, find the newest `summary_<repo>_*.json` under `verification_results/`.
    - Record the selected summary path in the output metadata.

### Phase 4: Verification Summary Reader

11. Load the selected VulnHunterX summary JSON and validate that it contains a top-level `verdicts` list.

12. Treat each `verdicts[i]` as the source item. Preserve `i` as the Oraculum finding id, so artifacts remain traceable to the original VulnHunterX summary order.

13. Preserve the original VulnHunterX `finding` object exactly. Do not inject `function_name` into it.

14. Split the VulnHunterX item into:
    ```text
    finding      # original VulnHunterX finding object
    verification # verdict, confidence, reasoning, answers, token stats, data_flow
    ```

15. Validate required finding fields before enrichment:
    - `rule_id`
    - `file`
    - `start_line`
    - `repo_name`
    - `lang`

### Phase 5: Verdict Filtering

16. Map CLI aliases to VulnHunterX verdict strings:
    ```text
    TP  -> True Positive
    FP  -> False Positive
    NMD -> Needs More Data
    all -> all non-Error verdicts
    ```

17. Default filter: `TP`.

18. Skip `Error` verdicts by default, including with `all`. A future debug flag can include errors if needed.

### Phase 6: Function Enrichment

19. Load `context/functions.csv`. Required columns:
    - `name`
    - `file`
    - `start_line`
    - `end_line`

20. Match the finding to an enclosing function:
    ```text
    row.file == finding.file
    row.start_line <= finding.start_line <= row.end_line
    ```

21. If multiple rows match, choose the narrowest span:
    ```text
    span = row.end_line - row.start_line
    ```

22. Add a sibling `function` object:
    ```json
    {
      "name": "BenchmarkTest00460_post",
      "file": "testcode/BenchmarkTest00460.py",
      "start_line": 28,
      "end_line": 64,
      "scope": "Function init"
    }
    ```

23. Treat missing function enrichment as an ingest failure for that finding. VulnHunterX already resolved function context during `verify`, so a miss usually means wrong repo/lang, stale context, or a summary/context mismatch.

### Phase 7: Output Snapshot

24. Write ingest outputs to:
    ```text
    output/python/<repo>/verification_results/
    ├── summary.json
    └── findings/
        ├── finding_0_py_xxe.json
        └── finding_1_py_xxe.json
    ```

25. Per-finding artifact shape:
    ```json
    {
      "id": "0",
      "rule_slug": "py_xxe",
      "source": {
        "vhx_root": "/home/caterpie/VulnHunterX",
        "vhx_repo_root": "/home/caterpie/VulnHunterX/repos/python/Benchmark",
        "vhx_output_root": "/home/caterpie/VulnHunterX/output/python/Benchmark",
        "summary_path": "/home/caterpie/VulnHunterX/output/python/Benchmark/verification_results/summary_Benchmark_20260523_134754.json"
      },
      "finding": {},
      "verification": {},
      "function": {}
    }
    ```

26. `summary.json` should include:
    - stage name: `ingest`
    - repo/lang
    - verdict filter
    - VulnHunterX source paths
    - counts: total, selected, enriched, skipped, failed
    - list of per-finding artifact paths
    - errors, if any

27. Artifact names:
    ```text
    finding_<id>_<rule_slug>.json
    ```
    where `rule_slug = finding.rule_id.replace("/", "_")`.

### Phase 8: Overwrite and Copy Policy

28. Default overwrite behavior:
    - If `output/python/<repo>/verification_results/summary.json` already exists, fail and ask for `--force`.

29. With `--force`:
    - overwrite ingest `summary.json`;
    - overwrite selected per-finding ingest JSON files;
    - do not delete later-stage artifacts like `fuzz_oracles/*.json` or `fuzz_targets/*.py`.

30. Initial copy policy:
    - copy only Oraculum ingest JSON outputs;
    - reference VulnHunterX source and context by absolute path.

31. Defer these options until reproducibility becomes a priority:
    - `--copy-context`
    - `--copy-source`
    - `--snapshot-all`

### Phase 9: Tests

32. Add small fixtures that mimic VulnHunterX output:
    ```text
    tests/fixtures/vhx/
    ├── repos/python/demo/pkg/app.py
    └── output/python/demo/
        ├── context/functions.csv
        └── verification_results/summary_demo_20260523_000000.json
    ```

33. Unit tests:
    - explicit `--summary` path resolves correctly.
    - omitted `--summary` picks newest summary.
    - `TP` filter selects only true positives.
    - `all` skips `Error`.
    - function enrichment succeeds on exact file/range match.
    - nested function ranges choose the narrowest match.
    - missing `functions.csv` fails clearly.
    - no matching function reports finding id, file, and line.
    - existing output without `--force` fails.
    - `--force` overwrites ingest JSON.

### Phase 10: Integration Smoke Test

34. Run against the real local VulnHunterX output:
    ```bash
    oraculum ingest \
      --vhx-root /home/caterpie/VulnHunterX \
      --repo Benchmark \
      --lang python \
      --verdict TP
    ```

35. Expected results:
    - command exits 0
    - `summary.json` is written
    - every selected finding has a non-empty `function.name`
    - artifact ids match original VulnHunterX summary indexes
    - no VulnHunterX files are modified

### Verification

- `python3 -m compileall -q src`
- `pytest tests/test_ingest.py`
- Manual smoke test against `/home/caterpie/VulnHunterX/output/python/Benchmark`
- Check `git status` in VulnHunterX after ingest to confirm no files changed

### Decisions

- **Ingest starts after VulnHunterX verify**: Oraculum does not rerun `prepare`, `analyze`, or `verify`.
- **Default filter is TP**: the main use case is fuzz confirmation of likely true positives.
- **Function metadata is a sibling object**: keep VulnHunterX `finding` unchanged for traceability.
- **Missing function is an error**: VulnHunterX has already resolved function context during verify, so Oraculum should fail loudly if the context cannot be reproduced.
- **Reference source/context first**: do not copy large repos or context directories until reproducible snapshots are explicitly needed.
