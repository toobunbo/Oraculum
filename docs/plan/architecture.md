# Oraculum Architecture Plan

## Purpose

Oraculum is a Python fuzz-verdict framework that consumes verified findings from VulnHunterX and generates runtime evidence through LLM-derived oracles and Atheris harnesses.

The framework does not run static analysis or LLM verification itself. VulnHunterX remains responsible for:

- `prepare`: source checkout, CodeQL database creation, context extraction
- `analyze`: CodeQL/Semgrep/OpenGrep SARIF generation
- `verify`: multi-turn LLM verdict generation

Oraculum starts after VulnHunterX `verify` has produced `output/python/<repo>/verification_results/`.

## Pipeline

```text
VulnHunterX root
  ├── repos/python/<repo>/
  └── output/python/<repo>/
      ├── context/functions.csv
      ├── context/callers.csv
      ├── context/classes.csv
      └── verification_results/summary_<repo>_<timestamp>.json

Oraculum
  ├── ingest     copy verified findings and enrich target function metadata
  ├── oracle     generate oracle_spec.json from verified finding evidence
  └── harness    generate Atheris harness.py from oracle_spec + source context
```

Initial implementation scope:

1. `ingest`
2. `oracle`
3. `harness`

Runtime execution, fuzz-result triage, and repair loops are planned later.

## Stage 0: Ingest

Ingest imports VulnHunterX verification output into Oraculum's workspace without mutating VulnHunterX artifacts.

Inputs:

- `--vhx-root /path/to/VulnHunterX`
- `--repo <repo>`
- `--lang python`
- optional `--summary <path>`; otherwise select the latest summary for the repo
- optional `--verdict TP|FP|NMD|all`

Reads from VulnHunterX:

```text
<vhx-root>/output/python/<repo>/verification_results/
<vhx-root>/output/python/<repo>/context/functions.csv
<vhx-root>/output/python/<repo>/context/callers.csv
<vhx-root>/output/python/<repo>/context/classes.csv
<vhx-root>/repos/python/<repo>/
```

Function enrichment uses the same primary strategy as VulnHunterX `ContextExtractor`:

```text
row.file == finding.file
row.start_line <= finding.start_line <= row.end_line
```

The selected function row adds:

- `function.name`
- `function.file`
- `function.start_line`
- `function.end_line`
- `function.scope`

If multiple rows match, choose the narrowest line range.

Output:

```text
output/python/<repo>/oraculum/ingest/
  summary.json
  findings/
    finding_<id>_<rule_slug>.json
```

## Stage 1: Oracle

Oracle generation converts verified finding evidence into a structured runtime oracle specification.

Inputs:

- enriched finding from `ingest`
- verification verdict, confidence, reasoning, answers, and data_flow
- SARIF dataflow path and related locations if present

Non-goal:

- Stage 1 does not require full function body.

Output:

```text
output/python/<repo>/oraculum/finding_<id>_<rule_slug>/oracle_spec.json
```

Oracle spec contains:

- monitor strategy: `inspect_return`, `patch_call`, or later `catch_exception`
- tainted input description
- trigger patterns
- sink or patch target when applicable
- seed corpus guidance
- metadata for traceability

## Stage 2: Harness

Harness generation turns `oracle_spec.json` into an executable Python Atheris harness.

Inputs:

- `oracle_spec.json`
- enriched function metadata
- source repo under VulnHunterX `repos/python/<repo>/`
- context CSVs where useful
- Jinja2 base harness template

Responsibilities:

- resolve import path for the target function
- build deterministic harness boilerplate
- ask the LLM only for the narrow body logic where needed
- validate generated Python syntax

Output:

```text
output/python/<repo>/oraculum/finding_<id>_<rule_slug>/
  harness.py
  corpus/
```

## Data Contracts

### Verified Finding

The VulnHunterX `finding` object contains:

- `rule_id`
- `message`
- `file`
- `start_line`
- `end_line`
- `repo_name`
- `lang`
- `sarif_path`
- `tool`
- `dataflow_path`
- `severity`
- `precision`
- `cwe_ids`
- `tags`
- `related_locations`

The surrounding VulnHunterX verdict item contains:

- `verdict`
- `confidence`
- `confidence_score`
- `reasoning`
- `answers`
- `context_needed`
- `iterations`
- `model`
- `timestamp`
- `elapsed_seconds`
- `tokens_used`
- `input_tokens`
- `output_tokens`
- `cached_input_tokens`
- `cost_usd`
- `data_flow`

### Enriched Finding

Oraculum wraps the original verdict item instead of rewriting it:

```json
{
  "id": "0",
  "source": {
    "vhx_root": "/path/to/VulnHunterX",
    "summary_path": "output/python/repo/verification_results/summary.json"
  },
  "finding": {},
  "verification": {},
  "function": {
    "name": "target_function",
    "file": "pkg/module.py",
    "start_line": 10,
    "end_line": 42,
    "scope": "Module pkg.module"
  }
}
```

## Repository Layout

Planned source layout follows VulnHunterX conventions:

```text
Oraculum/
├── config/
│   ├── oraculum.yaml
│   └── prompts/
├── docs/
│   └── plan/
├── src/
│   └── oraculum/
│       ├── cli/
│       ├── core/
│       ├── context/
│       ├── harness/
│       ├── llm/
│       ├── oracle/
│       └── verification/
├── tests/
└── output/
```

## CLI Shape

Planned commands:

```bash
oraculum ingest  --vhx-root /path/to/VulnHunterX --repo Benchmark --lang python --verdict TP
oraculum oracle  --repo Benchmark
oraculum harness --repo Benchmark
oraculum generate --vhx-root /path/to/VulnHunterX --repo Benchmark --lang python --verdict TP
```

`generate` is a convenience command for `ingest -> oracle -> harness`.

## Open Decisions

- Whether Oraculum should copy source/context into its own output or reference VulnHunterX paths.
- Whether default verdict filter should be `TP` only or `TP + NMD`.
- Whether `oracle_spec.json` should preserve the current FuzzGenG schema exactly or introduce versioned schema metadata.
- How much harness validation belongs in Stage 2 before adding a dedicated run/triage stage.
