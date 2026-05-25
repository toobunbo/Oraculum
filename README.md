# Oraculum

Python runtime-oracle and fuzz-harness generation for verified SAST findings.

Oraculum is designed as the Python fuzz-verdict extension that runs after
VulnHunterX has completed static analysis and LLM verification. It consumes
VulnHunterX verification artifacts, enriches each finding with target function
metadata, generates an oracle specification, and produces an Atheris harness for
runtime confirmation.

## Position in the Pipeline

VulnHunterX remains responsible for the first three stages:

```text
prepare  ->  analyze  ->  verify
```

Oraculum starts from the output of `verify`:

```text
VulnHunterX/output/python/<repo>/verification_results/
  -> Oraculum ingest
  -> Oraculum oracle
  -> Oraculum harness
```

Oraculum does not clone repositories, create CodeQL databases, run CodeQL,
Semgrep, OpenGrep, or re-run LLM verification.

## Planned Stages

### Stage 0: Ingest

Import VulnHunterX verification results into Oraculum without mutating the
VulnHunterX workspace.

Ingest reads:

```text
<vhx-root>/output/python/<repo>/verification_results/
<vhx-root>/output/python/<repo>/context/functions.csv
<vhx-root>/output/python/<repo>/context/callers.csv
<vhx-root>/output/python/<repo>/context/classes.csv
<vhx-root>/repos/python/<repo>/
```

It enriches each verified finding with target function metadata by matching
`finding.file` and `finding.start_line` against `context/functions.csv`.

### Stage 1: Oracle

Generate `oracle_spec.json` from the verified finding evidence:

- SAST rule and message
- LLM verdict, confidence, reasoning, and guided-question answers
- SARIF dataflow path and related locations
- enriched target function metadata

This stage does not require the full function body.

### Stage 2: Harness

Generate an Atheris `harness.py` from:

- `oracle_spec.json`
- target function metadata
- VulnHunterX source checkout
- context CSVs where useful
- a deterministic Jinja2 harness template

The goal is to keep boilerplate deterministic and use the LLM only for the
small portion of harness logic that benefits from reasoning.

## Expected Output Layout

```text
output/python/<repo>/oraculum/
├── ingest/
│   ├── summary.json
│   └── findings/
│       └── finding_<id>_<rule_slug>.json
└── finding_<id>_<rule_slug>/
    ├── oracle_spec.json
    ├── harness.py
    └── corpus/
```

## Planned CLI

```bash
oraculum ingest \
  --vhx-root /path/to/VulnHunterX \
  --repo Benchmark \
  --lang python \
  --verdict TP

oraculum oracle --repo Benchmark

oraculum harness --repo Benchmark

oraculum generate \
  --vhx-root /path/to/VulnHunterX \
  --repo Benchmark \
  --lang python \
  --verdict TP
```

`generate` is planned as a convenience command for:

```text
ingest -> oracle -> harness
```

## Current Status

Architecture planning is in progress. See
[`docs/plan/architecture.md`](docs/plan/architecture.md).
