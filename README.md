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

## Quick Start

### Prerequisites

- Python 3.10+; Python 3.12 is recommended for consistency with VulnHunterX.
- A VulnHunterX checkout that has already run `prepare`, `analyze`, and `verify`.
- An LLM provider key is not needed for `ingest`, but will be needed for later oracle/harness stages.

### Install

```bash
git clone https://github.com/toobunbo/Oraculum.git && cd Oraculum
uv venv --python python3.12 .venv && source .venv/bin/activate
uv pip install -e ".[dev]"

oraculum --help
```

> Requires [uv](https://docs.astral.sh/uv/) (`curl -LsSf https://astral.sh/uv/install.sh | sh`).
> Plain `python3.12 -m venv .venv` + `pip install -e ".[dev]"` also works if you do not want to install `uv`.

### First Ingest

Configure the VulnHunterX root for your machine:

```bash
export ORACULUM_VHX_ROOT=/path/to/VulnHunterX
```

Or put it in a local `.env` file at the Oraculum project root:

```bash
ORACULUM_VHX_ROOT=/path/to/VulnHunterX
```

Run from the Oraculum project root:

```bash
oraculum ingest \
  --repo Benchmark \
  --lang python \
  --verdict TP
```

You can still override the environment value per command with `--vhx-root`.

For a local smoke test without writing into the repo output directory:

```bash
oraculum ingest \
  --repo Benchmark \
  --lang python \
  --verdict TP \
  --output-dir /tmp/oraculum-ingest-smoke \
  --force
```

Expected output:

```text
Ingest Oraculum inputs
  VulnHunterX root: /home/caterpie/VulnHunterX
  Repo: python/Benchmark
  Summary: /home/caterpie/VulnHunterX/output/python/Benchmark/verification_results/summary_Benchmark_20260523_134754.json
  Verdict filter: TP

Done. selected=2 enriched=2 skipped=0 failed=0
Output: /tmp/oraculum-ingest-smoke/python/Benchmark/verification_results/summary.json
```

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

Generate oracle JSON specs from the verified finding evidence:

- SAST rule and message
- LLM verdict, confidence, reasoning, and guided-question answers
- SARIF dataflow path and related locations
- enriched target function metadata

This stage does not require the full function body.

### Stage 2: Harness

Generate Atheris fuzz targets from:

- oracle JSON specs
- target function metadata
- VulnHunterX source checkout
- context CSVs where useful
- a deterministic Jinja2 harness template

The goal is to keep boilerplate deterministic and use the LLM only for the
small portion of harness logic that benefits from reasoning.

## Expected Output Layout

```text
output/python/<repo>/
├── verification_results/
│   ├── summary.json
│   └── findings/
│       └── finding_<id>_<rule_slug>.json
├── fuzz_oracles/
│   ├── status.json
│   └── <rule_slug>_<file_slug>_<line>.json
├── fuzz_targets/
│   ├── status.json
│   └── <rule_slug>_<file_slug>_<line>.py
├── fuzz_corpus/
│   └── <rule_slug>_<file_slug>_<line>/
└── fuzz_results/
    └── summary.json
```

## CLI

```bash
oraculum ingest \
  --repo Benchmark \
  --lang python \
  --verdict TP

oraculum oracle --repo Benchmark

oraculum oracle \
  --repo Benchmark \
  --lang python \
  --log-file logs/oracle_Benchmark.md

# Planned next stage:
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

`ingest` and `oracle` are implemented. Harness generation is being migrated
from the prototype. See
[`docs/plan/architecture.md`](docs/plan/architecture.md).
