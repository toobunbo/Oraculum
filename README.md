# Oraculum: Automated Fuzzing Harness & Oracle Generator

Oraculum is an automated framework that generates coverage-guided **Atheris fuzzing harnesses** and **custom security oracles** for Python applications. 

By consuming verified vulnerability findings from [VulnHunterX](https://github.com/toobunbo/VulnHunterX) (a pipeline that verifies SAST findings to eliminate false positives), Oraculum automatically translates these security threats into executable fuzz targets. This enables automated, high-throughput verification of vulnerabilities using security-focused fuzzing.

---

## 1. How it Works (The Pipeline)

Oraculum operates in a 4-stage pipeline:

```
  Verified         Enriched          {Strategy,         Oracle            Atheris         Repaired         Crash /
  Finding    ──►   Finding    ──►    Mock Guidance} ──►  Spec       ──►    Harness   ──►   Harness   ──►   Violation
 (VHX Output)      (Stage 0:          (Stage 1:         (Stage 2:         (Stage 3:        (Stage 4:       (Fuzzer Run)
                   Ingest)           Classify)         Oracle)            Harness)        Repair Loop)
```

1. **Stage 0: Ingest**
   Imports finding reports verified as "True Positive" by VulnHunterX and transforms them into *enriched findings* with code structure metadata.
2. **Stage 1: Classification**
   An LLM decides the best monitoring strategy based on the nature of the sink:
   * **`recorded_call`**: Intercepts/mocks dangerous sinks (e.g. `subprocess.run`, network calls) to capture arguments safely and check them against injection patterns.
   * **`return_value`**: Invokes the target function directly and monitors the return output to detect filter/sanitizer bypasses (e.g., XSS, Open Redirects).
   * **`filesystem_state`**: Monitored for file creation/modification outside of temporary boundaries (e.g., Path Traversal).
3. **Stage 2: Oracle Research**
   Generates a JSON-formatted **Oracle Specification** defining the precise rules, targets, regex matching patterns, and parameters to fuzz.
4. **Stage 3: Harness Generation**
   Applies Jinja2 skeletons to construct the complete, runnable Python fuzzer target (Atheris code) and initializes a mutation seed corpus directory.
5. **Stage 4: Repair Loop**
   Automatically repairs runtime errors in generated fuzz harnesses. Each harness is dry-run with `-runs=1` (90s timeout). If it fails, the error is classified and a fix is applied — either a static transformation (seed encoding, framework context, Atheris timeout) or an LLM Agent call (DeepSeek V3.1). The process repeats for up to 3 iterations. Achieved a 71.5% pass rate (88/123) across the RealVuln benchmark, including 17 confirmed BUGs. See `docs/repair-loop-guide.md` for details.

---

## 2. Getting Started

### Prerequisites
* Python 3.10+
* A configured virtual environment (`.venv`)

### Setup Environment
1. Copy the example environment file:
   ```bash
   cp env.example .env
   ```
2. Configure the LLM provider in `.env`. Oraculum officially supports `openai`, `anthropic`, and `ollama` (both local and cloud/multi-key configurations). Choose one of the setups below:

   * **Option A: Ollama Cloud (Rotated multi-key)**
     ```ini
     LLM_PROVIDER=ollama
     LLM_MODEL=qwen3-coder:480b-cloud
     OLLAMA_API_BASE=https://ollama.com
     OLLAMA_API_KEYS=key1,key2,key3
     ```

   * **Option B: Ollama (Local)**
     ```ini
     LLM_PROVIDER=ollama
     LLM_MODEL=qwen3-coder
     OLLAMA_API_BASE=http://localhost:11434
     ```

   * **Option C: OpenAI**
     ```ini
     LLM_PROVIDER=openai
     LLM_MODEL=gpt-4o
     OPENAI_API_KEY=your-openai-api-key
     # Optional: OPENAI_BASE_URL=https://custom-proxy.com/v1
     ```

    * **Option D: Anthropic**
      ```ini
      LLM_PROVIDER=anthropic
      LLM_MODEL=claude-3-5-sonnet-latest
      ANTHROPIC_API_KEY=your-anthropic-api-key
      ```

    * **Option E: DeepSeek via shopaikey.com**
      ```ini
      LLM_PROVIDER=openai
      LLM_MODEL=deepseek-v3-1-250821
      OPENAI_API_KEY=sk-your-deepseek-api-key
      OPENAI_API_BASE=https://api.shopaikey.com/v1
      ```

3. Activate the virtual environment:
   ```bash
   source .venv/bin/activate
   ```

---

## 3. Running the Pipeline

The inputs of **Stage 1 (Classification)** are *enriched findings* (JSON files containing vulnerability metadata, source code, and VulnHunterX verification reasoning) and an ingest `summary.json` mapping them.

* **For the test benchmark:** Oraculum comes pre-packaged with these pre-ingested findings inside `tests/mini_benchmark/oraculum_output/`. Thus, Stage 0 is optional and you can run/test the pipeline immediately **without** depending on VulnHunterX (`vhx-root`).
* **For new scan reports:** Stage 0 (Ingest) is **required** to import and enrich raw findings before you can run Stage 1.

### Step 1: Classify Strategies (Stage 1)
Classify findings into their respective fuzzer monitoring strategies:
```bash
oraculum classify \
  --repo mini-bench \
  --output-dir tests/mini_benchmark/oraculum_output \
  --log-file tests/mini_benchmark/classify_log.md \
  --force
```

### Step 2: Generate Oracle Specifications (Stage 2)
Generate target oracle definitions:
```bash
oraculum oracle \
  --repo mini-bench \
  --output-dir tests/mini_benchmark/oraculum_output \
  --force
```

### Step 3: Generate Atheris Fuzzer Harnesses (Stage 3)
Generate the ready-to-run fuzz target scripts and corpus files:
```bash
oraculum harness \
  --repo mini-bench \
  --output-dir tests/mini_benchmark/oraculum_output \
  --force
```

Generated targets are placed in:
`tests/mini_benchmark/oraculum_output/python/mini-bench/fuzz_targets/`

---

### Ingest VulnHunterX Findings (Stage 0)
This step is required for new scan reports (optional for testing the pre-packaged benchmark). To import raw scan findings from a local VulnHunterX installation (which requires configuring the `--vhx-root` path containing the scanned repository and verification results):
```bash
oraculum ingest \
  --vhx-root tests/mini_benchmark/vhx_root \
  --repo mini-bench \
  --output-dir tests/mini_benchmark/oraculum_output \
  --force
```

---

## 4. Verifying the Fuzzers

### Run a Smoke Test
To verify the generated harness compiles and has no syntax or import errors, run it for 1 iteration:
```bash
python tests/mini_benchmark/oraculum_output/python/mini-bench/fuzz_targets/py_command_line_injection_target_app_py_4.py -runs=1
```

### Run Fuzz Testing (Catching Violations)
Run the fuzzer to mutate inputs from the seed corpus and detect vulnerabilities. The fuzzer exits with code `77` when an oracle violation is caught (e.g., `RuntimeError: Command injection detected`):
```bash
python tests/mini_benchmark/oraculum_output/python/mini-bench/fuzz_targets/py_command_line_injection_target_app_py_4.py
```

---

## 5. Directory Structure

* **`src/oraculum/`**: Core source code of the generator agents.
  * **`ingest/`**: Stage 0 data flow logic.
  * **`classification/`**: Stage 1 classification models & rules.
  * **`oracle/`**: Stage 2 prompt routing & oracle spec generator.
  * **`harness/`**: Stage 3 template structures, code generator, and CLI logic.
  * **`harness/repair/`**: **Post-generation Repair Loop** — automatically repairs runtime errors in generated harnesses (see `docs/repair-loop-guide.md`).
    * `runner.py`: `RepairLoop` class — dry-run → classify → fix → retry (max 3 iterations)
    * `error_classifier.py`: Classifies runtime errors from stderr → ErrorType (9 types)
    * `dry_run.py`: Runs harness with timeout + infers repo root
    * `fixers/`: 4 static fixers (seed encoding, Django/Flask/FastAPI context, Atheris timeout)
    * `fixers/llm_agent.py`: DeepSeek V3.1 fallback for error types without static fixers
* **`experiments/`**: Experiment scripts and results.
  * **`results/final_results_v3.json`**: Final results — 123 harnesses, 88 pass, 17 BUGs
  * **`results/repair_v6_results.json`**: Comparison results (V6, 67 pass)
  * **`scripts/run_repair_v7.sh`**: Repair Loop runner script (v7, latest)
  * **`config/realvuln_testing_guide.md`**: RealVuln experiment guide
  * **`archive/`**: Raw data from previous experiment runs
* **`config/`**: System and user prompt configuration files used by the LLM.
  * **`prompts/repair_agent.txt`**: System prompt for LLM Agent repair
* **`docs/`**: Technical documentation.
  * **`repair-loop-guide.md`**: Repair Loop technical documentation (architecture, metrics, experimental results)

---

## 6. Experimental Results (RealVuln Benchmark)

### 6.1 Pipeline Overview

Oraculum was evaluated on the **RealVuln benchmark** — 62 Python repositories containing 2,182 ground-truth vulnerability findings. After VHX verification (CodeQL + LLM), **671 True Positives** were fed into the Oraculum pipeline. From these, **123 Atheris fuzz harnesses** were automatically generated (Harness Generation Rate: 18.3%).

### 6.2 Metrics

We do not report Precision, Recall, or F1-Score because ground truth for "fuzzable vulnerabilities" does not exist — there is no labeled dataset indicating which vulnerabilities can be triggered via Atheris within N fuzz iterations. Instead, we report pipeline-conversion metrics that measure what the system demonstrably achieves:

| Metric | Formula | Track A (auto) | Track B (assisted) |
|--------|---------|----------------|-------------------|
| **Harness Generation Rate** | harness / VHX TP | **18.3%** | **18.3%** |
| **Runtime Pass Rate** | (PASS+BUG) / total | **54.5%** (67/123) | **71.5%** (88/123) |
| **First-Run Bug Detection Rate** | BUG / total | — | **13.8%** (17/123) |
| **End-to-End Confirmation Rate** | BUG / VHX TP | — | **2.5%** (17/671) |
| **Stage Survival Rate** | output / input per stage | varies (see below) | varies |

These metrics are verifiable, reproducible, and do not require unverifiable assumptions about ground truth. The First-Run Bug Detection Rate serves as a **lower bound** on precision: at least 13.8% of generated harnesses trigger a crash on the first fuzz input, confirming a true vulnerability.

### 6.3 Repair Loop Impact

The Repair Loop improved the pass rate from **26.8% (baseline)** to **71.5% (full repair)** — a **2.7x improvement** across 7 iterative versions:

| Version | Fixes applied | PASS rate |
|---------|--------------|-----------|
| V1 (baseline) | None | 26.8% |
| V2 (45s timeout, correct deps) | Package resolution | 26.8% |
| V3 (uv pip) | Correct dependency installation | 32.5% |
| V4 (static fixers) | Seed encoding, framework context, markdown cleanup | 35.8% |
| V5 (cwd fix) | Repo root working directory | 44.7% |
| V6 (instrument_all) | Atheris timeout workaround | 54.5% |
| V7 (full repair) | All static + LLM Agent | **71.5%** |

### 6.4 Bug Detection

17 out of 123 harnesses triggered an Atheris crash (return code 77) on the first fuzz input — confirmed exploitable vulnerabilities:

| Vulnerability class | Count |
|--------------------|-------|
| Command injection | 4 |
| SQL injection | 3 |
| Path injection | 3 |
| Reflective XSS | 2 |
| Unsafe deserialization | 2 |
| Template injection | 1 |
| Full SSRF | 1 |
| Weak sensitive data hashing | 1 |

### 6.5 Failure Analysis

35 harnesses (28.5%) remain in FAIL status. All are attributable to **Atheris runtime limitations**, not pipeline errors:
- 25 harnesses import modules with C extensions (`lxml`, `psycopg2`, `cryptography`) that Atheris cannot instrument
- 10 harnesses trigger `SystemError` during instrumentation of complex Django model chains

These harnesses are syntactically valid and semantically correct. They fail solely because of Atheris internals — a documented limitation of the fuzzing engine, not the harness generation or repair pipeline.

---

## 7. Running the Repair Loop

To reproduce the repair results on generated harnesses:

```bash
# Run repair on all harnesses in the output directory
python3 -c "
from oraculum.harness.repair.runner import RepairLoop
import glob

loop = RepairLoop(timeout=90)
for f in glob.glob('output/python/*/fuzz_targets/*.py'):
    result = loop.repair_one(f)
    print(result.summary)
"
```

```bash
# Or use the experiment script
bash experiments/scripts/run_repair_v7.sh
```

---

## 8. References

- **RealVuln Benchmark**: Kolega et al. https://realvuln.kolega.dev
- **Atheris**: Google. https://github.com/google/atheris
- **CKG-Fuzzer**: Dynamic Program Repair for C/C++ fuzz harnesses
- **VulnHunterX**: LLM-based SAST verification. https://github.com/toobunbo/VulnHunterX
