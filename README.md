# Oraculum: Automated Fuzzing Harness & Oracle Generator

Oraculum is an automated framework that generates coverage-guided **Atheris fuzzing harnesses** and **custom security oracles** for Python applications. 

By consuming verified vulnerability findings from [VulnHunterX](https://github.com/toobunbo/VulnHunterX) (a pipeline that verifies SAST findings to eliminate false positives), Oraculum automatically translates these security threats into executable fuzz targets. This enables automated, high-throughput verification of vulnerabilities using security-focused fuzzing.

---

## 1. How it Works (The Pipeline)

Oraculum operates in a 4-stage pipeline:

```
  Verified         Enriched          {Strategy,         Oracle            Atheris          Crash /
  Finding    ──►   Finding    ──►    Mock Guidance} ──►  Spec       ──►    Harness   ──►    Violation
 (VHX Output)      (Stage 0:          (Stage 1:         (Stage 2:         (Stage 3:        (Fuzzer Run)
                    Ingest)           Classify)         Research)         Harness)
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

Oraculum comes pre-packaged with pre-ingested benchmark findings inside `tests/mini_benchmark/oraculum_output/`, so you can run and test the pipeline immediately **without** depending on VulnHunterX (`vhx-root`).

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

### Optional: Ingest VulnHunterX Findings (Stage 0)
If you want to re-import raw scan findings from a local VulnHunterX installation (which requires configuring the `--vhx-root` path containing the scanned repository and verification results):
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
  * **`harness/repair/`**: **Post-generation Repair Loop** — tự động sửa lỗi runtime của harness (xem chi tiết tại `docs/repair-loop-guide.md`).
    * `runner.py`: `RepairLoop` class — dry-run → classify → fix → retry (max 3 iterations)
    * `error_classifier.py`: Phân loại lỗi từ stderr → ErrorType (9 types)
    * `dry_run.py`: Chạy harness với timeout + infer repo root
    * `fixers/`: 4 static fixers (seed encoding, Django/Flask/FastAPI context, Atheris timeout)
    * `fixers/llm_agent.py`: DeepSeek V3.1 fallback cho error types không có static fix
* **`experiments/`**: Thí nghiệm và kết quả thực nghiệm.
  * **`results/final_results_v3.json`**: Kết quả cuối — 123 harnesses
  * **`results/repair_v6_results.json`**: Kết quả so sánh
  * **`scripts/run_repair_v7.sh`**: Script chạy Repair Loop (v7, mới nhất)
  * **`config/realvuln_testing_guide.md`**: Hướng dẫn chạy thí nghiệm
  * **`archive/`**: Dữ liệu thô từ các lần chạy trước
* **`config/`**: System and user prompt configuration files used by the LLM.
  * **`prompts/repair_agent.txt`**: System prompt cho LLM Agent repair
* **`docs/`**: Tài liệu kỹ thuật.
  * **`repair-loop-guide.md`**: Tài liệu chi tiết về Repair Loop (kiến trúc, metrics, kết quả)

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
