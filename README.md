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
2. Configure the LLM provider in `.env` (supports `openai`, `anthropic`, or `ollama`):
   ```ini
   LLM_PROVIDER=ollama
   LLM_MODEL=qwen3-coder:480b-cloud
   ```
3. Activate the virtual environment:
   ```bash
   source .venv/bin/activate
   ```

---

## 3. Running the Pipeline

You can run the pipeline on the included `mini-bench` target project to verify everything is working.

### Step 1: Ingest VulnHunterX Findings (Stage 0)
Import VHX scan findings:
```bash
python -m oraculum.cli.main ingest \
  --vhx-root tests/mini_benchmark/vhx_root \
  --repo mini-bench \
  --output-dir tests/mini_benchmark/oraculum_output \
  --force
```

### Step 2: Classify Strategies (Stage 1)
Classify findings into their respective fuzzer monitoring strategies:
```bash
python -m oraculum.cli.main classify \
  --repo mini-bench \
  --output-dir tests/mini_benchmark/oraculum_output \
  --log-file tests/mini_benchmark/classify_log.md \
  --force
```

### Step 3: Generate Oracle Specifications (Stage 2)
Generate target oracle definitions:
```bash
python -m oraculum.cli.main oracle \
  --repo mini-bench \
  --output-dir tests/mini_benchmark/oraculum_output \
  --force
```

### Step 4: Generate Atheris Fuzzer Harnesses (Stage 3)
Generate the ready-to-run fuzz target scripts and corpus files:
```bash
python -m oraculum.cli.main harness \
  --repo mini-bench \
  --output-dir tests/mini_benchmark/oraculum_output \
  --force
```

Generated targets are placed in:
`tests/mini_benchmark/oraculum_output/python/mini-bench/fuzz_targets/`

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
* **`config/`**: System and user prompt configuration files used by the LLM.
* **`tests/`**: Unit tests (`test_harness.py`, `test_oracle.py`, etc.).
* **`tests/mini_benchmark/`**: Target project containing vulnerable code and simulated VulnHunterX reports for testing.
