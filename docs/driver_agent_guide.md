# Driver Agent Guide — Oraculum Harness Generation (Stage 2)

This document tells you exactly how to fill each `# LLM_FILL` slot in the
Driver-based Atheris harness template. **Follow it strictly.**

---

## 1. Your Role

You are a harness completion agent. Your job is to **fill in the `# LLM_FILL` slots
only**. You must NOT:

- Modify any section outside a `# LLM_FILL` slot.
- Write or restructure `TestOneInput` — it is already complete.
- Decide the oracle approach — it was decided upstream by the Oracle stage.
- Add imports that are not in the template header.
- Remove or rename the `Driver` class or its fixed methods.

## 2. Decision Tree Recap

The oracle approach and mock decision were made before you receive this harness.
You only need to understand what they mean so you fill slots correctly.

```
Q1: Is executing the sink dangerous in a test environment?
    YES -> build_mock = true
    NO  -> build_mock = false

Q2: Is the security violation observable after the function returns?
    YES -> continue to Q3
    NO  -> oracle_approach = recorded_call

Q3: Is the result accessible in memory on return?
    YES -> oracle_approach = return_value
    NO  -> oracle_approach = filesystem_state
```

Key rules:
- `build_mock` is a safety flag, not an oracle strategy.
- `recorded_call` means the violation is confirmed by inspecting what was captured
  at the sink call site.
- `return_value` means the violation is confirmed by inspecting the target's return value.
- `filesystem_state` means the violation is confirmed by diffing the filesystem
  before and after execution.

## 3. LLM_FILL Slots

### 3a. `_build_inputs(self)`

**Purpose:** Convert fuzz bytes into concrete parameters for the target function.

**Rules:**
- Use `self.fdp` (a `FuzzedDataProvider` instance wrapping `self.data`).
- For a **single string/bytes param**, consume all remaining bytes:
  ```python
  return self.fdp.ConsumeString(len(self.data))
  ```
- For **multiple params**, split the buffer:
  - Fixed-size types (`int`, `float`, `bool`) consume their natural byte width first.
  - Remaining bytes are divided evenly among `str`/`bytes` params; the last one
    consumes all remaining bytes.
  - Return a tuple or dict matching the target signature.
- For **flask_view** input strategy, build a request-like object (headers, path,
  query string) from fuzz bytes.
- **FORBIDDEN:** Do NOT use `ConsumeBool()` or `ConsumeIntInRange()` to select
  a strategy index or branch from a hardcoded list.
- **FORBIDDEN:** Do NOT reference `_SEED_CORPUS` here.

### 3b. `_call_target(self)`

**Purpose:** Call the target function with the inputs from `_build_inputs`.

**Rules:**
- Call `{{ function_name }}` with `self.inputs`.
- For **direct_params**: `return function_name(*self.inputs)` or unpack as needed.
- For **flask_view**: call the view function with a test request client or
  simulated Flask request context.
- Do NOT add retry logic, logging, or extra wrappers.

### 3c. `should_skip(self)`

**Purpose:** Performance filter to skip irrelevant fuzz inputs early.

**Rules:**
- Return `True` to skip, `False` to proceed.
- This is NOT an oracle. Never use it to conclude vulnerability.
- Example: `return len(self.inputs) < 3`
- Default is `return False` — only override if the finding context gives a clear
  minimum-input requirement.

### 3d. `recorded_call` branch — `mock_context()`, `_extract_recorded_value()`

**`mock_context()`:**
- Return a context manager that records calls to the sink.
- When `build_mock = true`:
  ```python
  @contextmanager
  def mock_context(self):
      with patch("{{ patch_target }}") as mock_obj:
          mock_obj.return_value = MagicMock()
          yield mock_obj
  ```
- When `build_mock = false`:
  - Prefer a spy/delegate that calls the real function but records arguments.
  - If no safe spy mechanism exists, use a mock but understand this is for
    observability, not safety.

**`_extract_recorded_value(call)`:**
- Inspect `call.args` and `call.kwargs` to find the tainted payload.
- Check `call.args[target_arg_index]` first, then `call.kwargs.get(target_arg_name)`.
- Return the extracted value (string, bytes, or object), or `None` if not found.
- **CRITICAL:** Do NOT assert on the raw fuzz input. Assert only on what was
  captured at the sink after the target processed the input.

### 3e. `return_value` branch — `_extract_return_value(result)`

**Purpose:** Extract the security-relevant field from the target's return value.

**Rules:**
- If the result is a string, return it directly.
- If the result is a response object (Flask/Django), extract the body:
  ```python
  return result.data.decode("utf-8", errors="replace")
  ```
- If the result is a dict or has a specific field, extract that field per the
  research output (e.g., `result.headers["Location"]` for open redirect).
- Return `None` if the result type is unexpected.

### 3f. `filesystem_state` branch — `snapshot_filesystem()`, `assert_filesystem_state()`, `cleanup_filesystem()`

**`snapshot_filesystem()`:**
- Return a `set` of absolute file paths in the allowed root directory.
- Use `os.walk()` or `pathlib.Path.rglob()` under the watched directory.
- Example:
  ```python
  return set(p for p in Path("/tmp/watched").rglob("*") if p.is_file())
  ```

**`assert_filesystem_state(before, after)`:**
- Compute `after - before` to find newly created files.
- For each new file, resolve its real path with `os.path.realpath()`.
- If any file is outside the allowed root, raise `RuntimeError(_RAISE_MESSAGE)`.

**`cleanup_filesystem(after)`:**
- Delete files in `after - before` to prevent disk exhaustion across fuzz iterations.
- Wrap in try/except to avoid crashes during cleanup.

### 3g. `_SEED_CORPUS`

**Rules:**
- Define as a module-level list (already scaffolded in template).
- At least 6 entries.
- Entries must be **bypass-oriented** — designed to SURVIVE the filter, not just trigger it.
- Cover: mixed case, whitespace injection, unicode homoglyphs, double encoding,
  tag nesting, attribute abuse.
- NEVER reference `_SEED_CORPUS` inside `TestOneInput` or any method.
- Seeds are exported to disk at startup; libFuzzer mutates raw bytes directly.

## 4. Absolute Rules — NEVER Violate

1. **Assert on captured data, not raw input.** For `recorded_call`, patterns
   must match the sink argument, never the fuzz input parameter.
2. **Oracle assert is OUTSIDE the target call try/except.** `RuntimeError` from
   the oracle must propagate to Atheris. It must never be inside `except Exception`.
3. **RuntimeError is always re-raised.** The template already does this in
   `TestOneInput`. Do not wrap oracle calls in additional try/except.
4. **Do NOT mock validation functions.** Only mock/record the sink itself.
   Validation and parsing logic must run with real behavior.
5. **Do NOT use `ConsumeBool()`/`ConsumeIntInRange()` to index seed lists.**
   Seeds are managed externally.
6. **Do NOT add imports.** All imports are handled by the template header.
7. **Do NOT modify `TestOneInput` or the `__main__` block.** They are complete.
8. **Do NOT add a `main()` guard or call `atheris.Setup` outside `__main__`.**

## 5. Quality Checklist

Before outputting, verify:

- [ ] All `# LLM_FILL` slots have concrete implementations (no `raise NotImplementedError`).
- [ ] `_build_inputs` uses `self.fdp`, consumes bytes correctly for the signature.
- [ ] `_call_target` calls `{{ function_name }}` with correct arguments.
- [ ] For `recorded_call`: `mock_context` returns a context manager yielding a recorder.
- [ ] For `recorded_call`: `_extract_recorded_value` checks `call.args` and `call.kwargs`.
- [ ] For `recorded_call`: no assertion is made on the raw fuzz input.
- [ ] For `return_value`: `_extract_return_value` handles the actual return type.
- [ ] For `filesystem_state`: `snapshot_filesystem` returns a set of paths.
- [ ] For `filesystem_state`: `cleanup_filesystem` removes new files.
- [ ] `_SEED_CORPUS` has at least 6 bypass-oriented entries.
- [ ] No modifications to `TestOneInput`, `__main__`, or FIXED CONTRACTS.
- [ ] No extra imports added.
- [ ] Output is a single complete Python file with no markdown, no explanation.
