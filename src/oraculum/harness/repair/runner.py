import os
import re
import sys
from dataclasses import dataclass, field

from oraculum.harness.repair.dry_run import dry_run_harness, DryRunResult, DRY_RUN_TIMEOUT, _infer_repo_root
from oraculum.harness.repair.error_classifier import ErrorType, classify_error
from oraculum.harness.repair.fixers import FIXER_REGISTRY, set_current_error
from oraculum.harness.repair.fixers.framework_context import REPO_ROOT_RE


MAX_REPAIR_ITERATIONS = 3


@dataclass
class HarnessRepairResult:
    harness_path: str
    initial_type: ErrorType | None = None
    final_type: ErrorType | None = None
    initial_status: str = ""
    final_status: str = ""
    fixes_applied: list[str] = field(default_factory=list)
    iterations: int = 0
    was_repaired: bool = False

    @property
    def summary(self) -> str:
        if self.final_status == "PASS":
            return f"[PASS] {self.harness_path} — {len(self.fixes_applied)} fixes: {', '.join(self.fixes_applied)}"
        if self.final_status == "BUG":
            return f"[BUG]  {self.harness_path} — oracle triggered after {len(self.fixes_applied)} fixes"
        if self.final_status == "REPAIRED":
            return f"[FIX]  {self.harness_path} — {len(self.fixes_applied)} fixes applied (requires re-smoke)"
        return f"[ERR]  {self.harness_path} — unrepairable ({self.final_type.value if self.final_type else 'unknown'})"


class RepairLoop:
    def __init__(self, timeout: int = 15, analyze_only: bool = False, force_apply: bool = False):
        self.timeout = timeout
        self.analyze_only = analyze_only
        self.force_apply = force_apply
        self.results: list[HarnessRepairResult] = []

    def repair_one(self, harness_path: str) -> HarnessRepairResult:
        result = HarnessRepairResult(harness_path=harness_path)

        if self.analyze_only or self.force_apply:
            source = self._read_harness(harness_path)
            if source is None:
                result.final_status = "ERR"
                return result
            result.initial_status = "ANALYZE"
            result.initial_type = self._detect_error_static(source)
            repo_root = self._extract_repo_root(source)
            for error_key, fix_func in FIXER_REGISTRY.items():
                new_source = fix_func(source, repo_root=repo_root)
                if new_source != source:
                    result.fixes_applied.append(error_key)
                    source = new_source
            if result.fixes_applied:
                result.final_status = "REPAIRED"
                result.was_repaired = True
            else:
                result.final_status = "ANALYZED"
            if self.force_apply and result.fixes_applied:
                self._write_harness(harness_path, source)
            return result

        # Normal mode: detect → fix → re-validate
        repo_root = _infer_repo_root(harness_path)
        initial = dry_run_harness(harness_path, timeout=self.timeout, cwd=repo_root)

        # rc=77 = Atheris found a crash (bug triggered!)
        if initial.returncode == 77:
            result.initial_status = "BUG"
            return result

        result.initial_status = "PASS" if initial.is_pass else ("BUG" if initial.is_bug else "ERR")
        if initial.is_pass or initial.is_bug:
            return result
        result.initial_type = classify_error(initial.stderr)

        source = self._read_harness(harness_path)
        if source is None:
            result.final_status = "ERR"
            result.final_type = result.initial_type
            return result

        # Strip markdown fences from LLM-generated harnesses
        source = source.replace("```python\n", "").replace("```\n", "")
        # Re-write cleaned source
        if source != self._read_harness(harness_path):
            self._write_harness(harness_path, source)

        repo_root = self._extract_repo_root(source) or repo_root
        prev_type = result.initial_type

        for iteration in range(1, MAX_REPAIR_ITERATIONS + 1):
            if prev_type is None or prev_type == ErrorType.UNKNOWN:
                break
            fix_func = FIXER_REGISTRY.get(prev_type.value)
            if fix_func is None:
                break

            set_current_error(initial.stderr)
            new_source = fix_func(source, repo_root=repo_root)
            if new_source == source:
                break

            self._write_harness(harness_path, new_source)
            result.fixes_applied.append(f"I{iteration}:{prev_type.value}")
            source = new_source

            post = dry_run_harness(harness_path, timeout=self.timeout, cwd=repo_root)
            result.iterations = iteration

            if post.is_pass:
                result.final_status = "PASS"
                result.was_repaired = True
                return result
            if post.is_bug:
                result.final_status = "BUG"
                result.was_repaired = True
                return result

            new_type = classify_error(post.stderr)
            if new_type == prev_type or new_type == ErrorType.UNKNOWN:
                break
            prev_type = new_type

        result.final_status = "ERR"
        result.final_type = classify_error(
            dry_run_harness(harness_path, timeout=self.timeout, cwd=repo_root).stderr
        )
        return result

    @staticmethod
    def _detect_error_static(source: str) -> ErrorType | None:
        if re.search(r'(?<!\w)b["\x27]', source):
            return ErrorType.SEED_ENCODE
        return None

    def repair_all(self, harness_dir: str) -> list[HarnessRepairResult]:
        self.results = []
        for root, dirs, files in os.walk(harness_dir):
            for fname in sorted(files):
                if fname.endswith(".py") and fname != "__init__.py":
                    path = os.path.join(root, fname)
                    result = self.repair_one(path)
                    self.results.append(result)
                    yield result

    def summary_report(self) -> str:
        total = len(self.results)
        if total == 0:
            return "No harnesses processed."

        final_statuses = {}
        for r in self.results:
            final_statuses[r.final_status] = final_statuses.get(r.final_status, 0) + 1

        lines = [
            "=" * 60,
            "REPAIR LOOP SUMMARY",
            "=" * 60,
            "",
            f"Total harnesses: {total}",
            "",
            "Final status breakdown:",
        ]
        for status, count in sorted(final_statuses.items()):
            lines.append(f"  {status}: {count} ({100 * count / total:.1f}%)")

        repaired = sum(1 for r in self.results if r.was_repaired)
        label = "Repaired" if self.analyze_only or self.force_apply else "Repaired (ERR\u2192PASS/BUG)"
        lines.append(f"\n{label}: {repaired} ({100 * repaired / total:.1f}%)")
        lines.append(f"Still ERR: {final_statuses.get('ERR', 0)}")
        lines.append("")

        if self.results:
            lines.append("Per-harness details:")
            for r in self.results:
                if r.was_repaired:
                    lines.append(f"  ✅ {r.summary}")
                elif r.final_status == "ERR":
                    lines.append(f"  ❌ {r.summary}")
                else:
                    lines.append(f"  ➖ {r.summary}")

        return "\n".join(lines)

    @staticmethod
    def _read_harness(path: str) -> str | None:
        try:
            with open(path, "r") as f:
                return f.read()
        except OSError:
            return None

    @staticmethod
    def _write_harness(path: str, source: str) -> None:
        with open(path, "w") as f:
            f.write(source)

    @staticmethod
    def _extract_repo_root(source: str) -> str:
        m = REPO_ROOT_RE.search(source)
        return m.group(1) if m else ""
