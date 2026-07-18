import subprocess
import sys
import os
from dataclasses import dataclass, field


DRY_RUN_TIMEOUT = 90

_REPO_BASES = [
    "/home/trieudai/VulnHunterX/repos/python",
    "/home/trieudai/VulnHunterX/benchmarks/datasets/realvuln/repos",
]


def _infer_repo_root(harness_path: str) -> str | None:
    parts = harness_path.split("/")
    if "fuzz_targets" in parts:
        idx = parts.index("fuzz_targets")
        repo_name = parts[idx - 1]
        for base in _REPO_BASES:
            candidate = f"{base}/{repo_name}"
            if os.path.isdir(candidate):
                return candidate
    return None


@dataclass
class DryRunResult:
    harness_path: str
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    error_type: str | None = None

    @property
    def is_pass(self) -> bool:
        return self.returncode == 0

    @property
    def is_bug(self) -> bool:
        trigger_prefixes = ("RuntimeError:", "ValueError:", "AssertionError:")
        for line in self.stderr.split("\n"):
            if any(p in line for p in trigger_prefixes):
                return True
        return False

    @property
    def is_error(self) -> bool:
        return not self.is_pass and not self.timed_out


def dry_run_harness(
    harness_path: str,
    timeout: int = DRY_RUN_TIMEOUT,
    cwd: str | None = None,
) -> DryRunResult:
    if not os.path.isfile(harness_path):
        return DryRunResult(
            harness_path=harness_path,
            returncode=-1,
            stderr="File not found",
        )

    if cwd is None:
        cwd = _infer_repo_root(harness_path) or os.path.dirname(harness_path) or "."

    try:
        proc = subprocess.run(
            [sys.executable, harness_path, "-runs=1"],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        return DryRunResult(
            harness_path=harness_path,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )
    except subprocess.TimeoutExpired:
        return DryRunResult(
            harness_path=harness_path,
            returncode=-1,
            stderr="TIMEOUT",
            timed_out=True,
        )
