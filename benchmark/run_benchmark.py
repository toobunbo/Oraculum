#!/usr/bin/env python3
"""Oraculum Benchmark and Metrics Runner.

This script automates running the Oraculum pipeline and evaluating three core metrics:
1. Validity Rate (Compilation check)
2. Recall Rate (Vulnerability detection with seeds)
3. Fuzzing Overhead (Comparison between with-check and no-check runs)
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import py_compile
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def run_cmd(cmd: list[str], cwd: Path | None = None, timeout: float | None = None) -> subprocess.CompletedProcess:
    """Run a subprocess command safely."""
    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=timeout,
        )
        stdout = res.stdout.decode("utf-8", errors="ignore") if isinstance(res.stdout, bytes) else (res.stdout or "")
        stderr = res.stderr.decode("utf-8", errors="ignore") if isinstance(res.stderr, bytes) else (res.stderr or "")
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=res.returncode,
            stdout=stdout,
            stderr=stderr,
        )
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout.decode("utf-8", errors="ignore") if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = e.stderr.decode("utf-8", errors="ignore") if isinstance(e.stderr, bytes) else (e.stderr or "")
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=-1,
            stdout=stdout,
            stderr=stderr or f"TimeoutExpired after {timeout} seconds",
        )


def run_pipeline(repo: str, vhx_root: str, output_dir: Path, force: bool) -> bool:
    """Run the complete Oraculum pipeline via CLI commands."""
    print("=== Running Oraculum Pipeline ===")
    base_cmd = [sys.executable, "-m", "oraculum.cli.main"]
    force_flag = ["--force"] if force else []

    # 1. Ingest
    print("Step 1/4: Ingesting...")
    cmd = base_cmd + [
        "ingest",
        "--repo", repo,
        "--vhx-root", vhx_root,
        "--output-dir", str(output_dir),
    ] + force_flag
    res = run_cmd(cmd)
    if res.returncode != 0:
        print(f"Ingest failed:\n{res.stderr}", file=sys.stderr)
        return False

    # 2. Classify
    print("Step 2/4: Classifying...")
    cmd = base_cmd + [
        "classify",
        "--repo", repo,
        "--output-dir", str(output_dir),
    ] + force_flag
    res = run_cmd(cmd)
    if res.returncode != 0:
        print(f"Classify failed:\n{res.stderr}", file=sys.stderr)
        return False

    # 3. Oracle
    print("Step 3/4: Generating Oracles...")
    cmd = base_cmd + [
        "oracle",
        "--repo", repo,
        "--output-dir", str(output_dir),
    ] + force_flag
    res = run_cmd(cmd)
    if res.returncode != 0:
        print(f"Oracle generation failed:\n{res.stderr}", file=sys.stderr)
        return False

    # 4. Harness
    print("Step 4/4: Generating Harnesses...")
    cmd = base_cmd + [
        "harness",
        "--repo", repo,
        "--output-dir", str(output_dir),
    ] + force_flag
    res = run_cmd(cmd)
    if res.returncode != 0:
        print(f"Harness generation failed:\n{res.stderr}", file=sys.stderr)
        return False

    print("Pipeline completed successfully!\n")
    return True


def prepare_temp_harness(original_path: Path, temp_path: Path, disable_oracle: bool) -> None:
    """Prepare a modified copy of the harness for overhead benchmarking."""
    content = original_path.read_text(encoding="utf-8")

    # 1. Clear the seed corpus to prevent crash on startup during overhead run
    content = re.sub(
        r"_SEED_CORPUS\s*=\s*\[.*?\]",
        "_SEED_CORPUS = []",
        content,
        flags=re.DOTALL
    )

    if disable_oracle:
        lines = content.splitlines()
        new_lines = []
        in_test_one_input = False
        in_check = False
        indent = ""

        for line in lines:
            stripped = line.strip()
            if line.startswith("def TestOneInput("):
                in_test_one_input = True

            if in_test_one_input:
                if stripped.startswith("#") and "oracle check" in stripped.lower():
                    in_check = True
                    indent = line[:len(line) - len(stripped)]
                    new_lines.append(indent + "pass")
                    continue
                elif stripped.startswith("# Check for new or modified") or stripped.startswith("# Check if any file"):
                    in_check = True
                    indent = line[:len(line) - len(stripped)]
                    new_lines.append(indent + "pass")
                    continue
                elif stripped.startswith("for pattern in _COMPILED_PATTERNS:"):
                    in_check = True
                    indent = line[:len(line) - len(stripped)]
                    new_lines.append(indent + "pass")
                    continue

                if in_check:
                    if line.startswith("# === SEED CORPUS") or line.startswith("if __name__ =="):
                        in_test_one_input = False
                        in_check = False
                    elif stripped.startswith("finally:"):
                        in_check = False
                    else:
                        continue

            if not in_test_one_input or not in_check:
                new_lines.append(line)
        content = "\n".join(new_lines) + "\n"

    temp_path.write_text(content, encoding="utf-8")


def check_compilation(harness_path: Path) -> tuple[bool, str]:
    """Check if the harness file compiles successfully."""
    try:
        py_compile.compile(str(harness_path), doraise=True)
        return True, ""
    except py_compile.PyCompileError as e:
        return False, str(e)


def evaluate_target(
    target: dict[str, Any],
    project_root: Path,
    runs: int,
    timeout: float
) -> dict[str, Any]:
    """Evaluate validity, recall, and overhead for a single target."""
    target_id = target.get("target_id", "unknown")
    harness_rel = target.get("harness", "")
    harness_path = project_root / harness_rel
    corpus_rel = target.get("corpus", "")
    corpus_dir = project_root / corpus_rel
    strategy = target.get("strategy", "unknown")

    result = {
        "target_id": target_id,
        "strategy": strategy,
        "valid": False,
        "recall": False,
        "overhead_pct": 0.0,
        "throughput_no_oracle": 0.0,
        "throughput_with_oracle": 0.0,
        "error_msg": "",
    }

    if not harness_path.exists():
        result["error_msg"] = f"Harness file not found: {harness_rel}"
        return result

    # 1. Measure Validity
    valid, compile_msg = check_compilation(harness_path)
    result["valid"] = valid
    if not valid:
        result["error_msg"] = f"Compilation failed: {compile_msg}"
        return result

    # 2. Measure Recall (Bug Detection with seeds)
    # We execute the harness with its seed corpus using sys.executable.
    # If the fuzzer crashes with non-zero and the output contains violation markers, recall is successful.
    res_recall = run_cmd([sys.executable, str(harness_path), "-runs=500"], timeout=timeout)
    
    # Check if crashed and output matches oracle violation pattern
    output = res_recall.stdout + "\n" + res_recall.stderr
    has_violation_marker = (
        "ORACULUM_VIOLATION" in output or 
        "VIOLATION:" in output or 
        "RuntimeError:" in output or
        "PATH-INJECTION" in output or
        "COMMAND-INJECTION" in output or
        "URL_REDIRECTION" in output
    )
    has_setup_error = (
        "ImportError:" in output or
        "NameError:" in output or
        "SyntaxError:" in output or
        "AttributeError:" in output or
        "TypeError:" in output
    )

    if res_recall.returncode != 0 and has_violation_marker and not has_setup_error:
        result["recall"] = True
    else:
        # If it timed out or exited cleanly, it failed to trigger
        if res_recall.returncode == 0:
            result["error_msg"] = "Harness exited with code 0 (failed to trigger violation)"
        elif has_setup_error:
            result["error_msg"] = f"Harness crashed with setup/import error: {has_setup_error}"
        else:
            result["error_msg"] = f"Harness crashed with unexpected error (exit code {res_recall.returncode})"

    # 3. Measure Overhead (with-check vs no-check on random inputs)
    # Create temp directory inside workspace
    temp_bench_dir = project_root / "output" / "benchmark_temp"
    temp_bench_dir.mkdir(parents=True, exist_ok=True)
    
    harness_with_oracle_temp = temp_bench_dir / f"{target_id}_with_oracle.py"
    harness_no_oracle_temp = temp_bench_dir / f"{target_id}_no_oracle.py"
    empty_corpus_dir = temp_bench_dir / f"{target_id}_empty_corpus"
    empty_corpus_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Prepare modified harness files
        prepare_temp_harness(harness_path, harness_with_oracle_temp, disable_oracle=False)
        prepare_temp_harness(harness_path, harness_no_oracle_temp, disable_oracle=True)

        # Run no-oracle version (baseline)
        start_no = time.perf_counter()
        res_no = run_cmd([sys.executable, str(harness_no_oracle_temp), str(empty_corpus_dir), f"-runs={runs}"], timeout=30.0)
        duration_no = time.perf_counter() - start_no

        # Run with-oracle version (comparison)
        start_with = time.perf_counter()
        res_with = run_cmd([sys.executable, str(harness_with_oracle_temp), str(empty_corpus_dir), f"-runs={runs}"], timeout=30.0)
        duration_with = time.perf_counter() - start_with

        # If both executed successfully, calculate overhead
        if res_no.returncode == 0 and res_with.returncode == 0:
            result["throughput_no_oracle"] = runs / duration_no if duration_no > 0 else 0.0
            result["throughput_with_oracle"] = runs / duration_with if duration_with > 0 else 0.0
            
            overhead = ((duration_with - duration_no) / duration_no) * 100.0 if duration_no > 0 else 0.0
            result["overhead_pct"] = max(0.0, overhead)  # clip negative noise to 0
        else:
            result["overhead_pct"] = -1.0  # signal measurement error
            no_err = f"no_oracle exit code {res_no.returncode}" if res_no.returncode != 0 else ""
            with_err = f"with_oracle exit code {res_with.returncode}" if res_with.returncode != 0 else ""
            result["error_msg"] += f" [Overhead error: {no_err} {with_err}]"
    finally:
        # Clean up temp files for this target
        if harness_with_oracle_temp.exists():
            harness_with_oracle_temp.unlink()
        if harness_no_oracle_temp.exists():
            harness_no_oracle_temp.unlink()
        if empty_corpus_dir.exists():
            shutil.rmtree(empty_corpus_dir)

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Oraculum Benchmark and Metrics Runner")
    parser.add_argument(
        "--repo",
        default="benchmark-python",
        help="Repository dataset to evaluate (default: benchmark-python)",
    )
    parser.add_argument(
        "--vhx-root",
        default="/home/tuonglnc/repo/VulnHunterX",
        help="VulnHunterX root workspace path",
    )
    parser.add_argument(
        "--output-dir",
        default="output",
        help="Oraculum output directory relative to repo root",
    )
    parser.add_argument(
        "--run-pipeline",
        action="store_true",
        help="Rerun the Oraculum pipeline stages before benchmarking",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force overwrite during pipeline run",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=20000,
        help="Number of iterations to run for overhead fuzzing (default: 20000)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Timeout in seconds for recall bug triggering (default: 10.0)",
    )

    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    output_dir = project_root / args.output_dir

    # Optional pipeline run
    if args.run_pipeline:
        success = run_pipeline(args.repo, args.vhx_root, output_dir, args.force)
        if not success:
            return 1

    status_json_path = output_dir / "python" / args.repo / "fuzz_targets" / "status.json"
    if not status_json_path.exists():
        print(f"Error: status.json not found at {status_json_path}", file=sys.stderr)
        print("Please run the Oraculum pipeline first or pass --run-pipeline.", file=sys.stderr)
        return 1

    with open(status_json_path, encoding="utf-8") as f:
        status_data = json.load(f)

    harnesses = status_data.get("harnesses", [])
    if not harnesses:
        print("No generated harnesses found in status.json.", file=sys.stderr)
        return 0

    print(f"=== Evaluating {len(harnesses)} targets from {args.repo} ===")
    results = []
    
    # Ensure temp dir parent exists
    temp_bench_dir = output_dir / "benchmark_temp"
    temp_bench_dir.mkdir(parents=True, exist_ok=True)

    try:
        for idx, target in enumerate(harnesses, 1):
            target_id = target.get("target_id", "unknown")
            print(f"[{idx}/{len(harnesses)}] Evaluating {target_id}...")
            res = evaluate_target(target, project_root, args.runs, args.timeout)
            results.append(res)
    finally:
        # Clean up temp benchmark dir if empty
        if temp_bench_dir.exists():
            try:
                shutil.rmtree(temp_bench_dir)
            except Exception:
                pass

    # Compute aggregate metrics
    total = len(results)
    valid_count = sum(1 for r in results if r["valid"])
    recall_count = sum(1 for r in results if r["recall"])
    
    overhead_sum = 0.0
    overhead_count = 0
    for r in results:
        if r["overhead_pct"] >= 0.0:
            overhead_sum += r["overhead_pct"]
            overhead_count += 1
    
    avg_overhead = overhead_sum / overhead_count if overhead_count > 0 else 0.0
    validity_rate = (valid_count / total) * 100.0 if total > 0 else 0.0
    recall_rate = (recall_count / total) * 100.0 if total > 0 else 0.0

    print("\n=== Benchmark Summary ===")
    print(f"Total Targets: {total}")
    print(f"Validity Rate (Compile): {validity_rate:.2f}% ({valid_count}/{total})")
    print(f"Recall Rate (Detection): {recall_rate:.2f}% ({recall_count}/{total})")
    print(f"Average Oracle Overhead: {avg_overhead:.2f}% (measured on {overhead_count} targets)")

    # 1. Export CSV report
    csv_path = project_root / "benchmark_report.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f_csv:
        writer = csv.writer(f_csv)
        writer.writerow([
            "Target ID", "Strategy", "Compile Valid", "Recall Detected", 
            "Throughput No-Oracle (exec/s)", "Throughput With-Oracle (exec/s)", 
            "Overhead (%)", "Notes"
        ])
        for r in results:
            writer.writerow([
                r["target_id"],
                r["strategy"],
                "YES" if r["valid"] else "NO",
                "YES" if r["recall"] else "NO",
                f"{r['throughput_no_oracle']:.1f}" if r["throughput_no_oracle"] > 0 else "N/A",
                f"{r['throughput_with_oracle']:.1f}" if r["throughput_with_oracle"] > 0 else "N/A",
                f"{r['overhead_pct']:.2f}%" if r["overhead_pct"] >= 0.0 else "N/A",
                r["error_msg"]
            ])

    # 2. Export Markdown report
    md_path = project_root / "benchmark_report.md"
    with open(md_path, "w", encoding="utf-8") as f_md:
        f_md.write(f"# Oraculum Benchmark Report\n\n")
        f_md.write(f"Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f_md.write(f"Repository: `{args.repo}`\n\n")
        
        f_md.write(f"## Executive Summary\n\n")
        f_md.write(f"| Metric | Score | Detail |\n")
        f_md.write(f"| --- | --- | --- |\n")
        f_md.write(f"| **Validity Rate (Compilation)** | **{validity_rate:.2f}%** | {valid_count} / {total} harnesses compiled |\n")
        f_md.write(f"| **Recall Rate (Detection)** | **{recall_rate:.2f}%** | {recall_count} / {total} bugs successfully triggered |\n")
        f_md.write(f"| **Average Oracle Overhead** | **{avg_overhead:.2f}%** | Performance penalty compared to baseline |\n\n")
        
        f_md.write(f"## Target Performance Details\n\n")
        f_md.write(f"| Target ID | Strategy | Valid | Recall | Overhead | Notes |\n")
        f_md.write(f"| --- | --- | --- | --- | --- | --- |\n")
        for r in results:
            valid_str = "✅ YES" if r["valid"] else "❌ NO"
            recall_str = "✅ YES" if r["recall"] else "❌ NO"
            overhead_str = f"{r['overhead_pct']:.2f}%" if r["overhead_pct"] >= 0.0 else "N/A"
            f_md.write(f"| `{r['target_id']}` | `{r['strategy']}` | {valid_str} | {recall_str} | {overhead_str} | {r['error_msg']} |\n")

    print(f"\nSaved CSV report to: {csv_path}")
    print(f"Saved Markdown report to: {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
