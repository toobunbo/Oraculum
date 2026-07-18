#!/usr/bin/env python3
"""
Oraculum Repair Loop — Post-Generation Runtime Error Repair.

Usage:
    python scripts/run_repair_loop.py <output_dir> [--timeout SECONDS] [--dry-run|--force-apply]

Modes:
  --dry-run      analyze only, no file writes
  --force-apply  static-analysis-based fixes applied directly to files (no dry-run needed)
  (neither)      normal mode: dry-run each harness, fix if ERR, re-validate

Applies deterministic fixes to all Python fuzz harnesses under <output_dir>:
    1. Seed encoding: fixes _seed.encode() crash on bytes literals
    2. Framework context: injects Django/Flask/FastAPI setup boilerplate

Output: prints repair summary with per-harness outcome.
"""

import argparse
import sys
import os
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from oraculum.harness.repair import RepairLoop
from oraculum.harness.repair.runner import HarnessRepairResult


def main():
    parser = argparse.ArgumentParser(description="Oraculum Repair Loop")
    parser.add_argument("output_dir", help="Oraculum output directory (e.g., output/python/)")
    parser.add_argument("--timeout", type=int, default=15, help="Dry-run timeout per harness (seconds)")
    parser.add_argument("--dry-run", action="store_true", help="Analyze only, do not modify files")
    parser.add_argument("--force-apply", action="store_true", help="Apply fixes based on static analysis (no dry-run)")
    args = parser.parse_args()

    if args.dry_run and args.force_apply:
        print("ERROR: --dry-run and --force-apply are mutually exclusive")
        sys.exit(1)

    if not os.path.isdir(args.output_dir):
        print(f"ERROR: output_dir not found: {args.output_dir}")
        sys.exit(1)

    loop = RepairLoop(timeout=args.timeout, analyze_only=args.dry_run, force_apply=args.force_apply)

    all_results: list[HarnessRepairResult] = []
    for result in loop.repair_all(args.output_dir):
        all_results.append(result)
        if args.dry_run or args.force_apply:
            print(f"  [{result.initial_type.value if result.initial_type else 'OK':6s}] {result.harness_path} {'→ fixed' if result.was_repaired else ''}")
        else:
            prefix = {True: "FIX", False: "ERR"}.get(result.was_repaired, "OK")
            print(f"  [{prefix:3s}] {result.summary}")

    print()
    print(loop.summary_report())

    # Print academic-ready table
    total = len(all_results)
    if total > 0:
        print(f"\n{'='*60}")
        print(f"ACADEMIC REPORT — Repair Loop Results")
        print(f"{'='*60}")
        initial_err = sum(1 for r in all_results if r.initial_status == "ERR")
        final_err = sum(1 for r in all_results if r.final_status == "ERR")
        repaired = sum(1 for r in all_results if r.was_repaired)
        pass_count = sum(1 for r in all_results if r.final_status == "PASS")
        bug_count = sum(1 for r in all_results if r.final_status == "BUG")
        print(f"  Total harnesses:        {total}")
        print(f"  Initial ERR:            {initial_err}")
        print(f"  Repaired:               {repaired}")
        print(f"  Final ERR:              {final_err}")
        print(f"  Final PASS:             {pass_count}")
        print(f"  Final BUG:              {bug_count}")
        if initial_err > 0:
            print(f"  ERR reduction rate:     {100 * repaired / initial_err:.1f}%")
            print(f"  Reduction ratio:         {initial_err} \u2192 {final_err} ({100*(initial_err-final_err)/initial_err:.0f}% drop)")

        # By error type
        from collections import Counter
        initial_types = Counter(
            r.initial_type.value if r.initial_type else "none"
            for r in all_results
        )
        print(f"\n  Error distribution (initial):")
        for etype, count in sorted(initial_types.items(), key=lambda x: -x[1]):
            print(f"    {etype}: {count} ({100*count/total:.1f}%)")

        # Fixes applied — handle both plain-key and I{n}:{key} formats
        fix_counts = Counter()
        for r in all_results:
            for f in r.fixes_applied:
                key = f.split(":", 1)[1] if ":" in f else f
                fix_counts[key] += 1
        if fix_counts:
            print(f"\n  Fixes applied:")
            for fix, count in sorted(fix_counts.items(), key=lambda x: -x[1]):
                print(f"    {fix}: {count}")


if __name__ == "__main__":
    main()
