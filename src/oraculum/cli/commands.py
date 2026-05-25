"""CLI command implementations for Oraculum."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from oraculum.ingest.runner import IngestError, run_ingest


def cmd_ingest(args: argparse.Namespace) -> int:
    """Run the ingest command."""
    vhx_root = _resolve_vhx_root(args.vhx_root)
    if vhx_root is None:
        print(
            "ingest failed: VulnHunterX root is required. "
            "Pass --vhx-root or set ORACULUM_VHX_ROOT.",
            file=sys.stderr,
        )
        return 1

    try:
        result = run_ingest(
            vhx_root=vhx_root,
            repo=args.repo,
            lang=args.lang,
            summary=Path(args.summary) if args.summary else None,
            verdict_filter=args.verdict,
            output_dir=Path(args.output_dir),
            force=args.force,
        )
    except Exception as exc:
        print(f"ingest failed: {exc}", file=sys.stderr)
        return 1

    print("Ingest Oraculum inputs")
    print(f"  VulnHunterX root: {vhx_root.expanduser().resolve()}")
    print(f"  Repo: {args.lang}/{args.repo}")
    print(f"  Summary: {result.source_summary_path}")
    print(f"  Verdict filter: {args.verdict}")
    print()
    print(
        "Done. "
        f"selected={result.selected} "
        f"enriched={result.enriched} "
        f"skipped={result.skipped} "
        f"failed={result.failed}"
    )
    print(f"Output: {result.summary_path}")
    return 0 if result.ok else 1


def _resolve_vhx_root(cli_value: str | None) -> Path | None:
    """Resolve VulnHunterX root from CLI or environment."""
    raw = cli_value or os.environ.get("ORACULUM_VHX_ROOT") or os.environ.get("VHX_ROOT")
    if not raw:
        return None
    return Path(raw)


__all__ = ["IngestError", "cmd_ingest"]
