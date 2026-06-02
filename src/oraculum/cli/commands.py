"""CLI command implementations for Oraculum."""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import TextIO

from dotenv import find_dotenv, load_dotenv

from oraculum.classification.runner import ClassificationError, run_classification
from oraculum.harness.runner import HarnessError, run_harness
from oraculum.ingest.runner import IngestError, run_ingest
from oraculum.oracle.runner import OracleError, run_oracle


def cmd_ingest(args: argparse.Namespace) -> int:
    """Run the ingest command."""
    _load_dotenv()
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


def cmd_classify(args: argparse.Namespace) -> int:
    """Run the classification command."""
    _load_dotenv()
    log_fh = _open_log_file(Path(args.log_file)) if args.log_file else None
    if log_fh:
        _write_classification_log_header(log_fh, args)

    print("Generate Oraculum classifications")
    print(f"  Repo: {args.lang}/{args.repo}")
    print(f"  Output dir: {Path(args.output_dir)}")
    if args.ingest_summary:
        print(f"  Ingest summary: {Path(args.ingest_summary)}")
    if args.finding_id:
        print(f"  Finding id: {args.finding_id}")
    if args.finding:
        print(f"  Finding: {Path(args.finding)}")
    if args.model:
        print(f"  Model: {args.model}")
    sys.stdout.flush()

    def write_log(line: str = "") -> None:
        if log_fh:
            log_fh.write(line + "\n")
            log_fh.flush()

    def on_start(
        i: int,
        total: int,
        artifact: dict,
        artifact_path: Path,
        target_id: str,
    ) -> None:
        finding = artifact.get("finding", {})
        print(f"\n[{i}/{total}] {finding.get('rule_id', 'unknown')}")
        print(f"  File: {finding.get('file', 'unknown')}:{finding.get('start_line', '?')}")
        print(f"  Target: {target_id}")
        write_log(f"## [{i}/{total}] {finding.get('rule_id', 'unknown')}")
        write_log()
        write_log(f"- File: `{finding.get('file', 'unknown')}:{finding.get('start_line', '?')}`")
        write_log(f"- Target: `{target_id}`")
        write_log(f"- Artifact: `{artifact_path}`")

    def on_complete(
        _i: int,
        _total: int,
        _artifact: dict | None,
        status: str,
        detail: str,
    ) -> None:
        if status == "generated":
            print(f"  Strategy: {detail}")
            write_log("- Result: `generated`")
            write_log(f"- Strategy: `{detail}`")
        elif status == "skipped_existing":
            print(f"  Classification: skipped existing -> {detail}")
            write_log("- Result: `skipped_existing`")
            write_log(f"- Existing classification: `{detail}`")
        else:
            print("  Classification: failed")
            print(f"  Error: {detail}")
            write_log("- Result: `failed`")
            write_log(f"- Error: `{detail}`")
        write_log()

    def on_llm_exchange(
        _i: int,
        _total: int,
        _artifact: dict,
        system_prompt: str,
        user_prompt: str,
        raw_response: str | None,
    ) -> None:
        if not log_fh:
            return
        if raw_response is None:
            _write_fenced_section(log_fh, "### System Prompt", system_prompt)
            _write_fenced_section(log_fh, "### User Prompt", user_prompt)
        else:
            _write_fenced_section(log_fh, "### LLM Response (Iteration 1)", raw_response)

    try:
        result = run_classification(
            repo=args.repo,
            lang=args.lang,
            output_dir=Path(args.output_dir),
            ingest_summary=Path(args.ingest_summary) if args.ingest_summary else None,
            finding_id=args.finding_id,
            finding=Path(args.finding) if args.finding else None,
            config_path=Path(args.config),
            model=args.model,
            force=args.force,
            on_finding_start=on_start,
            on_finding_complete=on_complete,
            on_llm_exchange=on_llm_exchange if log_fh else None,
        )
    except Exception as exc:
        write_log("## Failed")
        write_log()
        write_log(f"`{exc}`")
        if log_fh:
            print(f"Log: {Path(args.log_file)}")
            log_fh.close()
        print(f"classification failed: {exc}", file=sys.stderr)
        return 1

    print()
    print(
        "Done. "
        f"selected={result.selected} "
        f"generated={result.generated} "
        f"skipped={result.skipped} "
        f"failed={result.failed}"
    )
    print(f"Output: {result.status_path}")
    write_log("## Summary")
    write_log()
    write_log(f"- Selected: `{result.selected}`")
    write_log(f"- Generated: `{result.generated}`")
    write_log(f"- Skipped: `{result.skipped}`")
    write_log(f"- Failed: `{result.failed}`")
    write_log(f"- Status: `{result.status_path}`")
    if log_fh:
        print(f"Log: {Path(args.log_file)}")
        log_fh.close()
    return 0 if result.ok else 1


def cmd_oracle(args: argparse.Namespace) -> int:
    """Run the oracle command."""
    _load_dotenv()
    log_fh = _open_log_file(Path(args.log_file)) if args.log_file else None
    if log_fh:
        _write_oracle_log_header(log_fh, args)

    print("Generate Oraculum oracle specs")
    print(f"  Repo: {args.lang}/{args.repo}")
    print(f"  Output dir: {Path(args.output_dir)}")
    if args.ingest_summary:
        print(f"  Ingest summary: {Path(args.ingest_summary)}")
    if args.finding_id:
        print(f"  Finding id: {args.finding_id}")
    if args.finding:
        print(f"  Finding: {Path(args.finding)}")
    sys.stdout.flush()

    def write_log(line: str = "") -> None:
        if log_fh:
            log_fh.write(line + "\n")
            log_fh.flush()

    def on_start(
        i: int,
        total: int,
        artifact: dict,
        _artifact_path: Path,
        target_id: str,
    ) -> None:
        finding = artifact.get("finding", {})
        print(f"\n[{i}/{total}] {finding.get('rule_id', 'unknown')}")
        print(f"  File: {finding.get('file', 'unknown')}:{finding.get('start_line', '?')}")
        print(f"  Target: {target_id}")
        write_log(f"## [{i}/{total}] {finding.get('rule_id', 'unknown')}")
        write_log()
        write_log(f"- File: `{finding.get('file', 'unknown')}:{finding.get('start_line', '?')}`")
        write_log(f"- Target: `{target_id}`")
        write_log(f"- Artifact: `{_artifact_path}`")

    def on_complete(
        _i: int,
        _total: int,
        _artifact: dict | None,
        status: str,
        detail: str,
    ) -> None:
        if status == "generated":
            print(f"  Oracle: generated ({detail})")
            write_log("- Result: `generated`")
            write_log(f"- Strategy: `{detail}`")
        elif status == "skipped_existing":
            print(f"  Oracle: skipped existing -> {detail}")
            write_log("- Result: `skipped_existing`")
            write_log(f"- Existing oracle: `{detail}`")
        else:
            print("  Oracle: failed")
            print(f"  Error: {detail}")
            write_log("- Result: `failed`")
            write_log(f"- Error: `{detail}`")
        write_log()

    def on_llm_exchange(
        _i: int,
        _total: int,
        _artifact: dict,
        system_prompt: str,
        user_prompt: str,
        raw_response: str | None,
    ) -> None:
        if not log_fh:
            return
        if raw_response is None:
            _write_fenced_section(log_fh, "### System Prompt", system_prompt)
            _write_fenced_section(log_fh, "### User Prompt", user_prompt)
        else:
            _write_fenced_section(log_fh, "### LLM Response (Iteration 1)", raw_response)

    try:
        result = run_oracle(
            repo=args.repo,
            lang=args.lang,
            output_dir=Path(args.output_dir),
            ingest_summary=Path(args.ingest_summary) if args.ingest_summary else None,
            finding_id=args.finding_id,
            finding=Path(args.finding) if args.finding else None,
            config_path=Path(args.config),
            model=args.model,
            force=args.force,
            on_finding_start=on_start,
            on_finding_complete=on_complete,
            on_llm_exchange=on_llm_exchange if log_fh else None,
        )
    except Exception as exc:
        write_log("## Failed")
        write_log()
        write_log(f"`{exc}`")
        if log_fh:
            print(f"Log: {Path(args.log_file)}")
            log_fh.close()
        print(f"oracle failed: {exc}", file=sys.stderr)
        return 1

    print()
    print(
        "Done. "
        f"selected={result.selected} "
        f"generated={result.generated} "
        f"skipped={result.skipped} "
        f"failed={result.failed}"
    )
    print(f"Output: {result.status_path}")
    write_log("## Summary")
    write_log()
    write_log(f"- Selected: `{result.selected}`")
    write_log(f"- Generated: `{result.generated}`")
    write_log(f"- Skipped: `{result.skipped}`")
    write_log(f"- Failed: `{result.failed}`")
    write_log(f"- Status: `{result.status_path}`")
    if log_fh:
        print(f"Log: {Path(args.log_file)}")
        log_fh.close()
    return 0 if result.ok else 1


def cmd_harness(args: argparse.Namespace) -> int:
    """Run the harness command."""
    _load_dotenv()
    log_fh = _open_log_file(Path(args.log_file)) if args.log_file else None
    if log_fh:
        _write_harness_log_header(log_fh, args)

    oracle_status = Path(args.oracle_status) if args.oracle_status else (
        Path(args.output_dir) / args.lang / args.repo / "fuzz_oracles" / "status.json"
    )
    print("Generate Oraculum harnesses")
    print(f"  Repo: {args.lang}/{args.repo}")
    print(f"  Output dir: {Path(args.output_dir)}")
    if args.oracle:
        print(f"  Oracle: {Path(args.oracle)}")
    else:
        print(f"  Oracle status: {oracle_status}")
    if args.target_id:
        print(f"  Target id: {args.target_id}")
    if args.finding_id:
        print(f"  Finding id: {args.finding_id}")
    sys.stdout.flush()

    def write_log(line: str = "") -> None:
        if log_fh:
            log_fh.write(line + "\n")
            log_fh.flush()

    def on_start(
        i: int,
        total: int,
        artifact: dict,
        _oracle_spec: dict,
        target_id: str,
        oracle_path: Path,
        harness_path: Path,
        corpus_dir: Path,
    ) -> None:
        finding = artifact.get("finding", {})
        print(f"\n[{i}/{total}] {finding.get('rule_id', 'unknown')}")
        print(f"  File: {finding.get('file', 'unknown')}:{finding.get('start_line', '?')}")
        print(f"  Target: {target_id}")
        print(f"  Oracle: {oracle_path}")
        write_log(f"## [{i}/{total}] {finding.get('rule_id', 'unknown')}")
        write_log()
        write_log(f"- File: `{finding.get('file', 'unknown')}:{finding.get('start_line', '?')}`")
        write_log(f"- Target: `{target_id}`")
        write_log(f"- Oracle: `{oracle_path}`")
        write_log(f"- Harness: `{harness_path}`")
        write_log(f"- Corpus: `{corpus_dir}`")

    def on_complete(
        _i: int,
        _total: int,
        _artifact: dict | None,
        status: str,
        detail: str,
    ) -> None:
        if status == "generated":
            print(f"  Harness: generated ({detail})")
            write_log("- Result: `generated`")
            write_log(f"- Harness: `{detail}`")
        elif status == "skipped_existing":
            print(f"  Harness: skipped existing -> {detail}")
            write_log("- Result: `skipped_existing`")
            write_log(f"- Existing harness: `{detail}`")
        else:
            print("  Harness: failed")
            print(f"  Error: {detail}")
            write_log("- Result: `failed`")
            write_log(f"- Error: `{detail}`")
        write_log()

    def on_llm_exchange(
        _i: int,
        _total: int,
        _artifact: dict,
        _oracle_spec: dict,
        system_prompt: str,
        user_prompt: str,
        raw_response: str | None,
    ) -> None:
        if not log_fh:
            return
        if raw_response is None:
            _write_fenced_section(log_fh, "### System Prompt", system_prompt)
            _write_fenced_section(log_fh, "### User Prompt", user_prompt)
        else:
            _write_fenced_section(log_fh, "### LLM Response (Iteration 1)", raw_response)

    try:
        result = run_harness(
            repo=args.repo,
            lang=args.lang,
            output_dir=Path(args.output_dir),
            oracle_status=Path(args.oracle_status) if args.oracle_status else None,
            target_id=args.target_id,
            finding_id=args.finding_id,
            oracle=Path(args.oracle) if args.oracle else None,
            config_path=Path(args.config),
            model=args.model,
            force=args.force,
            on_harness_start=on_start,
            on_harness_complete=on_complete,
            on_llm_exchange=on_llm_exchange if log_fh else None,
        )
    except Exception as exc:
        write_log("## Failed")
        write_log()
        write_log(f"`{exc}`")
        if log_fh:
            print(f"Log: {Path(args.log_file)}")
            log_fh.close()
        print(f"harness failed: {exc}", file=sys.stderr)
        return 1

    print()
    print(
        "Done. "
        f"selected={result.selected} "
        f"generated={result.generated} "
        f"skipped={result.skipped} "
        f"failed={result.failed}"
    )
    print(f"Output: {result.status_path}")
    write_log("## Summary")
    write_log()
    write_log(f"- Selected: `{result.selected}`")
    write_log(f"- Generated: `{result.generated}`")
    write_log(f"- Skipped: `{result.skipped}`")
    write_log(f"- Failed: `{result.failed}`")
    write_log(f"- Status: `{result.status_path}`")
    if log_fh:
        print(f"Log: {Path(args.log_file)}")
        log_fh.close()
    return 0 if result.ok else 1


def _load_dotenv() -> None:
    """Load a local .env file without overriding exported environment variables."""
    dotenv_path = find_dotenv(usecwd=True)
    if dotenv_path:
        load_dotenv(dotenv_path, override=False)


def _resolve_vhx_root(cli_value: str | None) -> Path | None:
    """Resolve VulnHunterX root from CLI or environment."""
    raw = cli_value or os.environ.get("ORACULUM_VHX_ROOT") or os.environ.get("VHX_ROOT")
    if not raw:
        return None
    return Path(raw)


def _open_log_file(path: Path) -> TextIO:
    """Open a Markdown log file for a new command run."""
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.open("w", encoding="utf-8")


def _write_oracle_log_header(log_fh: TextIO, args: argparse.Namespace) -> None:
    """Write Markdown metadata for an oracle run."""
    log_fh.write("# Oraculum Oracle Run\n\n")
    log_fh.write(f"- Started: `{datetime.now().isoformat(timespec='seconds')}`\n")
    log_fh.write(f"- Repo: `{args.lang}/{args.repo}`\n")
    log_fh.write(f"- Output dir: `{Path(args.output_dir)}`\n")
    if args.ingest_summary:
        log_fh.write(f"- Ingest summary: `{Path(args.ingest_summary)}`\n")
    if args.finding_id:
        log_fh.write(f"- Finding id: `{args.finding_id}`\n")
    if args.finding:
        log_fh.write(f"- Finding: `{Path(args.finding)}`\n")
    if args.model:
        log_fh.write(f"- Model override: `{args.model}`\n")
    log_fh.write("\n")
    log_fh.flush()


def _write_classification_log_header(log_fh: TextIO, args: argparse.Namespace) -> None:
    """Write Markdown metadata for a classification run."""
    log_fh.write("# Oraculum Classification Run\n\n")
    log_fh.write(f"- Started: `{datetime.now().isoformat(timespec='seconds')}`\n")
    log_fh.write(f"- Repo: `{args.lang}/{args.repo}`\n")
    log_fh.write(f"- Output dir: `{Path(args.output_dir)}`\n")
    if args.ingest_summary:
        log_fh.write(f"- Ingest summary: `{Path(args.ingest_summary)}`\n")
    if args.finding_id:
        log_fh.write(f"- Finding id: `{args.finding_id}`\n")
    if args.finding:
        log_fh.write(f"- Finding: `{Path(args.finding)}`\n")
    if args.model:
        log_fh.write(f"- Model override: `{args.model}`\n")
    log_fh.write("\n")
    log_fh.flush()


def _write_harness_log_header(log_fh: TextIO, args: argparse.Namespace) -> None:
    """Write Markdown metadata for a harness run."""
    log_fh.write("# Oraculum Harness Run\n\n")
    log_fh.write(f"- Started: `{datetime.now().isoformat(timespec='seconds')}`\n")
    log_fh.write(f"- Repo: `{args.lang}/{args.repo}`\n")
    log_fh.write(f"- Output dir: `{Path(args.output_dir)}`\n")
    if args.oracle_status:
        log_fh.write(f"- Oracle status: `{Path(args.oracle_status)}`\n")
    if args.oracle:
        log_fh.write(f"- Oracle: `{Path(args.oracle)}`\n")
    if args.target_id:
        log_fh.write(f"- Target id: `{args.target_id}`\n")
    if args.finding_id:
        log_fh.write(f"- Finding id: `{args.finding_id}`\n")
    if args.model:
        log_fh.write(f"- Model override: `{args.model}`\n")
    log_fh.write("\n")
    log_fh.flush()


def _write_fenced_section(log_fh: TextIO, title: str, content: str) -> None:
    """Write a Markdown fenced block, escaping nested fence markers."""
    log_fh.write(f"\n{title}\n\n")
    log_fh.write("````text\n")
    log_fh.write(content.replace("````", "` ` ` `"))
    if not content.endswith("\n"):
        log_fh.write("\n")
    log_fh.write("````\n\n")
    log_fh.flush()


__all__ = [
    "ClassificationError",
    "HarnessError",
    "IngestError",
    "OracleError",
    "cmd_classify",
    "cmd_harness",
    "cmd_ingest",
    "cmd_oracle",
]
