"""Command-line entrypoint for Oraculum."""

from __future__ import annotations

import argparse

from oraculum import __version__
from oraculum.cli.commands import cmd_classify, cmd_harness, cmd_ingest, cmd_oracle


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oraculum",
        description="Python runtime-oracle and fuzz-harness generation for verified findings.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    ingest_parser = subparsers.add_parser(
        "ingest",
        help="Import VulnHunterX verification results into Oraculum",
    )
    ingest_parser.add_argument(
        "--vhx-root",
        help="Path to VulnHunterX root (default: ORACULUM_VHX_ROOT or VHX_ROOT)",
    )
    ingest_parser.add_argument("--repo", required=True, help="Repository name")
    ingest_parser.add_argument(
        "--lang",
        default="python",
        choices=["python"],
        help="Repository language (currently only python)",
    )
    ingest_parser.add_argument("--summary", help="Explicit VulnHunterX summary JSON path")
    ingest_parser.add_argument(
        "--verdict",
        default="TP",
        choices=["TP", "FP", "NMD", "all", "True Positive", "False Positive", "Needs More Data"],
        help="Verdict filter to ingest",
    )
    ingest_parser.add_argument(
        "--output-dir",
        default="output",
        help="Oraculum output directory",
    )
    ingest_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing ingest summary and selected finding artifacts",
    )
    ingest_parser.set_defaults(func=cmd_ingest)

    classify_parser = subparsers.add_parser(
        "classify",
        help="Classify ingested findings into runtime oracle strategies",
    )
    classify_parser.add_argument("--repo", required=True, help="Repository name")
    classify_parser.add_argument(
        "--lang",
        default="python",
        choices=["python"],
        help="Repository language (currently only python)",
    )
    classify_parser.add_argument(
        "--output-dir",
        default="output",
        help="Oraculum output directory",
    )
    classify_parser.add_argument(
        "--ingest-summary",
        help="Explicit ingest summary JSON path",
    )
    classify_parser.add_argument(
        "--finding-id",
        help="Classify one ingested finding id",
    )
    classify_parser.add_argument(
        "--finding",
        help="Classify one enriched finding JSON path",
    )
    classify_parser.add_argument(
        "--config",
        default="config/classification.yaml",
        help="Classification config path",
    )
    classify_parser.add_argument(
        "--model",
        help="Override LLM model for this run",
    )
    classify_parser.add_argument(
        "--log-file",
        help="Write classification LLM audit details to a Markdown log file",
    )
    classify_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing classification JSON files",
    )
    classify_parser.set_defaults(func=cmd_classify)

    oracle_parser = subparsers.add_parser(
        "oracle",
        help="Generate runtime oracle specs for ingested findings",
    )
    oracle_parser.add_argument("--repo", required=True, help="Repository name")
    oracle_parser.add_argument(
        "--lang",
        default="python",
        choices=["python"],
        help="Repository language (currently only python)",
    )
    oracle_parser.add_argument(
        "--output-dir",
        default="output",
        help="Oraculum output directory",
    )
    oracle_parser.add_argument(
        "--ingest-summary",
        help="Explicit ingest summary JSON path",
    )
    oracle_parser.add_argument(
        "--finding-id",
        help="Generate oracle for one ingested finding id",
    )
    oracle_parser.add_argument(
        "--finding",
        help="Generate oracle for one enriched finding JSON path",
    )
    oracle_parser.add_argument(
        "--config",
        default="config/oracle.yaml",
        help="Oracle config path",
    )
    oracle_parser.add_argument(
        "--model",
        help="Override LLM model for this run",
    )
    oracle_parser.add_argument(
        "--log-file",
        help="Write oracle progress details to a Markdown log file",
    )
    oracle_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing oracle JSON files",
    )
    oracle_parser.set_defaults(func=cmd_oracle)

    harness_parser = subparsers.add_parser(
        "harness",
        help="Generate Atheris fuzz harnesses for generated oracle specs",
    )
    harness_parser.add_argument("--repo", required=True, help="Repository name")
    harness_parser.add_argument(
        "--lang",
        default="python",
        choices=["python"],
        help="Repository language (currently only python)",
    )
    harness_parser.add_argument(
        "--output-dir",
        default="output",
        help="Oraculum output directory",
    )
    harness_parser.add_argument(
        "--oracle-status",
        help="Explicit oracle status JSON path",
    )
    harness_parser.add_argument(
        "--target-id",
        help="Generate harness for one oracle target id",
    )
    harness_parser.add_argument(
        "--finding-id",
        help="Generate harnesses for one ingested finding id",
    )
    harness_parser.add_argument(
        "--oracle",
        help="Generate harness for one explicit oracle JSON path",
    )
    harness_parser.add_argument(
        "--config",
        default="config/harness.yaml",
        help="Harness config path",
    )
    harness_parser.add_argument(
        "--model",
        help="Override LLM model for this run",
    )
    harness_parser.add_argument(
        "--log-file",
        help="Write harness LLM audit details to a Markdown log file",
    )
    harness_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing harness files",
    )
    harness_parser.set_defaults(func=cmd_harness)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)
    if hasattr(args, "func"):
        return args.func(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
