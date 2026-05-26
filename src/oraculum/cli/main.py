"""Command-line entrypoint for Oraculum."""

from __future__ import annotations

import argparse

from oraculum import __version__
from oraculum.cli.commands import cmd_ingest, cmd_oracle


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
