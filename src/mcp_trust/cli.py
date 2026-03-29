"""Command-line interface for MCP Trust Kit."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from mcp_trust import __version__
from mcp_trust.commands import add_scan_parser, run_scan_command


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level CLI parser."""
    parser = argparse.ArgumentParser(
        prog="mcp-trust",
        description="Deterministic surface-risk scoring for MCP servers.",
        epilog="Use 'mcp-trust scan --help' for scan command options.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command_name")
    add_scan_parser(subparsers)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command_name is None:
        parser.print_help()
        return 0

    if args.command_name == "scan":
        return run_scan_command(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
