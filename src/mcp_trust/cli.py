"""Command-line interface for MCP Trust Kit."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from mcp_trust import __version__


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level CLI parser."""
    parser = argparse.ArgumentParser(
        prog="mcp-trust",
        description="Deterministic trust scoring toolkit for MCP servers.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI."""
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

