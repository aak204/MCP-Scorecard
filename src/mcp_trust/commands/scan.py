"""Implementation of the ``mcp-trust scan`` CLI command."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from mcp_trust.models import Report
from mcp_trust.reporters import JsonReporter, SarifReporter, TerminalReporter
from mcp_trust.rules import build_v0_rule_registry
from mcp_trust.scoring import ScoringEngine
from mcp_trust.transport import TransportError
from mcp_trust.transports import StdioServerConfig, StdioTransport

EXIT_CODE_SUCCESS = 0
EXIT_CODE_SCAN_FAILED = 2
EXIT_CODE_SCORE_BELOW_THRESHOLD = 3


@dataclass(slots=True, frozen=True)
class ScanCommandOptions:
    """Normalized CLI options for ``mcp-trust scan``."""

    command: tuple[str, ...]
    timeout_seconds: float
    min_score: int
    json_out: str | None = None
    sarif_out: str | None = None

    @classmethod
    def from_namespace(cls, args: argparse.Namespace) -> ScanCommandOptions:
        """Build validated scan options from argparse output."""
        command = _normalize_server_command(args.cmd)
        min_score = _normalize_min_score(args.min_score)
        return cls(
            command=command,
            timeout_seconds=args.timeout,
            min_score=min_score,
            json_out=args.json_out,
            sarif_out=args.sarif,
        )


def add_scan_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the ``scan`` subcommand parser."""
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a local stdio MCP server and compute a deterministic surface-risk score.",
        description=(
            "Launch a local MCP server over stdio, discover its tools, run deterministic "
            "hygiene and capability rules, print a terminal summary, and optionally write "
            "JSON or SARIF reports."
        ),
        epilog=(
            "Example:\n"
            "  mcp-trust scan --min-score 80 --json-out report.json \\\n"
            "    --sarif report.sarif --cmd python examples/insecure-server/server.py"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan_parser.add_argument(
        "--cmd",
        nargs=argparse.REMAINDER,
        help=(
            "Server command to run over stdio. Put this flag last. "
            "The command is executed directly without a shell. "
            "Example: --cmd python examples/insecure-server/server.py"
        ),
    )
    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-request timeout in seconds. Default: 10.0.",
    )
    scan_parser.add_argument(
        "--json-out",
        help="Write the JSON report to this path.",
    )
    scan_parser.add_argument(
        "--sarif",
        help="Write the SARIF report to this path.",
    )
    scan_parser.add_argument(
        "--min-score",
        type=int,
        default=0,
        help=(
            "Fail with exit code 3 when the total score is below this threshold. "
            "Range: 0..100. Default: 0."
        ),
    )


def run_scan_command(args: argparse.Namespace) -> int:
    """Execute the ``scan`` command and return its process exit code."""
    try:
        options = ScanCommandOptions.from_namespace(args)
        report = _scan_server(options)
        _emit_outputs(report, options)
        return _enforce_min_score(report.total_score, options.min_score)
    except TransportError as exc:
        _print_scan_error(
            f"{exc} "
            "Check --cmd, verify the server starts locally over stdio, and review stderr output."
        )
        return EXIT_CODE_SCAN_FAILED
    except ValueError as exc:
        _print_scan_error(str(exc))
        return EXIT_CODE_SCAN_FAILED
    except OSError as exc:
        _print_scan_error(
            f"Could not write an output file: {exc}. "
            "Check the output path and directory permissions."
        )
        return EXIT_CODE_SCAN_FAILED


def _normalize_server_command(parts: Sequence[str] | None) -> tuple[str, ...]:
    """Return the subprocess command captured by ``--cmd``."""
    if parts is None:
        raise ValueError(
            "Missing --cmd. Pass a local stdio server command, for example: "
            "mcp-trust scan --cmd python examples/insecure-server/server.py"
        )

    normalized = tuple(part for part in parts if part != "--")
    if not normalized:
        raise ValueError(
            "Empty --cmd value. Pass a local stdio server command after --cmd, "
            "for example: mcp-trust scan --cmd python examples/insecure-server/server.py"
        )
    return normalized


def _normalize_min_score(value: int) -> int:
    """Validate the requested score threshold."""
    if not 0 <= value <= 100:
        raise ValueError("--min-score must be in the range 0..100.")
    return value


def _scan_server(options: ScanCommandOptions) -> Report:
    """Run discovery and deterministic scoring for one stdio server."""
    transport = StdioTransport()
    server = transport.scan(
        StdioServerConfig.from_command(
            options.command,
            timeout_seconds=options.timeout_seconds,
        )
    )
    return ScoringEngine(build_v0_rule_registry()).evaluate(server)


def _emit_outputs(report: Report, options: ScanCommandOptions) -> None:
    """Render terminal, JSON, and SARIF outputs for a completed report."""
    print(TerminalReporter().render(report), end="")
    if options.json_out is not None:
        _write_report_file(JsonReporter().render(report), options.json_out)
    if options.sarif_out is not None:
        _write_report_file(SarifReporter().render(report), options.sarif_out)


def _write_report_file(rendered_report: str, output_path_text: str) -> None:
    """Write one formatted report to disk."""
    output_path = Path(output_path_text)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered_report, encoding="utf-8")


def _enforce_min_score(total_score: int, min_score: int) -> int:
    """Return the final exit code after applying the score threshold."""
    if total_score >= min_score:
        return EXIT_CODE_SUCCESS

    print(
        (
            f"Score gate failed: total score {total_score} is below --min-score {min_score}. "
            "Lower the threshold or fix the reported findings."
        ),
        file=sys.stderr,
    )
    return EXIT_CODE_SCORE_BELOW_THRESHOLD


def _print_scan_error(message: str) -> None:
    """Print a user-facing technical scan error."""
    print(f"Scan failed: {message}", file=sys.stderr)
