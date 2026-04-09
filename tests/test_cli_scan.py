from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from pytest import CaptureFixture

from mcp_trust.cli import build_parser, main
from mcp_trust.commands import EXIT_CODE_SCAN_FAILED, EXIT_CODE_SCORE_BELOW_THRESHOLD

FAKE_SERVER = Path(__file__).resolve().parents[1] / "examples" / "fake_stdio_server.py"
INSECURE_SERVER = (
    Path(__file__).resolve().parents[1] / "examples" / "insecure-server" / "server.py"
)


def test_scan_cli_discovers_tools_from_fake_stdio_server(
    capsys: CaptureFixture[str],
) -> None:
    exit_code = main(["scan", "--timeout", "1.0", "--cmd", sys.executable, str(FAKE_SERVER)])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Generator: MCP Scorecard (mcp-scorecard " in captured.out
    assert "Report Schema: mcp-scorecard-report@1.0" in captured.out
    assert "Scan Timestamp:" in captured.out
    assert "Server: Fake MCP Server" in captured.out
    assert "Protocol: 2025-11-25" in captured.out
    assert "Target: stdio:" in captured.out
    assert "Target Description: Local MCP server launched over stdio." in captured.out
    assert "Finding Counts: total=0, error=0, warning=0, info=0" in captured.out
    assert "Score Meaning:" in captured.out
    assert "Findings By Bucket:" in captured.out
    assert "- none" in captured.out
    assert "Total Score: 100/100" in captured.out


def test_scan_cli_returns_non_zero_when_score_is_below_threshold(
    capsys: CaptureFixture[str],
) -> None:
    exit_code = main(
        [
            "scan",
            "--min-score",
            "80",
            "--cmd",
            sys.executable,
            str(INSECURE_SERVER),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == EXIT_CODE_SCORE_BELOW_THRESHOLD
    assert "Total Score: 10/100" in captured.out
    assert "Findings By Bucket:" in captured.out
    assert "Score gate failed" in captured.err
    assert "--min-score 80" in captured.err


def test_scan_cli_returns_non_zero_when_scan_fails_technically(
    capsys: CaptureFixture[str],
) -> None:
    exit_code = main(["scan", "--cmd", "does-not-exist-mcp-server-command"])

    captured = capsys.readouterr()

    assert exit_code == EXIT_CODE_SCAN_FAILED
    assert "Scan failed:" in captured.err
    assert "Check --cmd" in captured.err


def test_scan_cli_help_mentions_main_flags(capsys: CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["scan", "--help"])

    help_text = capsys.readouterr().out

    assert "scan" in help_text
    assert "--cmd" in help_text
    assert "--json-out" in help_text
    assert "--sarif" in help_text
    assert "--min-score" in help_text


def test_scan_cli_writes_json_report(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    json_path = tmp_path / "report.json"

    exit_code = main(
        [
            "scan",
            "--json-out",
            str(json_path),
            "--cmd",
            sys.executable,
            str(FAKE_SERVER),
        ]
    )
    captured = capsys.readouterr()
    parsed = json.loads(json_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert "Total Score: 100/100" in captured.out
    assert parsed["scorecard"]["total_score"]["value"] == 100
