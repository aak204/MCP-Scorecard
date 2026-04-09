from __future__ import annotations

from pytest import CaptureFixture

from mcp_trust.cli import main


def test_cli_help_smoke(capsys: CaptureFixture[str]) -> None:
    exit_code = main([])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "mcp-scorecard" in captured.out
    assert "Deterministic CI-first quality scorecard for MCP servers." in captured.out
