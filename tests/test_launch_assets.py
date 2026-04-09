from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_sample_reports_exist_and_match_current_demo_shape() -> None:
    json_report = ROOT / "sample-reports" / "insecure-server.report.json"
    sarif_report = ROOT / "sample-reports" / "insecure-server.report.sarif"
    terminal_report = ROOT / "sample-reports" / "insecure-server.terminal.md"
    hero_image = ROOT / "docs" / "assets" / "filesystem-scan-hero.svg"

    json_data = json.loads(json_report.read_text(encoding="utf-8"))
    sarif_data = json.loads(sarif_report.read_text(encoding="utf-8"))
    terminal_text = terminal_report.read_text(encoding="utf-8")
    hero_svg = hero_image.read_text(encoding="utf-8")

    assert json_data["generator"]["product_name"] == "MCP Scorecard"
    assert json_data["scan"]["target"]["server_name"] == "Insecure Demo Server"
    assert "timestamp" in json_data["scan"]
    assert json_data["scorecard"]["total_score"]["value"] == 10
    assert json_data["scorecard"]["finding_counts"]["total"] == 7
    assert json_data["scorecard"]["why_this_score"] == (
        "Score is driven mainly by security findings in command execution and file system "
        "and ergonomics findings."
    )
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"]) == 1
    assert "scan_timestamp" in sarif_data["runs"][0]["properties"]
    assert sarif_data["runs"][0]["properties"]["report_schema_id"] == "mcp-scorecard-report"
    assert len(sarif_data["runs"][0]["results"]) == 7
    assert "```text" in terminal_text
    assert "Generator: MCP Scorecard (mcp-scorecard 1.0.0)" in terminal_text
    assert "Report Schema: mcp-scorecard-report@1.0" in terminal_text
    assert "Total Score: 10/100" in terminal_text
    assert "Findings By Bucket:" in terminal_text
    assert "40/100" in hero_svg
    assert "dangerous_fs_write_tool" in hero_svg


def test_docs_and_readme_link_launch_assets() -> None:
    architecture_doc = ROOT / "docs" / "architecture.md"
    batch_report = ROOT / "MCP_SCORECARD_30_SERVER_BATCH.md"
    batch_summary = ROOT / "MCP_SCORECARD_30_SERVER_BATCH.summary.json"
    readme_text = (ROOT / "README.md").read_text(encoding="utf-8")
    architecture_text = architecture_doc.read_text(encoding="utf-8")
    batch_text = batch_report.read_text(encoding="utf-8")
    batch_json = json.loads(batch_summary.read_text(encoding="utf-8"))

    assert "```mermaid" in architecture_text
    assert "sample-reports/insecure-server.report.json" in readme_text
    assert "sample-reports/insecure-server.report.sarif" in readme_text
    assert "sample-reports/insecure-server.terminal.md" in readme_text
    assert "docs/architecture.md" in readme_text
    assert "MCP_SCORECARD_30_SERVER_BATCH.md" in readme_text
    assert "MCP_SCORECARD_30_SERVER_BATCH.summary.json" in readme_text
    assert "docs/assets/filesystem-scan-hero.svg" in readme_text
    assert "@modelcontextprotocol/server-memory" in batch_text
    assert "@modelcontextprotocol/server-filesystem" in batch_text
    assert batch_json["batch"]["attempted"] == 30
