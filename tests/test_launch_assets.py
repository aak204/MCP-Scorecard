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

    assert json_data["server"]["name"] == "Insecure Demo Server"
    assert "scan_timestamp" in json_data
    assert json_data["total_score"] == 10
    assert json_data["summary"]["finding_count"] == 7
    assert json_data["summary"]["why_score"] == (
        "Score is driven mainly by detected command execution and file system issues."
    )
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"]) == 1
    assert "scan_timestamp" in sarif_data["runs"][0]["properties"]
    assert len(sarif_data["runs"][0]["results"]) == 7
    assert "```text" in terminal_text
    assert "Total Score: 10/100" in terminal_text
    assert "40/100" in hero_svg
    assert "dangerous_fs_write_tool" in hero_svg


def test_docs_and_readme_link_launch_assets() -> None:
    architecture_doc = ROOT / "docs" / "architecture.md"
    validated_servers_doc = ROOT / "docs" / "validated-servers.md"
    readme_text = (ROOT / "README.md").read_text(encoding="utf-8")
    architecture_text = architecture_doc.read_text(encoding="utf-8")
    validated_text = validated_servers_doc.read_text(encoding="utf-8")

    assert "```mermaid" in architecture_text
    assert "sample-reports/insecure-server.report.json" in readme_text
    assert "sample-reports/insecure-server.report.sarif" in readme_text
    assert "sample-reports/insecure-server.terminal.md" in readme_text
    assert "docs/architecture.md" in readme_text
    assert "docs/validated-servers.md" in readme_text
    assert "docs/assets/filesystem-scan-hero.svg" in readme_text
    assert "@modelcontextprotocol/server-memory@2026.1.26" in validated_text
    assert "@modelcontextprotocol/server-filesystem@2026.1.14" in validated_text
