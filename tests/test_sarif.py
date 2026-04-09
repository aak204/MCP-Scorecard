from __future__ import annotations

import json
import sys
from pathlib import Path

from pytest import CaptureFixture

from mcp_trust.cli import main
from mcp_trust.reporters import SarifReporter, report_to_sarif_data
from mcp_trust.rules import build_v0_rule_registry
from mcp_trust.scoring import ScoringEngine
from mcp_trust.transports import StdioServerConfig, StdioTransport

INSECURE_SERVER = (
    Path(__file__).resolve().parents[1] / "examples" / "insecure-server" / "server.py"
)


def test_sarif_report_contains_rules_results_and_locations() -> None:
    transport = StdioTransport()
    server = transport.scan(
        StdioServerConfig.from_command(
            (sys.executable, str(INSECURE_SERVER)),
            timeout_seconds=1.0,
        )
    )
    report = ScoringEngine(build_v0_rule_registry()).evaluate(server)

    sarif_data = report_to_sarif_data(report)
    rendered = SarifReporter().render(report)
    parsed = json.loads(rendered)

    assert sarif_data["version"] == "2.1.0"
    assert parsed["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"

    runs = parsed["runs"]
    assert len(runs) == 1
    driver = runs[0]["tool"]["driver"]
    assert driver["name"] == "MCP Scorecard"
    assert runs[0]["properties"]["product_name"] == "MCP Scorecard"
    assert runs[0]["properties"]["tool_name"] == "mcp-scorecard"
    assert runs[0]["properties"]["report_schema_id"] == "mcp-scorecard-report"
    assert runs[0]["properties"]["report_schema_version"] == report.schema_version
    assert runs[0]["properties"]["scan_timestamp"] == report.generated_at.isoformat()
    assert runs[0]["invocations"][0]["endTimeUtc"] == report.generated_at.isoformat()
    assert {rule["id"] for rule in driver["rules"]} == {
        "duplicate_tool_names",
        "missing_tool_description",
        "overly_generic_tool_name",
        "vague_tool_description",
        "missing_schema_type",
        "schema_allows_arbitrary_properties",
        "weak_input_schema",
        "missing_required_for_critical_fields",
        "dangerous_exec_tool",
        "dangerous_shell_download_exec",
        "dangerous_fs_write_tool",
        "dangerous_fs_delete_tool",
        "dangerous_http_request_tool",
        "dangerous_network_tool",
        "write_tool_without_scope_hint",
        "tool_description_mentions_destructive_access",
    }

    results = runs[0]["results"]
    assert len(results) == 7
    assert {result["ruleId"] for result in results} == {
        "overly_generic_tool_name",
        "vague_tool_description",
        "schema_allows_arbitrary_properties",
        "weak_input_schema",
        "dangerous_exec_tool",
        "dangerous_fs_write_tool",
        "write_tool_without_scope_hint",
    }
    assert {result["level"] for result in results} == {"warning", "error"}
    assert all("risk_category" in result["properties"] for result in results)
    assert all("bucket" in result["properties"] for result in results)
    assert all("check_title" in result["properties"] for result in results)
    assert all("check_rationale" in result["properties"] for result in results)
    assert all("partialFingerprints" in result for result in results)
    assert all(
        result["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
        for result in results
    )
    assert all(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "examples/insecure-server/server.py"
        for result in results
    )


def test_scan_cli_writes_sarif_report(
    tmp_path: Path,
    capsys: CaptureFixture[str],
) -> None:
    sarif_path = tmp_path / "report.sarif"

    exit_code = main(
        [
            "scan",
            "--sarif",
            str(sarif_path),
            "--cmd",
            sys.executable,
            str(INSECURE_SERVER),
        ]
    )
    captured = capsys.readouterr()
    rendered = sarif_path.read_text(encoding="utf-8")
    parsed = json.loads(rendered)

    assert exit_code == 0
    assert "Total Score: 10/100" in captured.out
    assert parsed["version"] == "2.1.0"
    assert "scan_timestamp" in parsed["runs"][0]["properties"]
    assert parsed["runs"][0]["results"][0]["ruleId"] == "overly_generic_tool_name"
