from __future__ import annotations

from mcp_trust import __product_name__, __report_schema_id__, __tool_name__
from mcp_trust.models import (
    Finding,
    FindingCategory,
    FindingLevel,
    NormalizedServer,
    NormalizedTool,
    Report,
    RiskCategory,
    ScoreBreakdown,
    ScoreCategory,
)
from mcp_trust.reporters import TerminalReporter


def test_terminal_reporter_renders_stable_summary() -> None:
    server = NormalizedServer(
        target='stdio:["python","demo.py"]',
        name="Demo Server",
        version="1.0.0",
        tools=(
            NormalizedTool(
                name="exec_command",
                description="Execute a command.",
                input_schema={
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                    "required": ["command"],
                    "additionalProperties": False,
                },
            ),
            NormalizedTool(
                name="do_it",
                description="Helps with stuff.",
                input_schema={
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                    "required": ["target"],
                    "additionalProperties": False,
                },
            ),
        ),
        metadata={"mcp": {"protocolVersion": "2025-11-25"}},
    )
    findings = (
        Finding(
            rule_id="dangerous_exec_tool",
            level=FindingLevel.ERROR,
            title="Dangerous execution tool",
            category=FindingCategory.CAPABILITY,
            risk_category=RiskCategory.COMMAND_EXECUTION,
            bucket=ScoreCategory.SECURITY,
            message="Tool 'exec_command' appears to expose host command execution.",
            evidence=("input_keys=['command']",),
            penalty=20,
            tool_name="exec_command",
        ),
        Finding(
            rule_id="vague_tool_description",
            level=FindingLevel.WARNING,
            title="Vague tool description",
            category=FindingCategory.TOOL_DESCRIPTION,
            risk_category=RiskCategory.METADATA_HYGIENE,
            bucket=ScoreCategory.ERGONOMICS,
            message=(
                "Tool 'do_it' uses a vague description that does not "
                "explain its behavior clearly."
            ),
            evidence=("matched_phrase='helps with stuff'",),
            penalty=10,
            tool_name="do_it",
        ),
    )
    report = Report(
        server=server,
        findings=findings,
        score=ScoreBreakdown.from_findings(findings),
    )

    rendered = TerminalReporter().render(report)

    assert rendered.splitlines() == [
        f"Generator: {__product_name__} ({__tool_name__} {report.toolkit_version})",
        f"Report Schema: {__report_schema_id__}@{report.schema_version}",
        f"Scan Timestamp: {report.generated_at.isoformat()}",
        "Server: Demo Server",
        "Version: 1.0.0",
        "Protocol: 2025-11-25",
        'Target: stdio:["python","demo.py"]',
        "Target Description: Local MCP server launched over stdio.",
        "Tools: 2",
        "Finding Counts: total=2, error=1, warning=1, info=0",
        "Total Score: 70/100",
        (
            "Why This Score: Score is driven mainly by security findings in command execution "
            "and ergonomics findings."
        ),
        (
            "Score Meaning: Deterministic CI-first quality scorecard based on conformance, "
            "security-relevant capabilities, ergonomics, and metadata hygiene."
        ),
        "Category Scores:",
        "- conformance: 100/100 (findings: 0, penalties: 0)",
        "- security: 80/100 (findings: 1, penalties: 20)",
        "- ergonomics: 90/100 (findings: 1, penalties: 10)",
        "- metadata: 100/100 (findings: 0, penalties: 0)",
        "Findings By Bucket:",
        "- security: 1 finding, penalties: 20",
        (
            "  - ERROR dangerous_exec_tool [exec_command]: Tool 'exec_command' "
            "appears to expose host command execution."
        ),
        "- ergonomics: 1 finding, penalties: 10",
        (
            "  - WARNING vague_tool_description [do_it]: Tool 'do_it' uses a vague "
            "description that does not explain its behavior clearly."
        ),
        "Limitations:",
        (
            "- Low score means more deterministic findings or higher-risk exposed surface, "
            "not malicious intent."
        ),
        "- High score means fewer deterministic findings, not a guarantee of safety.",
    ]
