from __future__ import annotations

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
            score_category=ScoreCategory.TOOL_SURFACE,
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
            score_category=ScoreCategory.SPEC,
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
        "Server: Demo Server",
        "Version: 1.0.0",
        "Protocol: 2025-11-25",
        'Target: stdio:["python","demo.py"]',
        "Tools: 2",
        "Findings: 2",
        "Severity: error=1, warning=1, info=0",
        "Total Score: 70/100",
        (
            "Score Meaning: Deterministic surface-risk score based on protocol/tool hygiene "
            "and risky exposed capabilities."
        ),
        (
            "Why This Score: Score is driven mainly by detected command execution issues."
        ),
        "High-Risk Capabilities: command execution",
        "Review First: exec_command, do_it",
        "Category Scores:",
        "- spec: 90/100 (penalties: 10)",
        "- auth: 100/100 (penalties: 0)",
        "- secrets: 100/100 (penalties: 0)",
        "- tool_surface: 80/100 (penalties: 20)",
        "Top Findings:",
        (
            "- ERROR dangerous_exec_tool [exec_command]: Tool 'exec_command' "
            "appears to expose host command execution."
        ),
        (
            "- WARNING vague_tool_description [do_it]: Tool 'do_it' uses a vague "
            "description that does not explain its behavior clearly."
        ),
        "Score Limits:",
        "- Low score means higher exposed surface risk, not malicious intent.",
        "- High score means fewer deterministic findings, not a guarantee of safety.",
    ]
