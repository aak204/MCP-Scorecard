"""Terminal summary formatting for reports."""

from __future__ import annotations

from mcp_trust.models import Report, RiskCategory, ScoreCategory
from mcp_trust.reporters.summary import (
    SummaryFinding,
    build_report_summary,
    is_capability_category,
)


class TerminalReporter:
    """Render a concise terminal summary for a computed report."""

    reporter_id = "terminal"
    default_filename = "mcp-trust-summary.txt"

    def render(self, report: Report) -> str:
        """Render the report as plain text for terminal output."""
        summary = build_report_summary(report)
        severity_counts = summary["severity_counts"]
        protocol_version = _protocol_version(report)
        capability_labels = [
            bucket["label"]
            for bucket in summary["risk_summary"]
            if is_capability_category(RiskCategory(bucket["risk_category"]))
        ]
        high_risk_capabilities = ", ".join(capability_labels) if capability_labels else "none"
        review_first = ", ".join(summary["review_first_tools"]) or "none"

        lines = [
            f"Server: {report.server.name or '<unknown>'}",
            f"Version: {report.server.version or '<unknown>'}",
            f"Target: {report.server.target}",
            f"Tools: {summary['tool_count']}",
            f"Findings: {summary['finding_count']}",
            (
                "Severity: "
                f"error={severity_counts['error']}, "
                f"warning={severity_counts['warning']}, "
                f"info={severity_counts['info']}"
            ),
            f"Total Score: {report.total_score}/{report.score.max_score}",
            f"Score Meaning: {summary['score_meaning']}",
            f"Why This Score: {summary['why_score']}",
            f"High-Risk Capabilities: {high_risk_capabilities}",
            f"Review First: {review_first}",
            "Category Scores:",
        ]
        if protocol_version is not None:
            lines.insert(2, f"Protocol: {protocol_version}")

        for category in ScoreCategory:
            category_score = report.score.category_breakdown[category]
            lines.append(
                f"- {category.value}: {category_score.score}/{category_score.max_score} "
                f"(penalties: {category_score.penalty_points})"
            )

        lines.append("Top Findings:")
        if not summary["top_findings"]:
            lines.append("- none")
        else:
            for finding in summary["top_findings"]:
                lines.append(_format_finding_line(finding))

        lines.append("Score Limits:")
        for note in summary["score_limits"]:
            lines.append(f"- {note}")

        return "\n".join(lines) + "\n"


def _format_finding_line(finding: SummaryFinding) -> str:
    """Return one concise terminal line for a finding."""
    tool_name = finding["tool_name"]
    tool_suffix = "" if tool_name is None else f" [{tool_name}]"
    return (
        f"- {str(finding['severity']).upper()} {finding['rule_id']}{tool_suffix}: "
        f"{finding['message']}"
    )


def _protocol_version(report: Report) -> str | None:
    """Return protocol version from normalized server metadata when present."""
    mcp_metadata = report.server.metadata.get("mcp")
    if not isinstance(mcp_metadata, dict):
        return None
    protocol_version = mcp_metadata.get("protocolVersion")
    if not isinstance(protocol_version, str):
        return None
    return protocol_version
