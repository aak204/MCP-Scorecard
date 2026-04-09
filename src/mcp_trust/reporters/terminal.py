"""Terminal summary formatting for reports."""

from __future__ import annotations

from mcp_trust import __product_name__, __report_schema_id__, __tool_name__
from mcp_trust.models import Report, ScoreCategory
from mcp_trust.reporters.summary import BucketFindingsGroup, SummaryFinding, build_report_summary


class TerminalReporter:
    """Render a concise terminal summary for a computed report."""

    reporter_id = "terminal"
    default_filename = "mcp-scorecard-summary.txt"

    def render(self, report: Report) -> str:
        """Render the report as plain text for terminal output."""
        summary = build_report_summary(report)
        severity_counts = summary["severity_counts"]
        scan_timestamp = report.scan_timestamp.isoformat()
        protocol_version = _protocol_version(report)

        lines = [
            f"Generator: {__product_name__} ({__tool_name__} {report.toolkit_version})",
            f"Report Schema: {__report_schema_id__}@{report.schema_version}",
            f"Scan Timestamp: {scan_timestamp}",
            f"Server: {report.server.name or '<unknown>'}",
            f"Version: {report.server.version or '<unknown>'}",
            f"Target: {report.server.target}",
            f"Target Description: {_target_description(report)}",
            f"Tools: {summary['tool_count']}",
            (
                "Finding Counts: "
                f"total={summary['finding_count']}, "
                f"error={severity_counts['error']}, "
                f"warning={severity_counts['warning']}, "
                f"info={severity_counts['info']}"
            ),
            f"Total Score: {report.total_score}/{report.score.max_score}",
            f"Why This Score: {summary['why_score']}",
            f"Score Meaning: {summary['score_meaning']}",
            "Category Scores:",
        ]
        if protocol_version is not None:
            lines.insert(5, f"Protocol: {protocol_version}")

        for category in ScoreCategory:
            category_score = report.score.category_breakdown[category]
            lines.append(
                f"- {category.value}: {category_score.score}/{category_score.max_score} "
                f"(findings: {category_score.finding_count}, "
                f"penalties: {category_score.penalty_points})"
            )

        lines.append("Findings By Bucket:")
        if not summary["findings_by_bucket"]:
            lines.append("- none")
        else:
            for bucket_group in summary["findings_by_bucket"]:
                lines.extend(_format_bucket_group(bucket_group))

        lines.append("Limitations:")
        for note in summary["score_limits"]:
            lines.append(f"- {note}")

        return "\n".join(lines) + "\n"


def _format_finding_line(finding: SummaryFinding) -> str:
    """Return one concise terminal line for a finding."""
    tool_name = finding["tool_name"]
    tool_suffix = "" if tool_name is None else f" [{tool_name}]"
    return (
        f"- {str(finding['severity']).upper()} {finding['id']}{tool_suffix}: "
        f"{finding['message']}"
    )


def _format_bucket_group(bucket_group: BucketFindingsGroup) -> list[str]:
    """Return terminal lines for one grouped bucket section."""
    finding_word = "finding" if bucket_group["finding_count"] == 1 else "findings"
    header = (
        f"- {bucket_group['label']}: {bucket_group['finding_count']} {finding_word}, "
        f"penalties: {bucket_group['penalty_points']}"
    )
    lines = [header]
    for finding in bucket_group["findings"]:
        lines.append(f"  {_format_finding_line(finding)}")
    return lines


def _protocol_version(report: Report) -> str | None:
    """Return protocol version from normalized server metadata when present."""
    mcp_metadata = report.server.metadata.get("mcp")
    if not isinstance(mcp_metadata, dict):
        return None
    protocol_version = mcp_metadata.get("protocolVersion")
    if not isinstance(protocol_version, str):
        return None
    return protocol_version


def _target_description(report: Report) -> str:
    """Return a stable human-readable description of the scan target."""
    mcp_metadata = report.server.metadata.get("mcp")
    if isinstance(mcp_metadata, dict):
        transport = mcp_metadata.get("transport")
        if transport == "stdio":
            return "Local MCP server launched over stdio."
        if isinstance(transport, str) and transport.strip():
            return f"MCP server target evaluated over {transport.strip()}."

    prefix, separator, _ = report.server.target.partition(":")
    if separator and prefix == "stdio":
        return "Local MCP server launched over stdio."
    if separator and prefix:
        return f"MCP server target evaluated over {prefix}."
    return "MCP server target under evaluation."
