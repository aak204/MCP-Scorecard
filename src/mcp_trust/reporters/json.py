"""JSON report serialization."""

from __future__ import annotations

import json
from collections.abc import Mapping

from mcp_trust import (
    __package_name__,
    __product_name__,
    __report_schema_id__,
    __tool_name__,
)
from mcp_trust.models import (
    CategoryScoreBreakdown,
    Finding,
    JSONValue,
    NormalizedServer,
    NormalizedTool,
    Report,
    RuleDescriptor,
    ScoreBreakdown,
    ScoreCategory,
)
from mcp_trust.reporters.summary import ReportSummary, build_report_summary


class JsonReporter:
    """Render a report into a stable JSON document."""

    reporter_id = "json"
    default_filename = "mcp-scorecard-report.json"

    def render(self, report: Report) -> str:
        """Render the report as formatted JSON."""
        return json.dumps(report_to_json_data(report), indent=2, sort_keys=False) + "\n"


def report_to_json_data(report: Report) -> dict[str, object]:
    """Return a JSON-compatible representation of a report."""
    scan_timestamp = report.scan_timestamp.isoformat()
    summary = build_report_summary(report)
    return {
        "schema": {
            "id": __report_schema_id__,
            "version": report.schema_version,
        },
        "generator": {
            "product_name": __product_name__,
            "tool_name": __tool_name__,
            "package_name": __package_name__,
            "package_version": report.toolkit_version,
        },
        "scan": {
            "timestamp": scan_timestamp,
            "target": _serialize_target(report.server),
        },
        "inventory": {
            "tool_count": summary["tool_count"],
            "tools": [_serialize_tool(tool) for tool in report.server.tools],
        },
        "scorecard": {
            "total_score": {
                "value": report.total_score,
                "max": report.score.max_score,
                "penalty_points": report.score.total_penalty_points,
            },
            "category_scores": _serialize_category_breakdown(report.score),
            "finding_counts": _serialize_finding_counts(summary),
            "why_this_score": summary["why_score"],
            "score_meaning": summary["score_meaning"],
            "limitations": list(summary["score_limits"]),
        },
        "checks": [
            _serialize_rule_descriptor(rule_descriptor)
            for rule_descriptor in report.rule_descriptors.values()
        ],
        "findings": [
            _serialize_finding(
                finding,
                report.rule_descriptors.get(finding.rule_id),
            )
            for finding in report.findings
        ],
        "grouped_findings": {
            "by_bucket": summary["findings_by_bucket"],
        },
        "metadata": dict(report.metadata),
    }


def _serialize_target(server: NormalizedServer) -> dict[str, object]:
    """Serialize scan target information."""
    transport = _infer_transport(server.target, server.metadata)
    return {
        "raw": server.target,
        "transport": transport,
        "description": _target_description(transport),
        "server_name": server.name,
        "server_version": server.version,
        "protocol_version": _protocol_version(server),
        "metadata": dict(server.metadata),
    }


def _serialize_tool(tool: NormalizedTool) -> dict[str, object]:
    """Serialize one normalized tool."""
    return {
        "name": tool.name,
        "description": tool.description,
        "input_schema": dict(tool.input_schema),
        "metadata": dict(tool.metadata),
    }


def _serialize_rule_descriptor(rule_descriptor: RuleDescriptor) -> dict[str, object]:
    """Serialize one check descriptor."""
    return {
        "id": rule_descriptor.id,
        "title": rule_descriptor.title,
        "bucket": rule_descriptor.bucket.value,
        "severity": rule_descriptor.severity.value,
        "rationale": rule_descriptor.rationale,
        "category": rule_descriptor.category.value,
        "risk_category": rule_descriptor.risk_category.value,
        "score_impact": rule_descriptor.score_impact,
        "tags": list(rule_descriptor.tags),
    }


def _serialize_finding(
    finding: Finding,
    descriptor: RuleDescriptor | None,
) -> dict[str, object]:
    """Serialize one finding."""
    title = finding.title
    rationale = None
    if descriptor is not None:
        if title is None:
            title = descriptor.title
        rationale = descriptor.rationale

    return {
        "check_id": finding.rule_id,
        "title": title,
        "bucket": finding.bucket.value,
        "severity": finding.severity.value,
        "rationale": rationale,
        "category": None if finding.category is None else finding.category.value,
        "risk_category": finding.risk_category.value,
        "tool_name": finding.tool_name,
        "message": finding.message,
        "evidence": list(finding.evidence),
        "score_impact": finding.score_impact,
        "metadata": dict(finding.metadata),
    }


def _serialize_category_breakdown(score: ScoreBreakdown) -> dict[str, object]:
    """Serialize category-level scoring data."""
    return {
        category.value: _serialize_category_score(score.category_breakdown[category])
        for category in ScoreCategory
    }


def _serialize_category_score(
    breakdown: CategoryScoreBreakdown,
) -> dict[str, object]:
    """Serialize one category score."""
    return {
        "score": breakdown.score,
        "max_score": breakdown.max_score,
        "penalty_points": breakdown.penalty_points,
        "finding_count": breakdown.finding_count,
        "check_penalties": dict(breakdown.rule_penalties),
    }


def _serialize_finding_counts(summary: ReportSummary) -> dict[str, object]:
    """Serialize finding counters for the scorecard section."""
    bucket_summary = summary["bucket_summary"]
    by_bucket = {
        bucket_info["bucket"]: {
            "finding_count": bucket_info["finding_count"],
            "penalty_points": bucket_info["penalty_points"],
        }
        for bucket_info in bucket_summary
    }
    return {
        "total": summary["finding_count"],
        "by_severity": summary["severity_counts"],
        "by_bucket": by_bucket,
    }


def _infer_transport(target: str, metadata: Mapping[str, JSONValue]) -> str | None:
    """Infer target transport from normalized target text or metadata."""
    mcp_metadata = metadata.get("mcp")
    if isinstance(mcp_metadata, dict):
        transport = mcp_metadata.get("transport")
        if isinstance(transport, str) and transport.strip():
            return transport.strip()

    prefix, separator, _ = target.partition(":")
    if separator and prefix:
        return prefix
    return None


def _target_description(transport: str | None) -> str:
    """Return a stable human-readable description of the scan target."""
    if transport == "stdio":
        return "Local MCP server launched over stdio."
    if transport is not None:
        return f"MCP server target evaluated over {transport}."
    return "MCP server target under evaluation."


def _protocol_version(server: NormalizedServer) -> str | None:
    """Return protocol version from normalized server metadata when present."""
    mcp_metadata = server.metadata.get("mcp")
    if not isinstance(mcp_metadata, dict):
        return None
    protocol_version = mcp_metadata.get("protocolVersion")
    if not isinstance(protocol_version, str):
        return None
    return protocol_version
