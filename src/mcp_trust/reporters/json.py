"""JSON report serialization."""

from __future__ import annotations

import json

from mcp_trust.models import (
    CategoryScoreBreakdown,
    Finding,
    NormalizedServer,
    NormalizedTool,
    Report,
    ScoreBreakdown,
    ScoreCategory,
)
from mcp_trust.reporters.summary import build_report_summary


class JsonReporter:
    """Render a report into a stable JSON document."""

    reporter_id = "json"
    default_filename = "mcp-trust-report.json"

    def render(self, report: Report) -> str:
        """Render the report as formatted JSON."""
        return json.dumps(report_to_json_data(report), indent=2, sort_keys=False) + "\n"


def report_to_json_data(report: Report) -> dict[str, object]:
    """Return a JSON-compatible representation of a report."""
    return {
        "schema_version": report.schema_version,
        "toolkit_version": report.toolkit_version,
        "generated_at": report.generated_at.isoformat(),
        "server": _serialize_server(report.server),
        "tools": [_serialize_tool(tool) for tool in report.server.tools],
        "findings": [_serialize_finding(finding) for finding in report.findings],
        "score": _serialize_score(report.score),
        "summary": build_report_summary(report),
        "total_score": report.total_score,
        "max_score": report.score.max_score,
        "penalty_points": report.score.total_penalty_points,
        "target": report.server.target,
        "metadata": dict(report.metadata),
    }


def _serialize_server(server: NormalizedServer) -> dict[str, object]:
    """Serialize normalized server data."""
    return {
        "target": server.target,
        "name": server.name,
        "version": server.version,
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


def _serialize_finding(finding: Finding) -> dict[str, object]:
    """Serialize one finding."""
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "category": None if finding.category is None else finding.category.value,
        "risk_category": finding.risk_category.value,
        "score_category": finding.score_category.value,
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


def _serialize_score(score: ScoreBreakdown) -> dict[str, object]:
    """Serialize the scoring breakdown section."""
    return {
        "total_score": score.total_score,
        "max_score": score.max_score,
        "penalty_points": score.total_penalty_points,
        "category_breakdown": _serialize_category_breakdown(score),
        "rule_penalties": dict(score.rule_penalties),
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
        "rule_penalties": dict(breakdown.rule_penalties),
    }
