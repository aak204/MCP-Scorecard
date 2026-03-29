"""Shared report summary helpers used by output reporters."""

from __future__ import annotations

from typing import TypedDict

from mcp_trust.models import Finding, FindingLevel, Report, RiskCategory

MAX_SUMMARY_FINDINGS = 5
MAX_REVIEW_FIRST_TOOLS = 5
SCORE_MEANING = (
    "Deterministic surface-risk score based on protocol/tool hygiene "
    "and risky exposed capabilities."
)
SCORE_LIMITS = (
    "Low score means higher exposed surface risk, not malicious intent.",
    "High score means fewer deterministic findings, not a guarantee of safety.",
)

_SEVERITY_RANK = {
    FindingLevel.INFO: 0,
    FindingLevel.WARNING: 1,
    FindingLevel.ERROR: 2,
}
_RISK_LABELS = {
    RiskCategory.FILE_SYSTEM: "file system",
    RiskCategory.COMMAND_EXECUTION: "command execution",
    RiskCategory.NETWORK: "network",
    RiskCategory.EXTERNAL_SIDE_EFFECTS: "external side effects",
    RiskCategory.SCHEMA_HYGIENE: "schema hygiene",
    RiskCategory.METADATA_HYGIENE: "metadata hygiene",
}
_CAPABILITY_CATEGORIES = {
    RiskCategory.FILE_SYSTEM,
    RiskCategory.COMMAND_EXECUTION,
    RiskCategory.NETWORK,
    RiskCategory.EXTERNAL_SIDE_EFFECTS,
}


class SummaryFinding(TypedDict):
    """Compact finding representation used by reporters."""

    rule_id: str
    title: str | None
    severity: str
    risk_category: str
    tool_name: str | None
    message: str
    score_impact: int


class SeverityCounts(TypedDict):
    """Severity counters exposed in the report summary."""

    info: int
    warning: int
    error: int


class RiskBucketSummary(TypedDict):
    """Aggregated risk bucket information."""

    risk_category: str
    label: str
    finding_count: int
    penalty_points: int
    tool_names: list[str]


class ReportSummary(TypedDict):
    """Stable summary view shared by reporters."""

    tool_count: int
    finding_count: int
    severity_counts: SeverityCounts
    top_findings: list[SummaryFinding]
    risk_summary: list[RiskBucketSummary]
    why_score: str
    review_first_tools: list[str]
    score_meaning: str
    score_limits: list[str]


def build_report_summary(report: Report) -> ReportSummary:
    """Build a stable summary view from an already computed report."""
    sorted_findings = sorted(report.findings, key=_finding_sort_key)
    severity_counts: SeverityCounts = {
        "info": sum(1 for finding in report.findings if finding.severity is FindingLevel.INFO),
        "warning": sum(
            1 for finding in report.findings if finding.severity is FindingLevel.WARNING
        ),
        "error": sum(1 for finding in report.findings if finding.severity is FindingLevel.ERROR),
    }
    risk_summary = _build_risk_summary(sorted_findings)

    return {
        "tool_count": len(report.server.tools),
        "finding_count": report.finding_count,
        "severity_counts": severity_counts,
        "top_findings": [
            _serialize_summary_finding(finding)
            for finding in sorted_findings[:MAX_SUMMARY_FINDINGS]
        ],
        "risk_summary": risk_summary,
        "why_score": _build_why_score(risk_summary),
        "review_first_tools": _build_review_first_tools(sorted_findings),
        "score_meaning": SCORE_MEANING,
        "score_limits": list(SCORE_LIMITS),
    }


def risk_label(risk_category: RiskCategory) -> str:
    """Return a stable human-readable label for one risk category."""
    return _RISK_LABELS[risk_category]


def is_capability_category(risk_category: RiskCategory) -> bool:
    """Return whether the risk category represents exposed capability surface."""
    return risk_category in _CAPABILITY_CATEGORIES


def _serialize_summary_finding(finding: Finding) -> SummaryFinding:
    """Return a short, stable summary representation of one finding."""
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "risk_category": finding.risk_category.value,
        "tool_name": finding.tool_name,
        "message": finding.message,
        "score_impact": finding.score_impact,
    }


def _finding_sort_key(finding: Finding) -> tuple[int, int, str, str, str]:
    """Return a stable descending sort key for summary findings."""
    return (
        -finding.score_impact,
        -_SEVERITY_RANK[finding.severity],
        finding.tool_name or "",
        finding.rule_id,
        finding.message,
    )


def _build_risk_summary(findings: list[Finding]) -> list[RiskBucketSummary]:
    """Aggregate findings into stable risk buckets."""
    bucket_counts: dict[RiskCategory, int] = {}
    bucket_penalties: dict[RiskCategory, int] = {}
    bucket_tools: dict[RiskCategory, set[str]] = {}

    for finding in findings:
        category = finding.risk_category
        bucket_counts[category] = bucket_counts.get(category, 0) + 1
        bucket_penalties[category] = bucket_penalties.get(category, 0) + finding.score_impact
        if finding.tool_name is not None:
            bucket_tools.setdefault(category, set()).add(finding.tool_name)

    ordered_categories = sorted(
        bucket_counts,
        key=lambda category: (
            -bucket_penalties[category],
            -bucket_counts[category],
            _RISK_LABELS[category],
        ),
    )

    return [
        {
            "risk_category": category.value,
            "label": _RISK_LABELS[category],
            "finding_count": bucket_counts[category],
            "penalty_points": bucket_penalties[category],
            "tool_names": sorted(bucket_tools.get(category, set())),
        }
        for category in ordered_categories
    ]


def _build_why_score(risk_summary: list[RiskBucketSummary]) -> str:
    """Return a short explanation for the score shape."""
    if not risk_summary:
        return "No deterministic issues were detected in the current server surface."

    capability_labels = [
        bucket["label"]
        for bucket in risk_summary
        if is_capability_category(RiskCategory(bucket["risk_category"]))
    ]
    top_labels = capability_labels[:2]
    if not top_labels:
        top_labels = [bucket["label"] for bucket in risk_summary[:2]]

    if len(top_labels) == 1:
        return f"Score is driven mainly by detected {top_labels[0]} issues."
    return f"Score is driven mainly by detected {top_labels[0]} and {top_labels[1]} issues."


def _build_review_first_tools(findings: list[Finding]) -> list[str]:
    """Return a stable list of tools that deserve review first."""
    tool_penalties: dict[str, int] = {}
    tool_finding_counts: dict[str, int] = {}
    tool_severity_ranks: dict[str, int] = {}

    for finding in findings:
        if finding.tool_name is None:
            continue

        tool_penalties[finding.tool_name] = (
            tool_penalties.get(finding.tool_name, 0) + finding.score_impact
        )
        tool_finding_counts[finding.tool_name] = tool_finding_counts.get(finding.tool_name, 0) + 1
        tool_severity_ranks[finding.tool_name] = max(
            tool_severity_ranks.get(finding.tool_name, 0),
            _SEVERITY_RANK[finding.severity],
        )

    ordered_tools = sorted(
        tool_penalties,
        key=lambda tool_name: (
            -tool_penalties[tool_name],
            -tool_severity_ranks[tool_name],
            -tool_finding_counts[tool_name],
            tool_name,
        ),
    )
    return ordered_tools[:MAX_REVIEW_FIRST_TOOLS]
