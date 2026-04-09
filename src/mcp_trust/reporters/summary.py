"""Shared report summary helpers used by output reporters."""

from __future__ import annotations

from typing import TypedDict

from mcp_trust.models import (
    Finding,
    FindingLevel,
    Report,
    RiskCategory,
    RuleDescriptor,
    ScoreCategory,
)

MAX_SUMMARY_FINDINGS = 5
MAX_REVIEW_FIRST_TOOLS = 5
SCORE_MEANING = (
    "Deterministic CI-first quality scorecard based on conformance, "
    "security-relevant capabilities, ergonomics, and metadata hygiene."
)
SCORE_LIMITS = (
    "Low score means more deterministic findings or higher-risk exposed surface, "
    "not malicious intent.",
    "High score means fewer deterministic findings, not a guarantee of safety.",
)

_SEVERITY_RANK = {
    FindingLevel.INFO: 0,
    FindingLevel.WARNING: 1,
    FindingLevel.ERROR: 2,
}
_BUCKET_LABELS = {
    ScoreCategory.CONFORMANCE: "conformance",
    ScoreCategory.SECURITY: "security",
    ScoreCategory.ERGONOMICS: "ergonomics",
    ScoreCategory.METADATA: "metadata",
}
_BUCKET_DISPLAY_PRIORITY = {
    ScoreCategory.SECURITY: 0,
    ScoreCategory.CONFORMANCE: 1,
    ScoreCategory.ERGONOMICS: 2,
    ScoreCategory.METADATA: 3,
}
_RISK_LABELS = {
    RiskCategory.FILE_SYSTEM: "file system",
    RiskCategory.COMMAND_EXECUTION: "command execution",
    RiskCategory.NETWORK: "network",
    RiskCategory.EXTERNAL_SIDE_EFFECTS: "external side effects",
    RiskCategory.SCHEMA_HYGIENE: "schema hygiene",
    RiskCategory.METADATA_HYGIENE: "metadata hygiene",
}


class SummaryFinding(TypedDict):
    """Compact finding representation used by reporters."""

    id: str
    title: str | None
    severity: str
    bucket: str
    risk_category: str
    tool_name: str | None
    rationale: str | None
    message: str
    score_impact: int


class SeverityCounts(TypedDict):
    """Severity counters exposed in the report summary."""

    info: int
    warning: int
    error: int


class BucketSummary(TypedDict):
    """Aggregated per-bucket information for a report."""

    bucket: str
    label: str
    finding_count: int
    penalty_points: int
    tool_names: list[str]
    risk_categories: list[str]


class BucketFindingsGroup(TypedDict):
    """All findings grouped under one score bucket."""

    bucket: str
    label: str
    finding_count: int
    penalty_points: int
    findings: list[SummaryFinding]


class ReportSummary(TypedDict):
    """Stable summary view shared by reporters."""

    tool_count: int
    finding_count: int
    severity_counts: SeverityCounts
    top_findings: list[SummaryFinding]
    bucket_summary: list[BucketSummary]
    findings_by_bucket: list[BucketFindingsGroup]
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
    bucket_summary = _build_bucket_summary(sorted_findings)

    return {
        "tool_count": len(report.server.tools),
        "finding_count": report.finding_count,
        "severity_counts": severity_counts,
        "top_findings": [
            _serialize_summary_finding(
                finding,
                report.rule_descriptors.get(finding.rule_id),
            )
            for finding in sorted_findings[:MAX_SUMMARY_FINDINGS]
        ],
        "bucket_summary": bucket_summary,
        "findings_by_bucket": _build_findings_by_bucket(
            sorted_findings,
            report.rule_descriptors,
            bucket_summary,
        ),
        "why_score": _build_why_score(bucket_summary),
        "review_first_tools": _build_review_first_tools(sorted_findings),
        "score_meaning": SCORE_MEANING,
        "score_limits": list(SCORE_LIMITS),
    }


def bucket_label(bucket: ScoreCategory) -> str:
    """Return a stable human-readable label for one score bucket."""
    return _BUCKET_LABELS[bucket]


def risk_label(risk_category: RiskCategory) -> str:
    """Return a stable human-readable label for one risk category."""
    return _RISK_LABELS[risk_category]


def _serialize_summary_finding(
    finding: Finding,
    descriptor: RuleDescriptor | None,
) -> SummaryFinding:
    """Return a short, stable summary representation of one finding."""
    rationale = None if descriptor is None else descriptor.rationale
    return {
        "id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "bucket": finding.bucket.value,
        "risk_category": finding.risk_category.value,
        "tool_name": finding.tool_name,
        "rationale": rationale,
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


def _build_bucket_summary(findings: list[Finding]) -> list[BucketSummary]:
    """Aggregate findings into stable score buckets."""
    bucket_counts: dict[ScoreCategory, int] = {}
    bucket_penalties: dict[ScoreCategory, int] = {}
    bucket_tools: dict[ScoreCategory, set[str]] = {}
    bucket_risk_penalties: dict[ScoreCategory, dict[RiskCategory, int]] = {}

    for finding in findings:
        bucket = finding.bucket
        bucket_counts[bucket] = bucket_counts.get(bucket, 0) + 1
        bucket_penalties[bucket] = bucket_penalties.get(bucket, 0) + finding.score_impact
        if finding.tool_name is not None:
            bucket_tools.setdefault(bucket, set()).add(finding.tool_name)
        bucket_risk_penalties.setdefault(bucket, {})
        bucket_risk_penalties[bucket][finding.risk_category] = (
            bucket_risk_penalties[bucket].get(finding.risk_category, 0) + finding.score_impact
        )

    ordered_buckets = sorted(
        bucket_counts,
        key=lambda bucket: (
            -bucket_penalties[bucket],
            _BUCKET_DISPLAY_PRIORITY[bucket],
            -bucket_counts[bucket],
        ),
    )

    summary: list[BucketSummary] = []
    for bucket in ordered_buckets:
        ordered_risks = sorted(
            bucket_risk_penalties[bucket],
            key=lambda risk_category: (
                -bucket_risk_penalties[bucket][risk_category],
                _RISK_LABELS[risk_category],
            ),
        )
        summary.append(
            {
                "bucket": bucket.value,
                "label": _BUCKET_LABELS[bucket],
                "finding_count": bucket_counts[bucket],
                "penalty_points": bucket_penalties[bucket],
                "tool_names": sorted(bucket_tools.get(bucket, set())),
                "risk_categories": [_RISK_LABELS[risk_category] for risk_category in ordered_risks],
            }
        )
    return summary


def _build_findings_by_bucket(
    findings: list[Finding],
    rule_descriptors: dict[str, RuleDescriptor],
    bucket_summary: list[BucketSummary],
) -> list[BucketFindingsGroup]:
    """Group all findings by score bucket using a stable bucket order."""
    grouped_findings: dict[ScoreCategory, list[SummaryFinding]] = {}

    for finding in findings:
        grouped_findings.setdefault(finding.bucket, []).append(
            _serialize_summary_finding(
                finding,
                rule_descriptors.get(finding.rule_id),
            )
        )

    return [
        {
            "bucket": bucket_info["bucket"],
            "label": bucket_info["label"],
            "finding_count": bucket_info["finding_count"],
            "penalty_points": bucket_info["penalty_points"],
            "findings": grouped_findings[ScoreCategory(bucket_info["bucket"])],
        }
        for bucket_info in bucket_summary
    ]


def _build_why_score(bucket_summary: list[BucketSummary]) -> str:
    """Return a short explanation for the score shape."""
    if not bucket_summary:
        return "No deterministic issues were detected in the current server surface."

    top_bucket_descriptions = [
        _describe_bucket(bucket_info)
        for bucket_info in bucket_summary[:2]
    ]
    if len(top_bucket_descriptions) == 1:
        return f"Score is driven mainly by {top_bucket_descriptions[0]}."
    return (
        "Score is driven mainly by "
        f"{top_bucket_descriptions[0]} and {top_bucket_descriptions[1]}."
    )


def _describe_bucket(bucket_info: BucketSummary) -> str:
    """Return a compact explanation of one bucket's contribution."""
    bucket_name = bucket_info["label"]
    risk_categories = bucket_info["risk_categories"][:2]

    if bucket_name == "security" and risk_categories:
        if len(risk_categories) == 1:
            return f"security findings in {risk_categories[0]}"
        return f"security findings in {risk_categories[0]} and {risk_categories[1]}"
    return f"{bucket_name} findings"


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
