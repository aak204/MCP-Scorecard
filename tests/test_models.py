from __future__ import annotations

from datetime import UTC, datetime

import pytest

from mcp_trust.models import (
    CategoryScoreBreakdown,
    Finding,
    FindingLevel,
    NormalizedServer,
    NormalizedTool,
    Report,
    ScoreBreakdown,
    ScoreCategory,
)


def test_normalized_server_preserves_normalized_tools() -> None:
    tool = NormalizedTool(
        name="  list_tools  ",
        description="  Return all tools.  ",
        input_schema={"type": "object"},
    )

    server = NormalizedServer(
        target="  stdio://demo-server  ",
        name="  Demo Server  ",
        version="  1.2.3  ",
        tools=[tool],
    )

    assert server.target == "stdio://demo-server"
    assert server.name == "Demo Server"
    assert server.version == "1.2.3"
    assert server.tool_names == ("list_tools",)
    assert server.tools[0].description == "Return all tools."


def test_score_breakdown_aggregates_rule_penalties_and_clamps_to_zero() -> None:
    findings = (
        Finding(
            rule_id="rule.alpha",
            level=FindingLevel.WARNING,
            message="Alpha finding.",
            bucket=ScoreCategory.SECURITY,
            penalty=15,
        ),
        Finding(
            rule_id="rule.alpha",
            level=FindingLevel.INFO,
            message="Alpha informational finding.",
            bucket=ScoreCategory.SECURITY,
            penalty=5,
        ),
        Finding(
            rule_id="rule.beta",
            level=FindingLevel.ERROR,
            message="Beta finding.",
            bucket=ScoreCategory.SECURITY,
            penalty=95,
        ),
    )

    breakdown = ScoreBreakdown.from_findings(findings, max_score=100)

    assert breakdown.penalty_points == 115
    assert breakdown.final_score == 0
    assert breakdown.rule_penalties == {"rule.alpha": 20, "rule.beta": 95}
    assert breakdown.category_breakdown[ScoreCategory.SECURITY].penalty_points == 115
    assert breakdown.category_breakdown[ScoreCategory.SECURITY].score == 0
    assert breakdown.category_breakdown[ScoreCategory.CONFORMANCE].score == 100


def test_report_requires_timezone_aware_timestamp() -> None:
    server = NormalizedServer(target="stdio://demo")
    empty_category_breakdown = {
        category: CategoryScoreBreakdown(
            category=category,
            max_score=100,
            penalty_points=0,
            score=100,
            finding_count=0,
        )
        for category in ScoreCategory
    }
    score = ScoreBreakdown(
        max_score=100,
        total_penalty_points=0,
        total_score=100,
        category_breakdown=empty_category_breakdown,
        rule_penalties={},
    )

    with pytest.raises(ValueError, match="timezone-aware"):
        Report(
            server=server,
            findings=(),
            score=score,
            generated_at=datetime(2026, 3, 29),
        )

    report = Report(
        server=server,
        findings=(),
        score=score,
        generated_at=datetime(2026, 3, 29, tzinfo=UTC),
    )

    assert report.finding_count == 0
