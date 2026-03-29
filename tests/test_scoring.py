from __future__ import annotations

import json

from mcp_trust.models import (
    Finding,
    FindingCategory,
    FindingLevel,
    NormalizedServer,
    Report,
    RiskCategory,
    ScoreBreakdown,
    ScoreCategory,
)
from mcp_trust.reporters import JsonReporter, report_to_json_data


def test_score_breakdown_tracks_category_scores_and_clamps_total() -> None:
    findings = (
        Finding(
            rule_id="spec.rule",
            level=FindingLevel.WARNING,
            category=FindingCategory.INPUT_SCHEMA,
            risk_category=RiskCategory.SCHEMA_HYGIENE,
            score_category=ScoreCategory.SPEC,
            message="Spec issue.",
            penalty=15,
        ),
        Finding(
            rule_id="auth.rule",
            level=FindingLevel.ERROR,
            category=FindingCategory.CAPABILITY,
            risk_category=RiskCategory.EXTERNAL_SIDE_EFFECTS,
            score_category=ScoreCategory.AUTH,
            message="Auth issue.",
            penalty=35,
        ),
        Finding(
            rule_id="tool.rule",
            level=FindingLevel.ERROR,
            category=FindingCategory.CAPABILITY,
            risk_category=RiskCategory.COMMAND_EXECUTION,
            score_category=ScoreCategory.TOOL_SURFACE,
            message="Tool surface issue.",
            penalty=80,
        ),
    )

    breakdown = ScoreBreakdown.from_findings(findings, max_score=100)

    assert breakdown.total_score == 0
    assert breakdown.total_penalty_points == 130
    assert breakdown.category_breakdown[ScoreCategory.SPEC].score == 85
    assert breakdown.category_breakdown[ScoreCategory.AUTH].score == 65
    assert breakdown.category_breakdown[ScoreCategory.SECRETS].score == 100
    assert breakdown.category_breakdown[ScoreCategory.TOOL_SURFACE].score == 20


def test_json_report_contains_total_score_and_category_breakdown() -> None:
    server = NormalizedServer(target="stdio://demo")
    findings = (
        Finding(
            rule_id="tool.rule",
            level=FindingLevel.WARNING,
            category=FindingCategory.TOOL_DESCRIPTION,
            risk_category=RiskCategory.METADATA_HYGIENE,
            score_category=ScoreCategory.TOOL_SURFACE,
            title="Vague tool description",
            message="Tool description is too vague.",
            evidence=("description='stuff'",),
            penalty=10,
            tool_name="do_it",
        ),
    )
    report = Report(
        server=server,
        findings=findings,
        score=ScoreBreakdown.from_findings(findings),
    )

    json_data = report_to_json_data(report)
    rendered = JsonReporter().render(report)
    parsed = json.loads(rendered)

    assert json_data["total_score"] == 90
    assert json_data["summary"] == {
        "tool_count": 0,
        "finding_count": 1,
        "severity_counts": {
            "info": 0,
            "warning": 1,
            "error": 0,
        },
        "top_findings": [
            {
                "rule_id": "tool.rule",
                "title": "Vague tool description",
                "severity": "warning",
                "risk_category": "metadata_hygiene",
                "tool_name": "do_it",
                "message": "Tool description is too vague.",
                "score_impact": 10,
            }
        ],
        "risk_summary": [
            {
                "risk_category": "metadata_hygiene",
                "label": "metadata hygiene",
                "finding_count": 1,
                "penalty_points": 10,
                "tool_names": ["do_it"],
            }
        ],
        "why_score": "Score is driven mainly by detected metadata hygiene issues.",
        "review_first_tools": ["do_it"],
        "score_meaning": (
            "Deterministic surface-risk score based on protocol/tool hygiene "
            "and risky exposed capabilities."
        ),
        "score_limits": [
            "Low score means higher exposed surface risk, not malicious intent.",
            "High score means fewer deterministic findings, not a guarantee of safety.",
        ],
    }
    assert json_data["score"]["category_breakdown"] == {
        "spec": {
            "score": 100,
            "max_score": 100,
            "penalty_points": 0,
            "finding_count": 0,
            "rule_penalties": {},
        },
        "auth": {
            "score": 100,
            "max_score": 100,
            "penalty_points": 0,
            "finding_count": 0,
            "rule_penalties": {},
        },
        "secrets": {
            "score": 100,
            "max_score": 100,
            "penalty_points": 0,
            "finding_count": 0,
            "rule_penalties": {},
        },
        "tool_surface": {
            "score": 90,
            "max_score": 100,
            "penalty_points": 10,
            "finding_count": 1,
            "rule_penalties": {"tool.rule": 10},
        },
    }
    assert json_data["server"] == {
        "target": "stdio://demo",
        "name": None,
        "version": None,
        "metadata": {},
    }
    assert json_data["tools"] == []
    assert parsed["total_score"] == 90
    assert parsed["score"]["total_score"] == 90
    assert parsed["findings"][0]["score_category"] == "tool_surface"
