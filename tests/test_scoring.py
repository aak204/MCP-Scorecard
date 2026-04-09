from __future__ import annotations

import json

from mcp_trust import __package_name__, __product_name__, __tool_name__
from mcp_trust.models import (
    Finding,
    FindingCategory,
    FindingLevel,
    NormalizedServer,
    Report,
    RiskCategory,
    RuleDescriptor,
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
            bucket=ScoreCategory.CONFORMANCE,
            message="Spec issue.",
            penalty=15,
        ),
        Finding(
            rule_id="security.rule",
            level=FindingLevel.ERROR,
            category=FindingCategory.CAPABILITY,
            risk_category=RiskCategory.EXTERNAL_SIDE_EFFECTS,
            bucket=ScoreCategory.SECURITY,
            message="Security issue.",
            penalty=35,
        ),
        Finding(
            rule_id="tool.rule",
            level=FindingLevel.ERROR,
            category=FindingCategory.CAPABILITY,
            risk_category=RiskCategory.COMMAND_EXECUTION,
            bucket=ScoreCategory.ERGONOMICS,
            message="Tool surface issue.",
            penalty=80,
        ),
    )

    breakdown = ScoreBreakdown.from_findings(findings, max_score=100)

    assert breakdown.total_score == 0
    assert breakdown.total_penalty_points == 130
    assert breakdown.category_breakdown[ScoreCategory.CONFORMANCE].score == 85
    assert breakdown.category_breakdown[ScoreCategory.SECURITY].score == 65
    assert breakdown.category_breakdown[ScoreCategory.ERGONOMICS].score == 20
    assert breakdown.category_breakdown[ScoreCategory.METADATA].score == 100


def test_json_report_contains_total_score_and_bucket_grouping() -> None:
    server = NormalizedServer(target="stdio://demo")
    findings = (
        Finding(
            rule_id="tool.rule",
            level=FindingLevel.WARNING,
            category=FindingCategory.TOOL_DESCRIPTION,
            risk_category=RiskCategory.METADATA_HYGIENE,
            bucket=ScoreCategory.ERGONOMICS,
            title="Vague tool description",
            message="Tool description is too vague.",
            evidence=("description='stuff'",),
            penalty=10,
            tool_name="do_it",
        ),
    )
    rule_descriptors = {
        "tool.rule": RuleDescriptor(
            rule_id="tool.rule",
            title="Vague tool description",
            rationale="Tool descriptions should clearly explain what the tool does.",
            severity=FindingLevel.WARNING,
            category=FindingCategory.TOOL_DESCRIPTION,
            risk_category=RiskCategory.METADATA_HYGIENE,
            bucket=ScoreCategory.ERGONOMICS,
            score_impact=10,
            tags=("tools", "description"),
        )
    }
    report = Report(
        server=server,
        findings=findings,
        score=ScoreBreakdown.from_findings(findings),
        rule_descriptors=rule_descriptors,
    )

    json_data = report_to_json_data(report)
    rendered = JsonReporter().render(report)
    parsed = json.loads(rendered)

    assert json_data["schema"] == {
        "id": "mcp-scorecard-report",
        "version": "1.0",
    }
    assert json_data["generator"] == {
        "product_name": __product_name__,
        "tool_name": __tool_name__,
        "package_name": __package_name__,
        "package_version": report.toolkit_version,
    }
    assert json_data["scan"] == {
        "timestamp": report.generated_at.isoformat(),
        "target": {
            "raw": "stdio://demo",
            "transport": "stdio",
            "description": "Local MCP server launched over stdio.",
            "server_name": None,
            "server_version": None,
            "protocol_version": None,
            "metadata": {},
        },
    }
    assert json_data["inventory"] == {
        "tool_count": 0,
        "tools": [],
    }
    assert json_data["checks"] == [
        {
            "id": "tool.rule",
            "title": "Vague tool description",
            "bucket": "ergonomics",
            "severity": "warning",
            "rationale": "Tool descriptions should clearly explain what the tool does.",
            "category": "tool-description",
            "risk_category": "metadata_hygiene",
            "score_impact": 10,
            "tags": ["tools", "description"],
        }
    ]
    assert json_data["findings"][0] == {
        "check_id": "tool.rule",
        "title": "Vague tool description",
        "bucket": "ergonomics",
        "severity": "warning",
        "rationale": "Tool descriptions should clearly explain what the tool does.",
        "category": "tool-description",
        "risk_category": "metadata_hygiene",
        "tool_name": "do_it",
        "message": "Tool description is too vague.",
        "evidence": ["description='stuff'"],
        "score_impact": 10,
        "metadata": {},
    }
    assert json_data["grouped_findings"] == {
        "by_bucket": [
            {
                "bucket": "ergonomics",
                "label": "ergonomics",
                "finding_count": 1,
                "penalty_points": 10,
                "findings": [
                    {
                        "id": "tool.rule",
                        "title": "Vague tool description",
                        "severity": "warning",
                        "bucket": "ergonomics",
                        "risk_category": "metadata_hygiene",
                        "tool_name": "do_it",
                        "rationale": "Tool descriptions should clearly explain what the tool does.",
                        "message": "Tool description is too vague.",
                        "score_impact": 10,
                    }
                ],
            }
        ]
    }
    assert json_data["scorecard"] == {
        "total_score": {
            "value": 90,
            "max": 100,
            "penalty_points": 10,
        },
        "category_scores": {
            "conformance": {
                "score": 100,
                "max_score": 100,
                "penalty_points": 0,
                "finding_count": 0,
                "check_penalties": {},
            },
            "security": {
                "score": 100,
                "max_score": 100,
                "penalty_points": 0,
                "finding_count": 0,
                "check_penalties": {},
            },
            "ergonomics": {
                "score": 90,
                "max_score": 100,
                "penalty_points": 10,
                "finding_count": 1,
                "check_penalties": {"tool.rule": 10},
            },
            "metadata": {
                "score": 100,
                "max_score": 100,
                "penalty_points": 0,
                "finding_count": 0,
                "check_penalties": {},
            },
        },
        "finding_counts": {
            "total": 1,
            "by_severity": {
                "info": 0,
                "warning": 1,
                "error": 0,
            },
            "by_bucket": {
                "ergonomics": {
                    "finding_count": 1,
                    "penalty_points": 10,
                }
            },
        },
        "why_this_score": "Score is driven mainly by ergonomics findings.",
        "score_meaning": (
            "Deterministic CI-first quality scorecard based on conformance, "
            "security-relevant capabilities, ergonomics, and metadata hygiene."
        ),
        "limitations": [
            (
                "Low score means more deterministic findings or higher-risk exposed surface, "
                "not malicious intent."
            ),
            "High score means fewer deterministic findings, not a guarantee of safety.",
        ],
    }
    assert parsed["schema"]["version"] == "1.0"
    assert parsed["scan"]["timestamp"] == report.generated_at.isoformat()
    assert parsed["scorecard"]["total_score"]["value"] == 90
    assert parsed["findings"][0]["bucket"] == "ergonomics"
