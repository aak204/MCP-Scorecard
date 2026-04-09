"""Rule for tools without descriptions."""

from __future__ import annotations

from dataclasses import dataclass

from mcp_trust.models import (
    Finding,
    FindingCategory,
    FindingLevel,
    NormalizedServer,
    RiskCategory,
    ScoreCategory,
)
from mcp_trust.rules.base import Rule


@dataclass(slots=True, frozen=True)
class MissingToolDescriptionRule(Rule):
    """Flag tools that omit a human-readable description."""

    rule_id: str = "missing_tool_description"
    title: str = "Missing tool description"
    rationale: str = "Each tool should include a non-empty description."
    severity: FindingLevel = FindingLevel.WARNING
    category: FindingCategory = FindingCategory.TOOL_DESCRIPTION
    risk_category: RiskCategory = RiskCategory.METADATA_HYGIENE
    bucket: ScoreCategory = ScoreCategory.METADATA
    tags: tuple[str, ...] = ("tools", "description")

    def evaluate(self, server: NormalizedServer) -> tuple[Finding, ...]:
        """Return one finding per tool that lacks a description."""
        findings: list[Finding] = []

        for tool in server.tools:
            if tool.description is not None:
                continue

            findings.append(
                self.make_finding(
                    f"Tool {tool.name!r} does not provide a description.",
                    tool_name=tool.name,
                    evidence=(
                        f"tool_name={tool.name}",
                        "description=<missing>",
                    ),
                )
            )

        return tuple(findings)
