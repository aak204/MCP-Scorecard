"""Rule for duplicate MCP tool names."""

from __future__ import annotations

from collections import Counter
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
class DuplicateToolNamesRule(Rule):
    """Flag duplicate tool names after normalization."""

    rule_id: str = "duplicate_tool_names"
    title: str = "Duplicate tool names"
    rationale: str = "Tool names should be unique within one MCP server."
    severity: FindingLevel = FindingLevel.ERROR
    category: FindingCategory = FindingCategory.TOOL_IDENTITY
    risk_category: RiskCategory = RiskCategory.METADATA_HYGIENE
    bucket: ScoreCategory = ScoreCategory.CONFORMANCE
    tags: tuple[str, ...] = ("tools", "identity")

    def evaluate(self, server: NormalizedServer) -> tuple[Finding, ...]:
        """Return one finding per duplicated tool name."""
        counts = Counter(tool.name for tool in server.tools)
        findings: list[Finding] = []

        for tool_name, count in counts.items():
            if count < 2:
                continue

            findings.append(
                self.make_finding(
                    f"Tool name {tool_name!r} appears {count} times in the server tool list.",
                    tool_name=tool_name,
                    evidence=(
                        f"duplicate_count={count}",
                        f"tool_name={tool_name}",
                    ),
                )
            )

        return tuple(findings)
