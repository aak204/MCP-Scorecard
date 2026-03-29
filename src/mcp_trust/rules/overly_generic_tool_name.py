"""Rule for tool names that are too generic to be meaningful."""

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
from mcp_trust.rules.tool_helpers import normalize_text

_GENERIC_NAMES = {
    "do_it",
    "helper",
    "tool",
    "utility",
    "misc",
    "misc_tool",
    "action",
    "process",
    "handler",
    "run",
}


@dataclass(slots=True, frozen=True)
class OverlyGenericToolNameRule(Rule):
    """Flag tool names that do not communicate behavior clearly."""

    rule_id: str = "overly_generic_tool_name"
    title: str = "Overly generic tool name"
    summary: str = "Tool names should communicate behavior clearly."
    severity: FindingLevel = FindingLevel.WARNING
    category: FindingCategory = FindingCategory.TOOL_IDENTITY
    risk_category: RiskCategory = RiskCategory.METADATA_HYGIENE
    score_category: ScoreCategory = ScoreCategory.SPEC
    tags: tuple[str, ...] = ("tools", "identity")

    def evaluate(self, server: NormalizedServer) -> tuple[Finding, ...]:
        """Return findings for tools with known generic names."""
        findings: list[Finding] = []

        for tool in server.tools:
            normalized_name = normalize_text(tool.name).replace("-", "_").replace(" ", "_")
            if normalized_name not in _GENERIC_NAMES:
                continue

            findings.append(
                self.make_finding(
                    f"Tool {tool.name!r} uses an overly generic name that hides its behavior.",
                    tool_name=tool.name,
                    evidence=(f"tool_name={tool.name!r}",),
                )
            )

        return tuple(findings)
