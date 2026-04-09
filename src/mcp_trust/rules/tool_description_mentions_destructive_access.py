"""Rule for descriptions that explicitly advertise destructive unscoped access."""

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

_DESTRUCTIVE_MARKERS = ("delete", "remove", "erase", "overwrite", "truncate", "destroy")
_BROAD_SCOPE_MARKERS = (
    "arbitrary",
    "any file",
    "any directory",
    "host machine",
    "without validation",
)


@dataclass(slots=True, frozen=True)
class ToolDescriptionMentionsDestructiveAccessRule(Rule):
    """Flag descriptions that explicitly advertise broad destructive access."""

    rule_id: str = "tool_description_mentions_destructive_access"
    title: str = "Description mentions destructive access"
    rationale: str = "Tool descriptions should make destructive broad-scope access easy to spot."
    severity: FindingLevel = FindingLevel.WARNING
    category: FindingCategory = FindingCategory.CAPABILITY
    risk_category: RiskCategory = RiskCategory.EXTERNAL_SIDE_EFFECTS
    bucket: ScoreCategory = ScoreCategory.METADATA
    tags: tuple[str, ...] = ("tools", "description", "destructive")

    def evaluate(self, server: NormalizedServer) -> tuple[Finding, ...]:
        """Return findings for descriptions that explicitly advertise broad destructive access."""
        findings: list[Finding] = []

        for tool in server.tools:
            description = normalize_text(tool.description)
            if not description:
                continue

            matched_destructive = tuple(
                marker for marker in _DESTRUCTIVE_MARKERS if marker in description
            )
            matched_scope = tuple(
                marker for marker in _BROAD_SCOPE_MARKERS if marker in description
            )
            if not matched_destructive or not matched_scope:
                continue

            findings.append(
                self.make_finding(
                    (
                        f"Tool {tool.name!r} description explicitly advertises broad "
                        "destructive access."
                    ),
                    tool_name=tool.name,
                    evidence=(
                        f"destructive_markers={list(matched_destructive)!r}",
                        f"scope_markers={list(matched_scope)!r}",
                    ),
                )
            )

        return tuple(findings)
