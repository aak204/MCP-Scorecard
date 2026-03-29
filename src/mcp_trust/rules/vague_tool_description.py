"""Rule for descriptions that are too vague to be useful."""

from __future__ import annotations

import re
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

_WORD_RE = re.compile(r"[a-z0-9]+")
_VAGUE_PHRASES = {
    "helps with stuff",
    "does things",
    "tool",
    "utility tool",
    "misc helper",
    "general helper",
}
_VAGUE_WORDS = {
    "stuff",
    "things",
    "helper",
    "misc",
    "various",
    "general",
}


@dataclass(slots=True, frozen=True)
class VagueToolDescriptionRule(Rule):
    """Flag very short or generic tool descriptions."""

    rule_id: str = "vague_tool_description"
    title: str = "Vague tool description"
    summary: str = "Tool descriptions should clearly explain what the tool does."
    severity: FindingLevel = FindingLevel.WARNING
    category: FindingCategory = FindingCategory.TOOL_DESCRIPTION
    risk_category: RiskCategory = RiskCategory.METADATA_HYGIENE
    score_category: ScoreCategory = ScoreCategory.SPEC
    tags: tuple[str, ...] = ("tools", "description")

    def evaluate(self, server: NormalizedServer) -> tuple[Finding, ...]:
        """Return findings for descriptions matched by transparent heuristics."""
        findings: list[Finding] = []

        for tool in server.tools:
            if tool.description is None:
                continue

            normalized_description = " ".join(_WORD_RE.findall(tool.description.lower()))
            if not normalized_description:
                continue

            words = tuple(normalized_description.split())
            is_known_vague_phrase = normalized_description in _VAGUE_PHRASES
            is_short_and_generic = len(words) <= 3 and any(
                word in _VAGUE_WORDS for word in words
            )

            if not (is_known_vague_phrase or is_short_and_generic):
                continue

            evidence = [
                f"description={tool.description!r}",
                f"word_count={len(words)}",
            ]
            if is_known_vague_phrase:
                evidence.append(f"matched_phrase={normalized_description!r}")
            else:
                evidence.append("matched_heuristic=short_generic_description")

            findings.append(
                self.make_finding(
                    (
                        f"Tool {tool.name!r} uses a vague description that does not "
                        "explain its behavior clearly."
                    ),
                    tool_name=tool.name,
                    evidence=tuple(evidence),
                )
            )

        return tuple(findings)
