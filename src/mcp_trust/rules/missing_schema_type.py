"""Rule for missing top-level input schema types."""

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
from mcp_trust.rules.tool_helpers import looks_like_inputful_tool, schema_type


@dataclass(slots=True, frozen=True)
class MissingSchemaTypeRule(Rule):
    """Flag schemas that omit the top-level ``type`` field."""

    rule_id: str = "missing_schema_type"
    title: str = "Missing schema type"
    rationale: str = "Tool input schemas should declare a top-level type."
    severity: FindingLevel = FindingLevel.WARNING
    category: FindingCategory = FindingCategory.INPUT_SCHEMA
    risk_category: RiskCategory = RiskCategory.SCHEMA_HYGIENE
    bucket: ScoreCategory = ScoreCategory.CONFORMANCE
    tags: tuple[str, ...] = ("schema", "validation")

    def evaluate(self, server: NormalizedServer) -> tuple[Finding, ...]:
        """Return findings for tools whose schemas omit a top-level type."""
        findings: list[Finding] = []

        for tool in server.tools:
            if schema_type(tool.input_schema) is not None:
                continue
            if not tool.input_schema and not looks_like_inputful_tool(tool.name, tool.description):
                continue

            findings.append(
                self.make_finding(
                    f"Tool {tool.name!r} omits the top-level input schema type.",
                    tool_name=tool.name,
                    evidence=("schema_type=<missing>",),
                )
            )

        return tuple(findings)
