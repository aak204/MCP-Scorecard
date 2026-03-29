"""Rule for schemas that explicitly allow arbitrary properties."""

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
from mcp_trust.rules.tool_helpers import additional_properties, schema_properties, schema_type


@dataclass(slots=True, frozen=True)
class SchemaAllowsArbitraryPropertiesRule(Rule):
    """Flag schemas that explicitly permit arbitrary additional properties."""

    rule_id: str = "schema_allows_arbitrary_properties"
    title: str = "Schema allows arbitrary properties"
    summary: str = "Tool input schemas should not allow arbitrary top-level properties."
    severity: FindingLevel = FindingLevel.WARNING
    category: FindingCategory = FindingCategory.INPUT_SCHEMA
    risk_category: RiskCategory = RiskCategory.SCHEMA_HYGIENE
    score_category: ScoreCategory = ScoreCategory.SPEC
    tags: tuple[str, ...] = ("schema", "validation")

    def evaluate(self, server: NormalizedServer) -> tuple[Finding, ...]:
        """Return findings for schemas with ``additionalProperties: true``."""
        findings: list[Finding] = []

        for tool in server.tools:
            if schema_type(tool.input_schema) != "object":
                continue
            if additional_properties(tool.input_schema) is not True:
                continue

            findings.append(
                self.make_finding(
                    f"Tool {tool.name!r} allows arbitrary additional input properties.",
                    tool_name=tool.name,
                    evidence=(
                        "additionalProperties=True",
                        f"property_count={len(schema_properties(tool.input_schema))}",
                    ),
                )
            )

        return tuple(findings)
