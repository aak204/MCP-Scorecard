"""Rule for critical schema properties that are not required."""

from __future__ import annotations

from dataclasses import dataclass

from mcp_trust.models import (
    Finding,
    FindingCategory,
    FindingLevel,
    JSONValue,
    NormalizedServer,
    RiskCategory,
    ScoreCategory,
)
from mcp_trust.rules.base import Rule
from mcp_trust.rules.tool_helpers import (
    schema_property_names,
    schema_required_fields,
    schema_type,
)

_CRITICAL_REQUIRED_KEYS = ("command", "path", "file_path", "filepath", "url", "uri", "endpoint")


@dataclass(slots=True, frozen=True)
class MissingRequiredForCriticalFieldsRule(Rule):
    """Flag critical schema properties that are not listed as required."""

    rule_id: str = "missing_required_for_critical_fields"
    title: str = "Missing required critical fields"
    summary: str = "Critical schema fields such as path, command, or URL should be required."
    severity: FindingLevel = FindingLevel.WARNING
    category: FindingCategory = FindingCategory.INPUT_SCHEMA
    risk_category: RiskCategory = RiskCategory.SCHEMA_HYGIENE
    score_category: ScoreCategory = ScoreCategory.SPEC
    tags: tuple[str, ...] = ("schema", "validation")

    def evaluate(self, server: NormalizedServer) -> tuple[Finding, ...]:
        """Return findings for object schemas with optional critical fields."""
        findings: list[Finding] = []

        for tool in server.tools:
            evidence = self._collect_evidence(tool.input_schema)
            if not evidence:
                continue

            findings.append(
                self.make_finding(
                    f"Tool {tool.name!r} defines critical input fields that are not required.",
                    tool_name=tool.name,
                    evidence=evidence,
                )
            )

        return tuple(findings)

    def _collect_evidence(self, input_schema: dict[str, JSONValue]) -> tuple[str, ...]:
        """Return stable evidence for missing required declarations."""
        if schema_type(input_schema) != "object":
            return ()

        property_names = schema_property_names(input_schema)
        required_fields = schema_required_fields(input_schema)
        optional_critical_fields = tuple(
            key
            for key in _CRITICAL_REQUIRED_KEYS
            if key in property_names and key not in required_fields
        )
        if not optional_critical_fields:
            return ()

        return (
            f"critical_fields={list(optional_critical_fields)!r}",
            f"required_fields={list(required_fields)!r}",
        )
