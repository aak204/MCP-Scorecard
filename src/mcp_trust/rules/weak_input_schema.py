"""Rule for overly weak tool input schemas."""

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
    GENERIC_INPUT_KEYS,
    looks_like_inputful_tool,
    matching_keys,
    schema_properties,
    schema_type,
)


@dataclass(slots=True, frozen=True)
class WeakInputSchemaRule(Rule):
    """Flag schemas that accept unconstrained arbitrary payloads."""

    rule_id: str = "weak_input_schema"
    title: str = "Weak input schema"
    rationale: str = "Tool input schemas should constrain free-form payloads clearly."
    severity: FindingLevel = FindingLevel.WARNING
    category: FindingCategory = FindingCategory.INPUT_SCHEMA
    risk_category: RiskCategory = RiskCategory.SCHEMA_HYGIENE
    bucket: ScoreCategory = ScoreCategory.ERGONOMICS
    tags: tuple[str, ...] = ("schema", "validation")

    def evaluate(self, server: NormalizedServer) -> tuple[Finding, ...]:
        """Return findings for tools with weak or open-ended schemas."""
        findings: list[Finding] = []

        for tool in server.tools:
            reasons = self._collect_reasons(
                tool.name,
                tool.description,
                tool.input_schema,
            )
            if not reasons:
                continue

            findings.append(
                self.make_finding(
                    (
                        f"Tool {tool.name!r} exposes a weak input schema that leaves "
                        "free-form input underconstrained."
                    ),
                    tool_name=tool.name,
                    evidence=tuple(reasons),
                )
            )

        return tuple(findings)

    def _collect_reasons(
        self,
        name: str,
        description: str | None,
        input_schema: dict[str, JSONValue],
    ) -> tuple[str, ...]:
        """Return stable evidence lines for underconstrained payload schemas."""
        reasons: list[str] = []

        if schema_type(input_schema) != "object":
            return ()

        properties = schema_properties(input_schema)
        if not properties:
            if looks_like_inputful_tool(name, description):
                reasons.append("matched_heuristic=inputful_tool_with_empty_object_schema")
            return tuple(reasons)

        property_names = tuple(properties)
        generic_input_keys = matching_keys(property_names, GENERIC_INPUT_KEYS)
        weak_generic_keys: list[str] = []

        for key in generic_input_keys:
            property_schema = properties.get(key)
            if not isinstance(property_schema, dict):
                weak_generic_keys.append(key)
                continue

            property_type = property_schema.get("type")
            property_properties = property_schema.get("properties")
            property_additional_properties = property_schema.get("additionalProperties")
            if not isinstance(property_type, str):
                weak_generic_keys.append(key)
                continue
            if (
                property_type == "object"
                and not isinstance(property_properties, dict)
                and property_additional_properties is not False
            ):
                weak_generic_keys.append(key)

        if weak_generic_keys:
            reasons.append(f"generic_input_keys={weak_generic_keys!r}")

        return tuple(reasons)
