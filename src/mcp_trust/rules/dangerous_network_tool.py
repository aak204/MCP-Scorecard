"""Rule for generic network capability tools."""

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
    URL_KEYS,
    matching_keys,
    normalize_text,
    schema_property_names,
)

_NAME_MARKERS = ("connect", "socket", "proxy", "tunnel", "forward", "listen", "tcp", "udp")
_DESCRIPTION_MARKERS = (
    "network",
    "socket",
    "tcp",
    "udp",
    "port",
    "remote host",
    "proxy",
    "tunnel",
)
_NETWORK_KEYS = URL_KEYS + ("port", "address")


@dataclass(slots=True, frozen=True)
class DangerousNetworkToolRule(Rule):
    """Flag tools that expose generic network primitives."""

    rule_id: str = "dangerous_network_tool"
    title: str = "Dangerous network tool"
    rationale: str = "Tools that expose generic network access are high risk."
    severity: FindingLevel = FindingLevel.ERROR
    category: FindingCategory = FindingCategory.CAPABILITY
    risk_category: RiskCategory = RiskCategory.NETWORK
    bucket: ScoreCategory = ScoreCategory.SECURITY
    tags: tuple[str, ...] = ("capability", "network")

    def evaluate(self, server: NormalizedServer) -> tuple[Finding, ...]:
        """Return findings for tools that match the generic network heuristic."""
        findings: list[Finding] = []

        for tool in server.tools:
            evidence = self._collect_evidence(tool.name, tool.description, tool.input_schema)
            if not evidence:
                continue

            findings.append(
                self.make_finding(
                    f"Tool {tool.name!r} appears to expose generic network connectivity.",
                    tool_name=tool.name,
                    evidence=evidence,
                )
            )

        return tuple(findings)

    def _collect_evidence(
        self,
        name: str,
        description: str | None,
        input_schema: dict[str, JSONValue],
    ) -> tuple[str, ...]:
        """Return stable evidence for network primitives."""
        normalized_name = normalize_text(name)
        normalized_description = normalize_text(description)
        property_names = schema_property_names(input_schema)

        matched_name_markers = tuple(
            marker for marker in _NAME_MARKERS if marker in normalized_name
        )
        matched_description_markers = tuple(
            marker for marker in _DESCRIPTION_MARKERS if marker in normalized_description
        )
        matched_network_keys = matching_keys(property_names, _NETWORK_KEYS)

        if not matched_name_markers:
            return ()
        if not matched_description_markers and not matched_network_keys:
            return ()

        evidence = [f"name_markers={list(matched_name_markers)!r}"]
        if matched_description_markers:
            evidence.append(f"description_markers={list(matched_description_markers)!r}")
        if matched_network_keys:
            evidence.append(f"network_keys={list(matched_network_keys)!r}")
        return tuple(evidence)
