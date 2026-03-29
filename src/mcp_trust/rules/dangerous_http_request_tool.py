"""Rule for HTTP request style tools."""

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

_NAME_MARKERS = ("http", "fetch", "request", "post", "get", "webhook", "download", "upload")
_DESCRIPTION_MARKERS = (
    "http request",
    "remote api",
    "webhook",
    "download",
    "upload",
    "fetch url",
    "call external",
)


@dataclass(slots=True, frozen=True)
class DangerousHttpRequestToolRule(Rule):
    """Flag tools that appear to make arbitrary HTTP requests."""

    rule_id: str = "dangerous_http_request_tool"
    title: str = "Dangerous HTTP request tool"
    summary: str = "Tools that issue arbitrary HTTP requests are high risk."
    severity: FindingLevel = FindingLevel.ERROR
    category: FindingCategory = FindingCategory.CAPABILITY
    risk_category: RiskCategory = RiskCategory.NETWORK
    score_category: ScoreCategory = ScoreCategory.TOOL_SURFACE
    tags: tuple[str, ...] = ("capability", "network", "http")

    def evaluate(self, server: NormalizedServer) -> tuple[Finding, ...]:
        """Return findings for tools that match the HTTP request heuristic."""
        findings: list[Finding] = []

        for tool in server.tools:
            evidence = self._collect_evidence(tool.name, tool.description, tool.input_schema)
            if not evidence:
                continue

            findings.append(
                self.make_finding(
                    f"Tool {tool.name!r} appears to expose outbound HTTP request capability.",
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
        """Return stable evidence for arbitrary HTTP request tools."""
        normalized_name = normalize_text(name)
        normalized_description = normalize_text(description)
        property_names = schema_property_names(input_schema)

        matched_name_markers = tuple(
            marker for marker in _NAME_MARKERS if marker in normalized_name
        )
        matched_description_markers = tuple(
            marker for marker in _DESCRIPTION_MARKERS if marker in normalized_description
        )
        matched_url_keys = matching_keys(property_names, URL_KEYS)

        if not matched_url_keys:
            return ()
        if not matched_name_markers and not matched_description_markers:
            return ()

        evidence = [f"url_keys={list(matched_url_keys)!r}"]
        if matched_name_markers:
            evidence.append(f"name_markers={list(matched_name_markers)!r}")
        if matched_description_markers:
            evidence.append(f"description_markers={list(matched_description_markers)!r}")
        return tuple(evidence)
