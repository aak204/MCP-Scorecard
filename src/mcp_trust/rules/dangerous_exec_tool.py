"""Rule for shell or command execution style tools."""

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
    matching_keys,
    matching_markers,
    normalize_text,
    schema_property_names,
)

_NAME_MARKERS = ("exec", "shell", "command", "cmd", "bash", "powershell", "terminal")
_DESCRIPTION_MARKERS = ("execute", "shell command", "host machine", "arbitrary command")
_INPUT_KEYS = ("command", "cmd", "script", "shell")


@dataclass(slots=True, frozen=True)
class DangerousExecToolRule(Rule):
    """Flag tools that appear to execute host commands."""

    rule_id: str = "dangerous_exec_tool"
    title: str = "Dangerous execution tool"
    rationale: str = "Tools that execute host shell commands are high risk."
    severity: FindingLevel = FindingLevel.ERROR
    category: FindingCategory = FindingCategory.CAPABILITY
    risk_category: RiskCategory = RiskCategory.COMMAND_EXECUTION
    bucket: ScoreCategory = ScoreCategory.SECURITY
    tags: tuple[str, ...] = ("capability", "execution")

    def evaluate(self, server: NormalizedServer) -> tuple[Finding, ...]:
        """Return findings for tools that match the exec heuristic."""
        findings: list[Finding] = []

        for tool in server.tools:
            evidence = self._collect_evidence(
                tool.name,
                tool.description,
                tool.input_schema,
            )
            if not evidence:
                continue

            findings.append(
                self.make_finding(
                    f"Tool {tool.name!r} appears to expose host command execution.",
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
        """Return stable evidence for tools that look like exec primitives."""
        normalized_name = normalize_text(name)
        normalized_description = normalize_text(description)
        property_names = schema_property_names(input_schema)

        matched_name_markers = matching_markers(normalized_name, _NAME_MARKERS)
        matched_description_markers = matching_markers(
            normalized_description,
            _DESCRIPTION_MARKERS,
        )
        matched_input_keys = matching_keys(property_names, _INPUT_KEYS)

        if not matched_name_markers:
            return ()
        if not matched_description_markers and not matched_input_keys:
            return ()

        evidence = [f"name_markers={list(matched_name_markers)!r}"]
        if matched_description_markers:
            evidence.append(f"description_markers={list(matched_description_markers)!r}")
        if matched_input_keys:
            evidence.append(f"input_keys={list(matched_input_keys)!r}")
        return tuple(evidence)
