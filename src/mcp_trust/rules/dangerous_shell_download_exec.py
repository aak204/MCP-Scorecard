"""Rule for tools that combine network download and command execution."""

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

_EXEC_MARKERS = ("exec", "shell", "command", "bash", "powershell")
_DOWNLOAD_MARKERS = ("download", "fetch", "curl", "wget", "remote script", "remote payload")
_EXEC_KEYS = ("command", "cmd", "script")


@dataclass(slots=True, frozen=True)
class DangerousShellDownloadExecRule(Rule):
    """Flag tools that can both fetch and execute remote content."""

    rule_id: str = "dangerous_shell_download_exec"
    title: str = "Dangerous download-and-execute tool"
    rationale: str = "Tools that combine remote download with shell execution are high risk."
    severity: FindingLevel = FindingLevel.ERROR
    category: FindingCategory = FindingCategory.CAPABILITY
    risk_category: RiskCategory = RiskCategory.COMMAND_EXECUTION
    bucket: ScoreCategory = ScoreCategory.SECURITY
    tags: tuple[str, ...] = ("capability", "execution", "network")

    def evaluate(self, server: NormalizedServer) -> tuple[Finding, ...]:
        """Return findings for tools that combine download and exec heuristics."""
        findings: list[Finding] = []

        for tool in server.tools:
            evidence = self._collect_evidence(tool.name, tool.description, tool.input_schema)
            if not evidence:
                continue

            findings.append(
                self.make_finding(
                    (
                        f"Tool {tool.name!r} appears to combine remote download capability "
                        "with command execution."
                    ),
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
        """Return stable evidence for download-and-execute patterns."""
        normalized_name = normalize_text(name)
        normalized_description = normalize_text(description)
        property_names = schema_property_names(input_schema)

        matched_exec_markers = tuple(
            marker for marker in _EXEC_MARKERS if marker in normalized_name
        )
        matched_download_markers = tuple(
            marker
            for marker in _DOWNLOAD_MARKERS
            if marker in normalized_name or marker in normalized_description
        )
        matched_exec_keys = matching_keys(property_names, _EXEC_KEYS)
        matched_url_keys = matching_keys(property_names, URL_KEYS)

        has_exec = bool(matched_exec_markers or matched_exec_keys)
        has_download = bool(matched_download_markers or matched_url_keys)
        if not (has_exec and has_download):
            return ()

        evidence: list[str] = []
        if matched_exec_markers:
            evidence.append(f"exec_markers={list(matched_exec_markers)!r}")
        if matched_download_markers:
            evidence.append(f"download_markers={list(matched_download_markers)!r}")
        if matched_exec_keys:
            evidence.append(f"exec_keys={list(matched_exec_keys)!r}")
        if matched_url_keys:
            evidence.append(f"url_keys={list(matched_url_keys)!r}")
        return tuple(evidence)
