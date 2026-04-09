"""Rule for filesystem write style tools."""

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
    CONTENT_KEYS,
    PATH_KEYS,
    matching_keys,
    normalize_text,
    schema_property_names,
)

_WRITE_MARKERS = ("write", "save", "append", "create", "update", "edit")
_FILE_MARKERS = ("file", "filesystem", "disk", "path", "directory", "folder")


@dataclass(slots=True, frozen=True)
class DangerousFsWriteToolRule(Rule):
    """Flag tools that appear to modify files on disk."""

    rule_id: str = "dangerous_fs_write_tool"
    title: str = "Dangerous filesystem write tool"
    rationale: str = "Tools that write files on disk are high risk."
    severity: FindingLevel = FindingLevel.ERROR
    category: FindingCategory = FindingCategory.CAPABILITY
    risk_category: RiskCategory = RiskCategory.FILE_SYSTEM
    bucket: ScoreCategory = ScoreCategory.SECURITY
    tags: tuple[str, ...] = ("capability", "filesystem")

    def evaluate(self, server: NormalizedServer) -> tuple[Finding, ...]:
        """Return findings for tools that match the fs write heuristic."""
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
                    f"Tool {tool.name!r} appears to provide filesystem write access.",
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
        """Return stable evidence for tools that look like file writers."""
        normalized_name = normalize_text(name)
        normalized_description = normalize_text(description)
        property_names = schema_property_names(input_schema)

        matched_write_markers = tuple(
            marker for marker in _WRITE_MARKERS if marker in normalized_name
        )
        matched_file_markers = tuple(
            marker
            for marker in _FILE_MARKERS
            if marker in normalized_name or marker in normalized_description
        )
        matched_path_keys = matching_keys(property_names, PATH_KEYS)
        matched_content_keys = matching_keys(property_names, CONTENT_KEYS)

        if not matched_write_markers:
            return ()
        if not matched_file_markers:
            return ()
        if not matched_path_keys:
            return ()

        evidence = [
            f"write_markers={list(matched_write_markers)!r}",
            f"file_markers={list(matched_file_markers)!r}",
            f"path_keys={list(matched_path_keys)!r}",
        ]
        if matched_content_keys:
            evidence.append(f"content_keys={list(matched_content_keys)!r}")
        return tuple(evidence)
