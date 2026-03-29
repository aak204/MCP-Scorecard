"""Rule for filesystem deletion style tools."""

from __future__ import annotations

import re
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
    PATH_KEYS,
    matching_keys,
    normalize_text,
    schema_property_names,
)

_DELETE_MARKERS = ("delete", "remove", "rm", "unlink", "erase", "truncate")
_FILE_MARKERS = ("file", "filesystem", "disk", "path", "directory", "folder")
_TOKEN_RE = re.compile(r"[a-z0-9]+")


@dataclass(slots=True, frozen=True)
class DangerousFsDeleteToolRule(Rule):
    """Flag tools that appear to delete or erase files on disk."""

    rule_id: str = "dangerous_fs_delete_tool"
    title: str = "Dangerous filesystem delete tool"
    summary: str = "Tools that delete files or directories are high risk."
    severity: FindingLevel = FindingLevel.ERROR
    category: FindingCategory = FindingCategory.CAPABILITY
    risk_category: RiskCategory = RiskCategory.FILE_SYSTEM
    score_category: ScoreCategory = ScoreCategory.TOOL_SURFACE
    tags: tuple[str, ...] = ("capability", "filesystem", "destructive")

    def evaluate(self, server: NormalizedServer) -> tuple[Finding, ...]:
        """Return findings for tools that match the fs delete heuristic."""
        findings: list[Finding] = []

        for tool in server.tools:
            evidence = self._collect_evidence(tool.name, tool.description, tool.input_schema)
            if not evidence:
                continue

            findings.append(
                self.make_finding(
                    f"Tool {tool.name!r} appears to provide filesystem delete access.",
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
        """Return stable evidence for delete-like filesystem tools."""
        normalized_name = normalize_text(name)
        normalized_description = normalize_text(description)
        property_names = schema_property_names(input_schema)
        name_tokens = set(_TOKEN_RE.findall(normalized_name))
        description_tokens = set(_TOKEN_RE.findall(normalized_description))

        matched_delete_markers = tuple(
            marker
            for marker in _DELETE_MARKERS
            if marker in name_tokens or marker in description_tokens
        )
        matched_file_markers = tuple(
            marker
            for marker in _FILE_MARKERS
            if marker in normalized_name or marker in normalized_description
        )
        matched_path_keys = matching_keys(property_names, PATH_KEYS)

        if not matched_delete_markers or not matched_file_markers or not matched_path_keys:
            return ()

        return (
            f"delete_markers={list(matched_delete_markers)!r}",
            f"file_markers={list(matched_file_markers)!r}",
            f"path_keys={list(matched_path_keys)!r}",
        )
