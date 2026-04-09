"""Rule for write-capable tools that lack any scope hint."""

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
    PATH_KEYS,
    has_scope_hint,
    matching_keys,
    normalize_text,
    schema_property_names,
)

_WRITE_MARKERS = ("write", "save", "append", "create", "update", "edit")
_DELETE_MARKERS = ("delete", "remove", "unlink", "erase", "truncate")
_FILE_MARKERS = ("file", "filesystem", "disk", "path", "directory", "folder")


@dataclass(slots=True, frozen=True)
class WriteToolWithoutScopeHintRule(Rule):
    """Flag side-effecting filesystem tools that do not mention scope constraints."""

    rule_id: str = "write_tool_without_scope_hint"
    title: str = "Write tool without scope hint"
    rationale: str = "Filesystem mutation tools should document scope constraints clearly."
    severity: FindingLevel = FindingLevel.WARNING
    category: FindingCategory = FindingCategory.CAPABILITY
    risk_category: RiskCategory = RiskCategory.EXTERNAL_SIDE_EFFECTS
    bucket: ScoreCategory = ScoreCategory.ERGONOMICS
    tags: tuple[str, ...] = ("capability", "filesystem", "scope")

    def evaluate(self, server: NormalizedServer) -> tuple[Finding, ...]:
        """Return findings for write-capable tools with no scope hint."""
        findings: list[Finding] = []

        for tool in server.tools:
            evidence = self._collect_evidence(tool.name, tool.description, tool.input_schema)
            if not evidence:
                continue

            findings.append(
                self.make_finding(
                    f"Tool {tool.name!r} modifies the filesystem without any visible scope hint.",
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
        """Return stable evidence for unscoped filesystem mutation tools."""
        normalized_name = normalize_text(name)
        normalized_description = normalize_text(description)
        property_names = schema_property_names(input_schema)

        has_write_marker = any(marker in normalized_name for marker in _WRITE_MARKERS)
        has_delete_marker = any(
            marker in normalized_name or marker in normalized_description
            for marker in _DELETE_MARKERS
        )
        has_file_marker = any(
            marker in normalized_name or marker in normalized_description
            for marker in _FILE_MARKERS
        )
        matched_path_keys = matching_keys(property_names, PATH_KEYS)

        if not (has_write_marker or has_delete_marker):
            return ()
        if not has_file_marker or not matched_path_keys:
            return ()
        if has_scope_hint(description=description, input_schema=input_schema):
            return ()

        return (
            f"path_keys={list(matched_path_keys)!r}",
            "scope_hint=<missing>",
        )
