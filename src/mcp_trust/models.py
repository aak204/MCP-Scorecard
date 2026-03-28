"""Core data models for normalized scan results and reports."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TypeAlias

from mcp_trust import __version__

JSONScalar: TypeAlias = str | int | float | bool | None
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]


def _normalize_required_text(value: str, *, field_name: str) -> str:
    """Return a stripped string or raise when the value is empty."""
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be empty.")
    return normalized


def _normalize_optional_text(value: str | None) -> str | None:
    """Return a stripped string or ``None`` when the value is blank."""
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


class FindingLevel(StrEnum):
    """Severity level emitted by deterministic rules."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(slots=True, frozen=True)
class NormalizedTool:
    """Normalized representation of a single MCP tool."""

    name: str
    description: str | None = None
    input_schema: dict[str, JSONValue] = field(default_factory=dict)
    metadata: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "name",
            _normalize_required_text(self.name, field_name="tool name"),
        )
        object.__setattr__(self, "description", _normalize_optional_text(self.description))
        object.__setattr__(self, "input_schema", dict(self.input_schema))
        object.__setattr__(self, "metadata", dict(self.metadata))


@dataclass(slots=True, frozen=True)
class NormalizedServer:
    """Normalized server payload consumed by rules and reporters."""

    target: str
    name: str | None = None
    version: str | None = None
    tools: tuple[NormalizedTool, ...] = field(default_factory=tuple)
    metadata: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "target",
            _normalize_required_text(self.target, field_name="server target"),
        )
        object.__setattr__(self, "name", _normalize_optional_text(self.name))
        object.__setattr__(self, "version", _normalize_optional_text(self.version))
        object.__setattr__(self, "tools", tuple(self.tools))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def tool_names(self) -> tuple[str, ...]:
        """Return tool names in normalized order."""
        return tuple(tool.name for tool in self.tools)


@dataclass(slots=True, frozen=True)
class Finding:
    """Deterministic issue or observation produced by a rule."""

    rule_id: str
    level: FindingLevel
    message: str
    penalty: int = 0
    tool_name: str | None = None
    metadata: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "rule_id",
            _normalize_required_text(self.rule_id, field_name="rule_id"),
        )
        object.__setattr__(
            self,
            "message",
            _normalize_required_text(self.message, field_name="finding message"),
        )
        object.__setattr__(self, "tool_name", _normalize_optional_text(self.tool_name))
        object.__setattr__(self, "metadata", dict(self.metadata))
        if self.penalty < 0:
            raise ValueError("finding penalty must be greater than or equal to zero.")


@dataclass(slots=True, frozen=True)
class ScoreBreakdown:
    """Aggregated trust score information for a report."""

    max_score: int
    penalty_points: int
    final_score: int
    rule_penalties: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.max_score < 0:
            raise ValueError("max_score must be greater than or equal to zero.")
        if self.penalty_points < 0:
            raise ValueError("penalty_points must be greater than or equal to zero.")
        if self.final_score < 0:
            raise ValueError("final_score must be greater than or equal to zero.")
        if self.final_score > self.max_score:
            raise ValueError("final_score must not exceed max_score.")

        penalties = dict(self.rule_penalties)
        for rule_id, penalty in penalties.items():
            _normalize_required_text(rule_id, field_name="rule penalty key")
            if penalty < 0:
                raise ValueError("rule penalties must be greater than or equal to zero.")

        if sum(penalties.values()) != self.penalty_points:
            raise ValueError("penalty_points must equal the sum of rule_penalties.")

        object.__setattr__(self, "rule_penalties", penalties)

    @classmethod
    def from_findings(
        cls,
        findings: Sequence[Finding],
        *,
        max_score: int = 100,
    ) -> ScoreBreakdown:
        """Build a score breakdown from rule findings."""
        if max_score < 0:
            raise ValueError("max_score must be greater than or equal to zero.")

        rule_penalties: dict[str, int] = {}
        for finding in findings:
            rule_penalties[finding.rule_id] = (
                rule_penalties.get(finding.rule_id, 0) + finding.penalty
            )

        penalty_points = sum(rule_penalties.values())
        final_score = max(max_score - penalty_points, 0)

        return cls(
            max_score=max_score,
            penalty_points=penalty_points,
            final_score=final_score,
            rule_penalties=rule_penalties,
        )


@dataclass(slots=True, frozen=True)
class Report:
    """Report produced by the scoring engine and consumed by reporters."""

    server: NormalizedServer
    findings: tuple[Finding, ...]
    score: ScoreBreakdown
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    schema_version: str = "0.3"
    toolkit_version: str = __version__
    metadata: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(
            self,
            "schema_version",
            _normalize_required_text(self.schema_version, field_name="schema_version"),
        )
        object.__setattr__(
            self,
            "toolkit_version",
            _normalize_required_text(self.toolkit_version, field_name="toolkit_version"),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.generated_at.tzinfo is None or self.generated_at.utcoffset() is None:
            raise ValueError("generated_at must be timezone-aware.")

    @property
    def finding_count(self) -> int:
        """Return the total number of findings in the report."""
        return len(self.findings)
