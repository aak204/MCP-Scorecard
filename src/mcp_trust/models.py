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


class FindingCategory(StrEnum):
    """High-level category assigned to a deterministic finding."""

    TOOL_IDENTITY = "tool-identity"
    TOOL_DESCRIPTION = "tool-description"
    INPUT_SCHEMA = "input-schema"
    CAPABILITY = "capability"


class RiskCategory(StrEnum):
    """Capability-aware risk categories used in summaries and findings."""

    FILE_SYSTEM = "file_system"
    COMMAND_EXECUTION = "command_execution"
    NETWORK = "network"
    EXTERNAL_SIDE_EFFECTS = "external_side_effects"
    SCHEMA_HYGIENE = "schema_hygiene"
    METADATA_HYGIENE = "metadata_hygiene"


class ScoreCategory(StrEnum):
    """Top-level scoring buckets exposed to users."""

    SPEC = "spec"
    AUTH = "auth"
    SECRETS = "secrets"
    TOOL_SURFACE = "tool_surface"


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
    title: str | None = None
    category: FindingCategory | None = None
    risk_category: RiskCategory = RiskCategory.METADATA_HYGIENE
    score_category: ScoreCategory = ScoreCategory.TOOL_SURFACE
    evidence: tuple[str, ...] = field(default_factory=tuple)
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
        object.__setattr__(self, "title", _normalize_optional_text(self.title))
        evidence = tuple(
            _normalize_required_text(item, field_name="finding evidence item")
            for item in self.evidence
        )
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "tool_name", _normalize_optional_text(self.tool_name))
        object.__setattr__(self, "metadata", dict(self.metadata))
        if self.penalty < 0:
            raise ValueError("finding penalty must be greater than or equal to zero.")

    @property
    def severity(self) -> FindingLevel:
        """Return the finding severity."""
        return self.level

    @property
    def score_impact(self) -> int:
        """Return the score impact associated with the finding."""
        return self.penalty


@dataclass(slots=True, frozen=True)
class RuleDescriptor:
    """Stable rule metadata attached to a computed report."""

    rule_id: str
    name: str
    summary: str
    severity: FindingLevel
    category: FindingCategory
    risk_category: RiskCategory
    score_category: ScoreCategory
    score_impact: int
    tags: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "rule_id",
            _normalize_required_text(self.rule_id, field_name="rule_id"),
        )
        object.__setattr__(
            self,
            "name",
            _normalize_required_text(self.name, field_name="rule name"),
        )
        object.__setattr__(
            self,
            "summary",
            _normalize_required_text(self.summary, field_name="rule summary"),
        )
        if self.score_impact < 0:
            raise ValueError("rule score_impact must be greater than or equal to zero.")

        tags = tuple(_normalize_required_text(tag, field_name="rule tag") for tag in self.tags)
        object.__setattr__(self, "tags", tags)


@dataclass(slots=True, frozen=True)
class CategoryScoreBreakdown:
    """Per-category score breakdown exposed in reports."""

    category: ScoreCategory
    max_score: int
    penalty_points: int
    score: int
    finding_count: int
    rule_penalties: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.max_score < 0:
            raise ValueError("max_score must be greater than or equal to zero.")
        if self.penalty_points < 0:
            raise ValueError("penalty_points must be greater than or equal to zero.")
        if self.score < 0:
            raise ValueError("score must be greater than or equal to zero.")
        if self.score > self.max_score:
            raise ValueError("score must not exceed max_score.")
        if self.finding_count < 0:
            raise ValueError("finding_count must be greater than or equal to zero.")

        penalties = dict(self.rule_penalties)
        for rule_id, penalty in penalties.items():
            _normalize_required_text(rule_id, field_name="rule penalty key")
            if penalty < 0:
                raise ValueError("rule penalties must be greater than or equal to zero.")

        if sum(penalties.values()) != self.penalty_points:
            raise ValueError("penalty_points must equal the sum of rule_penalties.")

        object.__setattr__(self, "rule_penalties", penalties)


@dataclass(slots=True, frozen=True)
class ScoreBreakdown:
    """Aggregated trust score information for a report."""

    max_score: int
    total_penalty_points: int
    total_score: int
    category_breakdown: dict[ScoreCategory, CategoryScoreBreakdown] = field(default_factory=dict)
    rule_penalties: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.max_score < 0:
            raise ValueError("max_score must be greater than or equal to zero.")
        if self.total_penalty_points < 0:
            raise ValueError("total_penalty_points must be greater than or equal to zero.")
        if self.total_score < 0:
            raise ValueError("total_score must be greater than or equal to zero.")
        if self.total_score > self.max_score:
            raise ValueError("total_score must not exceed max_score.")

        penalties = dict(self.rule_penalties)
        for rule_id, penalty in penalties.items():
            _normalize_required_text(rule_id, field_name="rule penalty key")
            if penalty < 0:
                raise ValueError("rule penalties must be greater than or equal to zero.")

        if sum(penalties.values()) != self.total_penalty_points:
            raise ValueError("total_penalty_points must equal the sum of rule_penalties.")

        normalized_category_breakdown = dict(self.category_breakdown)
        expected_categories = set(ScoreCategory)
        if set(normalized_category_breakdown) != expected_categories:
            raise ValueError("category_breakdown must include every score category exactly once.")

        category_penalty_points = sum(
            breakdown.penalty_points for breakdown in normalized_category_breakdown.values()
        )
        if category_penalty_points != self.total_penalty_points:
            raise ValueError(
                "total_penalty_points must equal the sum of category breakdown penalties."
            )

        object.__setattr__(self, "rule_penalties", penalties)
        object.__setattr__(self, "category_breakdown", normalized_category_breakdown)

    @property
    def penalty_points(self) -> int:
        """Compatibility alias for total penalty points."""
        return self.total_penalty_points

    @property
    def final_score(self) -> int:
        """Compatibility alias for the total score."""
        return self.total_score

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
        category_penalties: dict[ScoreCategory, int] = {
            category: 0 for category in ScoreCategory
        }
        category_rule_penalties: dict[ScoreCategory, dict[str, int]] = {
            category: {} for category in ScoreCategory
        }
        category_finding_counts: dict[ScoreCategory, int] = {
            category: 0 for category in ScoreCategory
        }

        for finding in findings:
            rule_penalties[finding.rule_id] = (
                rule_penalties.get(finding.rule_id, 0) + finding.penalty
            )
            category_penalties[finding.score_category] += finding.penalty
            category_finding_counts[finding.score_category] += 1
            category_rule_penalties[finding.score_category][finding.rule_id] = (
                category_rule_penalties[finding.score_category].get(finding.rule_id, 0)
                + finding.penalty
            )

        total_penalty_points = sum(rule_penalties.values())
        total_score = max(max_score - total_penalty_points, 0)
        category_breakdown = {
            category: CategoryScoreBreakdown(
                category=category,
                max_score=max_score,
                penalty_points=category_penalties[category],
                score=max(max_score - category_penalties[category], 0),
                finding_count=category_finding_counts[category],
                rule_penalties=category_rule_penalties[category],
            )
            for category in ScoreCategory
        }

        return cls(
            max_score=max_score,
            total_penalty_points=total_penalty_points,
            total_score=total_score,
            category_breakdown=category_breakdown,
            rule_penalties=rule_penalties,
        )


@dataclass(slots=True, frozen=True)
class Report:
    """Report produced by the scoring engine and consumed by reporters."""

    server: NormalizedServer
    findings: tuple[Finding, ...]
    score: ScoreBreakdown
    rule_descriptors: dict[str, RuleDescriptor] = field(default_factory=dict)
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    schema_version: str = "0.4"
    toolkit_version: str = __version__
    metadata: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "rule_descriptors", dict(self.rule_descriptors))
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

    @property
    def total_score(self) -> int:
        """Return the total score from the scoring breakdown."""
        return self.score.total_score
