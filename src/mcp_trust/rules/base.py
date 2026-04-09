"""Base abstractions for deterministic scorecard checks."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field

from mcp_trust.models import (
    Finding,
    FindingCategory,
    FindingLevel,
    JSONValue,
    NormalizedServer,
    RiskCategory,
    RuleDescriptor,
    ScoreCategory,
)

SEVERITY_SCORE_IMPACT = {
    FindingLevel.INFO: 0,
    FindingLevel.WARNING: 10,
    FindingLevel.ERROR: 20,
}


@dataclass(slots=True, frozen=True)
class Rule(ABC):
    """Base class for deterministic rules with explicit metadata."""

    rule_id: str
    title: str
    rationale: str
    severity: FindingLevel
    category: FindingCategory
    risk_category: RiskCategory
    bucket: ScoreCategory
    tags: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.rule_id.strip():
            raise ValueError("rule_id must not be empty.")
        if not self.title.strip():
            raise ValueError("rule title must not be empty.")
        if not self.rationale.strip():
            raise ValueError("rule rationale must not be empty.")
        normalized_tags = tuple(tag.strip() for tag in self.tags if tag.strip())
        object.__setattr__(self, "tags", normalized_tags)

    @property
    def summary(self) -> str:
        """Compatibility alias for the rule rationale."""
        return self.rationale

    @property
    def score_category(self) -> ScoreCategory:
        """Compatibility alias for the score bucket."""
        return self.bucket

    @property
    def score_impact(self) -> int:
        """Return the penalty points implied by the rule severity."""
        return SEVERITY_SCORE_IMPACT[self.severity]

    def to_descriptor(self) -> RuleDescriptor:
        """Return stable metadata for report serialization layers."""
        return RuleDescriptor(
            rule_id=self.rule_id,
            title=self.title,
            rationale=self.rationale,
            severity=self.severity,
            category=self.category,
            risk_category=self.risk_category,
            bucket=self.bucket,
            score_impact=self.score_impact,
            tags=self.tags,
        )

    @abstractmethod
    def evaluate(self, server: NormalizedServer) -> Sequence[Finding]:
        """Return findings emitted for the given normalized server."""

    def make_finding(
        self,
        message: str,
        *,
        evidence: Sequence[str],
        tool_name: str | None = None,
        metadata: dict[str, JSONValue] | None = None,
    ) -> Finding:
        """Construct a finding populated from the rule metadata."""
        return Finding(
            rule_id=self.rule_id,
            level=self.severity,
            title=self.title,
            category=self.category,
            risk_category=self.risk_category,
            bucket=self.bucket,
            message=message,
            evidence=tuple(evidence),
            penalty=self.score_impact,
            tool_name=tool_name,
            metadata={} if metadata is None else metadata,
        )
