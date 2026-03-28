"""Deterministic scoring engine skeleton."""

from __future__ import annotations

from dataclasses import dataclass

from mcp_trust.models import Finding, NormalizedServer, Report, ScoreBreakdown
from mcp_trust.rules.registry import RuleRegistry


@dataclass(slots=True)
class ScoringEngine:
    """Evaluate registered rules and produce a report."""

    registry: RuleRegistry
    max_score: int = 100

    def __post_init__(self) -> None:
        if self.max_score < 0:
            raise ValueError("max_score must be greater than or equal to zero.")

    def collect_findings(self, server: NormalizedServer) -> tuple[Finding, ...]:
        """Run all registered rules and collect their findings."""
        findings: list[Finding] = []
        for rule in self.registry:
            findings.extend(rule.evaluate(server))
        return tuple(findings)

    def build_score(self, findings: tuple[Finding, ...]) -> ScoreBreakdown:
        """Convert findings into a score breakdown."""
        return ScoreBreakdown.from_findings(findings, max_score=self.max_score)

    def evaluate(self, server: NormalizedServer) -> Report:
        """Produce a report for the given normalized server."""
        findings = self.collect_findings(server)
        score = self.build_score(findings)
        return Report(server=server, findings=findings, score=score)

