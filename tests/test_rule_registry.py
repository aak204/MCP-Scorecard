from __future__ import annotations

from mcp_trust.models import (
    Finding,
    FindingCategory,
    FindingLevel,
    NormalizedServer,
    RiskCategory,
    ScoreCategory,
)
from mcp_trust.rules import RuleRegistry
from mcp_trust.rules.base import Rule


class DummyRule(Rule):
    """Simple test rule used to verify registry behavior."""

    def __init__(self, rule_id: str) -> None:
        super().__init__(
            rule_id=rule_id,
            title=f"Title for {rule_id}",
            rationale=f"Rationale for {rule_id}",
            severity=FindingLevel.INFO,
            category=FindingCategory.TOOL_DESCRIPTION,
            risk_category=RiskCategory.METADATA_HYGIENE,
            bucket=ScoreCategory.METADATA,
        )

    def evaluate(self, server: NormalizedServer) -> list[Finding]:
        return [
            Finding(
                rule_id=self.rule_id,
                level=FindingLevel.INFO,
                message=f"Checked {server.target}.",
            )
        ]


def test_rule_registry_preserves_registration_order() -> None:
    first = DummyRule("rule.first")
    second = DummyRule("rule.second")

    registry = RuleRegistry.from_rules([first, second])

    assert registry.rule_ids == ("rule.first", "rule.second")
    assert tuple(rule.rule_id for rule in registry) == ("rule.first", "rule.second")
    assert len(registry) == 2


def test_rule_registry_rejects_duplicate_rule_ids() -> None:
    registry = RuleRegistry()
    registry.register(DummyRule("rule.duplicate"))

    try:
        registry.register(DummyRule("rule.duplicate"))
    except ValueError as exc:
        assert str(exc) == "Rule 'rule.duplicate' is already registered."
    else:
        raise AssertionError("Expected duplicate rule registration to fail.")
