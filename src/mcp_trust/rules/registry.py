"""Registry for deterministic scoring rules."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from mcp_trust.rules.base import Rule


def _normalize_rule_id(rule: Rule) -> str:
    """Return a normalized rule identifier or raise for invalid rules."""
    rule_id = rule.rule_id.strip()
    if not rule_id:
        raise ValueError("rule_id must not be empty.")
    return rule_id


@dataclass(slots=True)
class RuleRegistry:
    """Ordered registry for deterministic rules."""

    _rules: dict[str, Rule] = field(default_factory=dict)

    @classmethod
    def from_rules(cls, rules: Iterable[Rule]) -> RuleRegistry:
        """Build a registry from an iterable of rules."""
        registry = cls()
        registry.register_many(rules)
        return registry

    @property
    def rule_ids(self) -> tuple[str, ...]:
        """Return registered rule identifiers in execution order."""
        return tuple(self._rules)

    def register(self, rule: Rule) -> None:
        """Register a single rule."""
        rule_id = _normalize_rule_id(rule)
        if rule_id in self._rules:
            raise ValueError(f"Rule '{rule_id}' is already registered.")
        self._rules[rule_id] = rule

    def register_many(self, rules: Iterable[Rule]) -> None:
        """Register multiple rules in order."""
        for rule in rules:
            self.register(rule)

    def get(self, rule_id: str) -> Rule:
        """Return a registered rule by identifier."""
        try:
            return self._rules[rule_id]
        except KeyError as exc:
            raise KeyError(f"Rule '{rule_id}' is not registered.") from exc

    def __iter__(self) -> Iterator[Rule]:
        """Iterate over registered rules in execution order."""
        return iter(self._rules.values())

    def __len__(self) -> int:
        """Return the number of registered rules."""
        return len(self._rules)

