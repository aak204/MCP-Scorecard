"""Rule interface for deterministic trust scoring."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from mcp_trust.models import Finding, NormalizedServer


class Rule(Protocol):
    """Deterministic rule that inspects a normalized server."""

    rule_id: str
    summary: str

    def evaluate(self, server: NormalizedServer) -> Sequence[Finding]:
        """Return findings emitted for the given normalized server."""

