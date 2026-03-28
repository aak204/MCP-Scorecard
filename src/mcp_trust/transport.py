"""Transport interface definitions."""

from __future__ import annotations

from typing import Protocol

from mcp_trust.models import NormalizedServer


class Transport(Protocol):
    """Load a target and return a normalized server description."""

    transport_name: str

    def scan(self, target: str) -> NormalizedServer:
        """Scan the given target and return normalized data for scoring."""

