"""Reporter interface definitions."""

from __future__ import annotations

from typing import Protocol

from mcp_trust.models import Report


class Reporter(Protocol):
    """Render a report into a specific output representation."""

    reporter_id: str
    default_filename: str

    def render(self, report: Report) -> str:
        """Render the given report into reporter-specific text."""

