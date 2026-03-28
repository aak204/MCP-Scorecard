"""Output layer skeleton for writing reports through reporters."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from mcp_trust.models import Report
from mcp_trust.reporting import Reporter


def _validate_reporter(reporter: Reporter) -> tuple[str, str]:
    """Return normalized reporter identifiers used by the output layer."""
    reporter_id = reporter.reporter_id.strip()
    if not reporter_id:
        raise ValueError("reporter_id must not be empty.")

    default_filename = reporter.default_filename.strip()
    if not default_filename:
        raise ValueError("default_filename must not be empty.")

    return reporter_id, default_filename


@dataclass(slots=True, frozen=True)
class RenderedOutput:
    """In-memory representation of a rendered report artifact."""

    reporter_id: str
    filename: str
    content: str


class OutputWriter:
    """Coordinate report rendering across a fixed set of reporters."""

    def __init__(self, reporters: Iterable[Reporter]) -> None:
        self._reporters = tuple(reporters)
        seen_reporters: set[str] = set()
        seen_filenames: set[str] = set()

        for reporter in self._reporters:
            reporter_id, filename = _validate_reporter(reporter)
            if reporter_id in seen_reporters:
                raise ValueError(f"Reporter '{reporter_id}' is already registered.")
            if filename in seen_filenames:
                raise ValueError(f"Output filename '{filename}' is already registered.")

            seen_reporters.add(reporter_id)
            seen_filenames.add(filename)

    @property
    def reporters(self) -> tuple[Reporter, ...]:
        """Return configured reporters in execution order."""
        return self._reporters

    def render(self, report: Report, reporter: Reporter) -> RenderedOutput:
        """Render a report with a single reporter."""
        reporter_id, filename = _validate_reporter(reporter)
        return RenderedOutput(
            reporter_id=reporter_id,
            filename=filename,
            content=reporter.render(report),
        )

    def render_all(self, report: Report) -> tuple[RenderedOutput, ...]:
        """Render a report with every configured reporter."""
        return tuple(self.render(report, reporter) for reporter in self._reporters)

    def write_all(self, report: Report, output_dir: Path) -> tuple[Path, ...]:
        """Write all rendered outputs into the target directory."""
        output_dir.mkdir(parents=True, exist_ok=True)

        written_paths: list[Path] = []
        for rendered_output in self.render_all(report):
            output_path = output_dir / rendered_output.filename
            output_path.write_text(rendered_output.content, encoding="utf-8")
            written_paths.append(output_path)

        return tuple(written_paths)

