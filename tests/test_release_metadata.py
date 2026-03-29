from __future__ import annotations

import tomllib
from pathlib import Path

import mcp_trust

ROOT = Path(__file__).resolve().parents[1]


def test_pyproject_version_and_license_match_release_surface() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject["project"]

    assert project["name"] == "mcp-trust-kit"
    assert project["version"] == mcp_trust.__version__
    assert project["license"] == "Apache-2.0"
    assert project["license-files"] == ["LICENSE"]


def test_example_workflow_matches_readme_release_shape() -> None:
    workflow_text = (ROOT / ".github" / "workflows" / "example.yml").read_text(
        encoding="utf-8"
    )

    assert "pull_request:" in workflow_text
    assert "workflow_dispatch:" in workflow_text
    assert "uses: ./" in workflow_text
    assert 'min-score: "80"' in workflow_text


def test_ci_workflow_runs_release_validation_stack() -> None:
    workflow_text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )

    assert "name: CI" in workflow_text
    assert "python -m pytest" in workflow_text
    assert "python -m ruff check ." in workflow_text
    assert "python -m mypy" in workflow_text
