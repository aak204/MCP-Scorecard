from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_action_definition_exposes_expected_inputs_and_scan_command() -> None:
    action_text = (ROOT / "action.yml").read_text(encoding="utf-8")

    assert "name: MCP Trust Kit" in action_text
    assert "cmd:" in action_text
    assert "min-score:" in action_text
    assert "json-out:" in action_text
    assert "sarif-out:" in action_text
    assert "actions/setup-python@v5" in action_text
    assert 'python-version: "3.12"' in action_text
    assert "python -m pip install ." in action_text
    assert '"scan"' in action_text
    assert '"--min-score"' in action_text
    assert '"--json-out"' in action_text
    assert '"--sarif"' in action_text
    assert '"--cmd"' in action_text


def test_readme_documents_github_actions_quickstart() -> None:
    readme_text = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "## GitHub Actions Quickstart" in readme_text
    assert "uses: aak204/MCP-Trust-Kit@v0.3.0" in readme_text
    assert "cmd: python path/to/your/server.py" in readme_text
    assert "github/codeql-action/upload-sarif@v3" in readme_text
    assert "mcp-trust-report.sarif" in readme_text


def test_example_workflow_shows_upload_sarif_even_on_failure() -> None:
    workflow_text = (ROOT / ".github" / "workflows" / "example.yml").read_text(
        encoding="utf-8"
    )

    assert "uses: actions/checkout@v4" in workflow_text
    assert "uses: ./" in workflow_text
    assert 'min-score: "80"' in workflow_text
    assert "security-events: write" in workflow_text
    assert "if: always()" in workflow_text
    assert "github/codeql-action/upload-sarif@v3" in workflow_text
