# Release Checklist

Use this list before publishing `v1.0.0`.

## Repository

- confirm the default branch is green
- verify `LICENSE`, `CHANGELOG.md`, and release docs are present
- verify `docs/release-notes-v1.0.0.md` exists and matches the intended release surface

## Validation

- run `python -m venv .venv`
- run `source .venv/bin/activate`
- run `pip install -e .[dev]`
- run `python -m pytest`
- run `python -m ruff check .`
- run `python -m mypy`
- run `mcp-scorecard --help`
- run `mcp-scorecard scan --help`

Windows note:

- use `.\.venv\Scripts\Activate.ps1` instead of `source .venv/bin/activate`

## Install Surface

- create a clean virtual environment
- run `pip install .`
- run `mcp-scorecard --help`
- verify `import mcp_trust; print(mcp_trust.__version__)`
- verify package metadata shows version `1.0.0`
- verify both `mcp-scorecard` and legacy `mcp-trust` entrypoints are available

## Examples And Reports

- run `mcp-scorecard scan --cmd python examples/insecure-server/server.py`
- run `mcp-scorecard scan --json-out sample-reports/insecure-server.report.json --sarif sample-reports/insecure-server.report.sarif --cmd python examples/insecure-server/server.py`
- confirm JSON, SARIF, and terminal sample artifacts match current output
- confirm `examples/insecure-server/README.md` matches the current preferred CLI syntax
- confirm `MCP_SCORECARD_30_SERVER_BATCH.md` and `MCP_SCORECARD_30_SERVER_BATCH.summary.json` match the current public-scan positioning

## GitHub Action

- verify `action.yml` inputs are `cmd`, `min-score`, `json-out`, `sarif-out`, `markdown-out`
- verify `action.yml` outputs are `total-score`, `category-scores`, `passed`
- verify `.github/workflows/example.yml` is copy-pasteable
- verify `.github/workflows/ci.yml` is green
- verify SARIF upload example still points to `github/codeql-action/upload-sarif@v3`

## Release

- create tag `v1.0.0`
- publish GitHub Release notes from `docs/release-notes-v1.0.0.md`
- attach or link sample artifacts if desired
- smoke-test the published action from a separate repository
