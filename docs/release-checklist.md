# Release Checklist

Use this list before publishing `v0.4.0`.

## Repository

- confirm the default branch is green
- verify `LICENSE`, `CHANGELOG.md`, and release docs are present

## Validation

- run `python -m venv .venv`
- run `source .venv/bin/activate`
- run `pip install -e .[dev]`
- run `python -m pytest`
- run `python -m ruff check .`
- run `python -m mypy`
- run `mcp-trust --help`
- run `mcp-trust scan --help`

Windows note:

- use `.\.venv\Scripts\Activate.ps1` instead of `source .venv/bin/activate`

## Install Surface

- create a clean virtual environment
- run `pip install .`
- run `mcp-trust --help`
- verify `import mcp_trust; print(mcp_trust.__version__)`
- verify package metadata shows version `0.4.0`

## Examples And Reports

- run `mcp-trust scan --cmd python examples/insecure-server/server.py`
- run `mcp-trust scan --json-out sample-reports/insecure-server.report.json --sarif sample-reports/insecure-server.report.sarif --cmd python examples/insecure-server/server.py`
- confirm JSON, SARIF, and terminal sample artifacts match current output
- confirm `examples/insecure-server/README.md` matches the current CLI syntax
- confirm `docs/validated-servers.md` matches current real-server validation runs

## GitHub Action

- verify `action.yml` inputs are `cmd`, `min-score`, `json-out`, `sarif-out`
- verify `.github/workflows/example.yml` is copy-pasteable
- verify `.github/workflows/ci.yml` is green
- verify SARIF upload example still points to `github/codeql-action/upload-sarif@v3`

## Release

- create tag `v0.4.0`
- publish GitHub Release notes from `CHANGELOG.md`
- attach or link sample artifacts if desired
- smoke-test the published action from a separate repository
