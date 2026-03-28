# MCP Trust Kit

`MCP Trust Kit` is a CI-first deterministic scanner for MCP servers.

## Status

This repository currently contains the initial `v0.3.0` project skeleton:

- Python package with `mcp-trust` CLI entrypoint
- test, lint, and type-check configuration
- placeholder directories for examples and sample reports

The scoring engine, report generation, and GitHub Action workflow are not implemented yet.

## Quickstart

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .[dev]
mcp-trust --help
pytest
```

## Planned v0.3 scope

- scan an MCP server
- normalize tool metadata
- apply deterministic rules
- calculate a trust score
- print a terminal summary
- save JSON and SARIF reports
- run in GitHub Actions

## Project Layout

```text
src/mcp_trust/    Python package and CLI
tests/            Smoke tests
examples/         Future example configs and usage samples
sample-reports/   Future JSON and SARIF outputs
```

## License

Apache-2.0. See `LICENSE`.

