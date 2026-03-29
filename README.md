# MCP Trust Kit

[![Build Status](https://github.com/aak204/MCP-Trust-Kit/actions/workflows/example.yml/badge.svg)](https://github.com/aak204/MCP-Trust-Kit/actions/workflows/example.yml)
[![Release](https://img.shields.io/github/v/release/aak204/MCP-Trust-Kit?sort=semver)](https://github.com/aak204/MCP-Trust-Kit/releases)
[![License](https://img.shields.io/github/license/aak204/MCP-Trust-Kit)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)

**Deterministic trust scoring for MCP servers.**

`MCP Trust Kit` is a CI-first scanner for MCP servers. It launches a server over `stdio`,
discovers its tools, runs deterministic checks, calculates a trust score, and emits terminal,
JSON, and SARIF output that fits cleanly into GitHub Actions.

## Why

MCP servers expose tools to agents. Tool hygiene and risky tool surface should be reviewable with
fast, repeatable checks.

`MCP Trust Kit` is built for that narrow job. It is not a gateway, a hosted service, or an opaque
security product. It is a usable scanner with explainable output.

## What It Does

- launches a local MCP server over `stdio`
- performs a minimal MCP handshake and tool discovery
- normalizes tool metadata into a stable internal model
- runs deterministic rules without LLMs
- calculates a score from `0..100`
- prints a short terminal summary
- writes JSON for CI and integrations
- writes SARIF for GitHub code scanning
- fails CI when the score is below a threshold

v0.3.0 is intentionally focused on local `stdio` servers.

## Quickstart Local

Scan the included demo server:

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -e .[dev]
.\.venv\Scripts\mcp-trust scan --cmd .\.venv\Scripts\python examples\insecure-server\server.py
```

Generate reports and enforce a minimum score:

```powershell
.\.venv\Scripts\mcp-trust scan `
  --min-score 80 `
  --json-out mcp-trust-report.json `
  --sarif mcp-trust-report.sarif `
  --cmd .\.venv\Scripts\python examples\insecure-server\server.py
```

## GitHub Actions Quickstart

Drop this workflow into your repository:

```yaml
name: MCP Trust Scan

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run MCP Trust Kit
        uses: aak204/MCP-Trust-Kit@v0.3.0
        with:
          cmd: python path/to/your/server.py
          min-score: "80"
          json-out: mcp-trust-report.json
          sarif-out: mcp-trust-report.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: mcp-trust-report.sarif
```

If the `v0.3.0` tag is not published yet, use a branch name or commit SHA while testing privately.

## Example Output

```text
Server: Insecure Demo Server
Version: 0.1.0
Protocol: 2025-11-25
Target: stdio:[".\\.venv\\Scripts\\python","examples\\insecure-server\\server.py"]
Tools: 4
Findings: 4
Severity: error=2, warning=2, info=0
Total Score: 40/100
Category Scores:
- spec: 100/100 (penalties: 0)
- auth: 100/100 (penalties: 0)
- secrets: 100/100 (penalties: 0)
- tool_surface: 40/100 (penalties: 60)
Top Findings:
- WARNING vague_tool_description [do_it]: Tool 'do_it' uses a vague description that does not explain its behavior clearly.
- WARNING weak_input_schema [debug_payload]: Tool 'debug_payload' exposes a weak input schema that accepts poorly constrained input.
- ERROR dangerous_exec_tool [exec_command]: Tool 'exec_command' appears to expose host command execution.
- ERROR dangerous_fs_write_tool [write_file]: Tool 'write_file' appears to provide filesystem write access.
```

## Validated On Real MCP Servers

This repository includes a deterministic demo server, but the scanner has also been checked against
real public MCP servers. This section is meant as a reproducibility note, not a leaderboard.

Validated on `2026-03-29`:

| Server | Source | Result | Notes |
| --- | --- | --- | --- |
| `examples/insecure-server` | local demo | `40/100` | intentionally risky demo fixture |
| `@modelcontextprotocol/server-memory@2026.1.26` | official public package | `90/100` | one `weak_input_schema` finding on `read_graph` |
| `@modelcontextprotocol/server-filesystem@2026.1.14` | official public package | `30/100` | write-capable tool surface is flagged, which is expected |

Full commands, findings, and caveats:

- [docs/validated-servers.md](docs/validated-servers.md)

## Rule Categories

Current v0.3.0 rules focus on two practical areas:

| Area | What it catches today |
| --- | --- |
| Protocol and tool hygiene | duplicate names, missing descriptions, vague descriptions, weak input schemas |
| Risky tool surface | exec-like tools and filesystem write tools |

Score breakdown is emitted across:

- `spec`
- `auth`
- `secrets`
- `tool_surface`

## Scoring

The scoring model is intentionally simple:

1. start at `100`
2. subtract fixed penalties for findings
3. clamp to `0..100`
4. compute category scores the same way

Severity mapping in v0.3.0:

| Severity | Penalty |
| --- | --- |
| `info` | `0` |
| `warning` | `10` |
| `error` | `20` |

## Examples And Docs

- [examples/insecure-server/README.md](examples/insecure-server/README.md)
- [examples/fake_stdio_server.py](examples/fake_stdio_server.py)
- [sample-reports/insecure-server.report.json](sample-reports/insecure-server.report.json)
- [sample-reports/insecure-server.report.sarif](sample-reports/insecure-server.report.sarif)
- [sample-reports/insecure-server.terminal.md](sample-reports/insecure-server.terminal.md)
- [docs/architecture.md](docs/architecture.md)
- [docs/validated-servers.md](docs/validated-servers.md)
- [.github/workflows/example.yml](.github/workflows/example.yml)

## Roadmap

- expand deterministic rules for `spec`, `auth`, and `secrets`
- improve SARIF location mapping where source context exists
- add more sample reports and validation cases
- keep the GitHub Action path simple and reliable

## Contributing

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -e .[dev]
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\python -m ruff check .
.\.venv\Scripts\python -m mypy
```

Good contribution areas:

- new deterministic rules with tests
- `stdio` transport hardening
- reporter improvements that preserve stable output
- docs and example workflows

## License

Apache-2.0. See [LICENSE](LICENSE).
