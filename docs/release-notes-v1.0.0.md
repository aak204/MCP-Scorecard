# MCP Scorecard v1.0.0

`v1.0.0` is the first stable release of `MCP Scorecard`.

This release takes the existing deterministic scanner and hardens it into a release-grade
CI-first scorecard for MCP servers. The core philosophy stays the same: local discovery,
deterministic checks, stable scoring, and machine-readable output. What changes in `v1.0.0` is the
contract quality, naming consistency, and release surface.

## Highlights

- stable V1 JSON scorecard report contract
- explicit score buckets:
  - `conformance`
  - `security`
  - `ergonomics`
  - `metadata`
- explicit check metadata:
  - `id`
  - `title`
  - `bucket`
  - `severity`
  - `rationale`
- scorecard-oriented GitHub Action outputs and PR summary
- preferred CLI name `mcp-scorecard`, with `mcp-trust` retained as a compatibility alias

## Included In v1.0.0

- JSON reports now expose a stable top-level contract:
  - `schema`
  - `generator`
  - `scan`
  - `inventory`
  - `scorecard`
  - `checks`
  - `findings`
  - `grouped_findings`
  - `metadata`
- terminal output now mirrors the scorecard contract:
  - generator
  - schema version
  - scan timestamp
  - target description
  - total score
  - category scores
  - findings by bucket
  - limitations
- SARIF now carries aligned scorecard metadata in run properties and result properties
- sample reports regenerated from the current scanner
- release docs, checklist, and README updated for `v1.0.0`

## Compatibility Notes

- the repository and action reference remain `aak204/MCP-Trust-Kit` for this release line
- `mcp-scorecard` is the preferred CLI
- `mcp-trust` remains available as a compatibility alias
- the Python module remains `mcp_trust`

## Score Meaning

- a high score means fewer deterministic findings, not a guarantee of safety
- a low score means more deterministic findings or higher-risk exposed surface, not malicious intent
- the score measures deterministic, reviewable properties only

## Quickstart

Local:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
mcp-scorecard scan --json-out mcp-scorecard-report.json --sarif mcp-scorecard-report.sarif --cmd python examples/insecure-server/server.py
```

GitHub Actions:

```yaml
- name: Run MCP Scorecard
  id: scorecard
  uses: aak204/MCP-Trust-Kit@v1.0.0
  with:
    cmd: python path/to/your/server.py
    min-score: "80"
    json-out: mcp-scorecard-report.json
    sarif-out: mcp-scorecard-report.sarif
    markdown-out: mcp-scorecard-summary.md
```

## Validation Snapshot

- `examples/insecure-server` -> `10/100`
- `@modelcontextprotocol/server-memory@2026.1.26` -> `100/100`
- `@modelcontextprotocol/server-filesystem@2026.1.14` -> `40/100`

## Out Of Scope

- LLM scoring
- hosted scanning
- registry integration
- certification-style claims
