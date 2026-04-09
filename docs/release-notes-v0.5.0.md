# MCP Scorecard v0.5.0

Historical `v0.5.0` release of the project now presented as `MCP Scorecard`.

`v0.5.0` is a narrow integration-driven release.

The scanner contract from `v0.4.0` stays intentionally stable: local `stdio` discovery,
deterministic rules, predictable scoring, terminal summary, JSON, SARIF, and GitHub Actions.
The main reason for `v0.5.0` is to make CI-first scorecard output easier to consume by downstream
systems that care about scan freshness and temporal decay.

## Highlights

- explicit `scan_timestamp` field in JSON output
- matching timestamp metadata in SARIF
- no break to existing `generated_at` consumers
- release-ready deterministic scorecard contract for higher-layer integrations

## Included In v0.5.0

- JSON reports now expose:
  - `scan_timestamp`
  - `generated_at`
  - aggregate score breakdown
  - capability-aware and hygiene-aware findings
- SARIF runs now expose:
  - `runs[].properties.scan_timestamp`
  - `runs[].invocations[].endTimeUtc`
- sample reports regenerated from the current scanner
- release docs and README updated for `v0.5.0`

## Validation Snapshot

- `examples/insecure-server` -> `10/100`
- `@modelcontextprotocol/server-memory@2026.1.26` -> `100/100`
- `@modelcontextprotocol/server-filesystem@2026.1.14` -> `40/100`

## Contract Note

`generated_at` is still present for backward compatibility.

`scan_timestamp` is now the canonical timestamp field for downstream integrations that need to
reason about baseline freshness.

## Quickstart

Local:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
mcp-trust scan --json-out baseline.json --cmd python examples/insecure-server/server.py
```

GitHub Actions:

```yaml
- name: Run MCP Scorecard
  uses: aak204/MCP-Trust-Kit@v0.5.0
  with:
    cmd: python path/to/your/server.py
    min-score: "80"
    json-out: mcp-scorecard-report.json
    sarif-out: mcp-scorecard-report.sarif
```
