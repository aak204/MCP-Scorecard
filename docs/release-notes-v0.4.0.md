# MCP Trust Kit v0.4.0

`v0.4.0` is the first practically useful public release of `MCP Trust Kit`.

This release keeps the product intentionally narrow: local `stdio` MCP discovery, deterministic
rules, predictable scoring, terminal summary, JSON, SARIF, and GitHub Actions. The main change is
not "more features for the sake of it". The main change is that the score now behaves more like a
review signal and less like a demo number.

## Highlights

- deterministic surface-risk scoring for MCP servers
- refined schema heuristics that stop penalizing empty object schemas for no-arg tools by default
- expanded rules for schema hygiene and risky exposed capabilities
- capability-aware report summaries
- terminal output that explains why the score is low and which tools to review first
- real-world validation against public MCP servers
- Bash-first quickstart and production-ish GitHub Action docs

## Included In v0.4.0

- local `stdio` discovery transport
- normalized server, tool, finding, and report models
- deterministic rule set covering:
  - metadata hygiene
  - schema hygiene
  - command execution
  - filesystem mutation
  - network request surface
  - download-and-execute patterns
- penalty-based score breakdown across `spec`, `auth`, `secrets`, and `tool_surface`
- terminal summary, JSON report, and SARIF export
- demo insecure MCP server
- sample reports, validation docs, and CI workflow

## Validation Snapshot

- `examples/insecure-server` -> `10/100`
- `@modelcontextprotocol/server-memory@2026.1.26` -> `100/100`
- `@modelcontextprotocol/server-filesystem@2026.1.14` -> `40/100`

The key interpretation stays the same:

- low score means higher exposed surface risk, not malicious intent
- high score means fewer deterministic findings, not a guarantee of safety

## Quickstart

Local:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
mcp-trust scan --cmd python examples/insecure-server/server.py
```

GitHub Actions:

```yaml
- name: Run MCP Trust Kit
  uses: aak204/MCP-Trust-Kit@v0.4.0
  with:
    cmd: python path/to/your/server.py
    min-score: "80"
    json-out: mcp-trust-report.json
    sarif-out: mcp-trust-report.sarif
```
