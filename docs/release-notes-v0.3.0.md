# MCP Scorecard v0.3.0

Historical initial public release of the project now presented as `MCP Scorecard`.

`MCP Scorecard` is a deterministic scanner for MCP servers. It runs local `stdio` discovery,
normalizes tool metadata, applies explainable rules, calculates a quality score, and emits terminal,
JSON, and SARIF output for local use and GitHub Actions.

## Highlights

- deterministic checks for protocol and tool hygiene
- risky tool surface detection for exec-like and filesystem write tools
- stable quality score with category breakdowns
- JSON report for CI and future integrations
- SARIF export for GitHub code scanning
- `mcp-trust scan` CLI with score thresholds and release-friendly exit codes
- copy-pasteable GitHub Action

## Included In v0.3.0

- local `stdio` MCP transport
- normalized server, tool, finding, and report models
- first deterministic ruleset:
  - `duplicate_tool_names`
  - `missing_tool_description`
  - `vague_tool_description`
  - `weak_input_schema`
  - `dangerous_exec_tool`
  - `dangerous_fs_write_tool`
- terminal summary reporter
- JSON reporter
- SARIF reporter
- example insecure MCP server
- sample reports and release docs

## Quickstart

Local:

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -e .[dev]
.\.venv\Scripts\mcp-trust scan --cmd .\.venv\Scripts\python examples\insecure-server\server.py
```

GitHub Actions:

```yaml
- name: Run MCP Scorecard
  uses: <owner>/mcp-trust-kit@v0.3.0
  with:
    cmd: python path/to/your/server.py
    min-score: "80"
    json-out: mcp-scorecard-report.json
    sarif-out: mcp-scorecard-report.sarif
```

## Notes

- v0.3.0 supports local `stdio` servers
- the scoring model is deterministic and penalty-based
- the tool is usable today, but intentionally narrow
- HTTP and SSE transports are not part of this release
