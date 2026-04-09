# Insecure Demo Server

This example is a tiny deterministic MCP server that intentionally exposes risky tools.

It exists for:

- local manual checks with `mcp-scorecard scan`
- future README screenshots and examples
- stable scanner tests that should always produce the same findings

## Why It Is Insecure

The tool surface is intentionally problematic:

- `exec_command`: arbitrary shell execution
- `write_file`: filesystem write access
- `do_it`: vague, low-quality description
- `debug_payload`: excessively weak input schema with open-ended arbitrary payload

## Run Locally

From the repository root:

```bash
python examples/insecure-server/server.py
```

Scan it with MCP Scorecard:

```bash
mcp-scorecard scan --cmd python examples/insecure-server/server.py
```

With the local virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
mcp-scorecard scan --cmd python examples/insecure-server/server.py
```

<details>
<summary>Windows (PowerShell)</summary>

```powershell
.\.venv\Scripts\mcp-scorecard scan --cmd .\.venv\Scripts\python examples\insecure-server\server.py
```

</details>

Sample launch artifacts generated from this server:

- [`sample-reports/insecure-server.report.json`](../../sample-reports/insecure-server.report.json)
- [`sample-reports/insecure-server.report.sarif`](../../sample-reports/insecure-server.report.sarif)
- [`sample-reports/insecure-server.terminal.md`](../../sample-reports/insecure-server.terminal.md)

## Expected Findings

This example should reliably trigger findings such as:

- dangerous shell execution capability
- filesystem write capability
- vague or low-signal metadata
- underconstrained input schema
- missing scope hint for filesystem mutation

## Notes

- This server is intentionally insecure and should not be used outside demos/tests.
- It implements only the minimal MCP handshake needed for local discovery.
