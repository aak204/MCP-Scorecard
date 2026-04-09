# Validated On Real MCP Servers

This note records a few reproducible validation runs on public MCP servers.

It is not a leaderboard and it is not a claim that a low score means a server is "bad".
The point is narrower: show that `MCP Scorecard` works on real servers outside the demo fixture.

**MCP Scorecard is a deterministic quality scorecard, not a safety verdict.**

Validation date: `2026-03-31`

Reference sources for the public packages used here:

- official servers repo: https://github.com/modelcontextprotocol/servers
- official project site: https://modelcontextprotocol.io

## Environment Note

These validation runs were executed on Windows.

- `mcp-scorecard` launches subprocesses without a shell
- on this machine `npx` resolves through `npx.cmd`
- on macOS or Linux, the equivalent command is usually just `npx`

## 1. Deterministic Demo Fixture

Server:

- [`examples/insecure-server`](../examples/insecure-server/README.md)

Command:

```bash
mcp-scorecard scan --cmd python examples/insecure-server/server.py
```

Windows:

```powershell
.\.venv\Scripts\mcp-scorecard scan --cmd .\.venv\Scripts\python examples\insecure-server\server.py
```

Observed result:

- score: `10/100`
- findings:
  - `overly_generic_tool_name`
  - `vague_tool_description`
  - `schema_allows_arbitrary_properties`
  - `weak_input_schema`
  - `dangerous_exec_tool`
  - `dangerous_fs_write_tool`
  - `write_tool_without_scope_hint`

Caveat:

- this server is intentionally insecure and exists as a stable demo/test asset

## 2. Official Memory Server

Package:

- `@modelcontextprotocol/server-memory@2026.1.26`

Command:

```bash
mcp-scorecard scan --cmd npx -y @modelcontextprotocol/server-memory@2026.1.26
```

Windows:

```powershell
.\.venv\Scripts\mcp-scorecard scan --cmd C:\nvm4w\nodejs\npx.cmd -y @modelcontextprotocol/server-memory@2026.1.26
```

Observed result:

- server name: `memory-server`
- score: `100/100`
- finding count: `0`

Why this is a good case:

- no command execution surface was flagged
- no filesystem mutation surface was flagged
- no noisy schema warning was emitted for a no-arg tool

Caveat:

- `100/100` means no current deterministic findings, not a safety guarantee

## 3. Official Filesystem Server

Package:

- `@modelcontextprotocol/server-filesystem@2026.1.14`

Command:

```bash
mkdir -p .tmp-mcp-fs
mcp-scorecard scan --cmd npx -y @modelcontextprotocol/server-filesystem@2026.1.14 .tmp-mcp-fs
```

Windows:

```powershell
$tmp = Join-Path $PWD ".tmp-mcp-fs"
New-Item -ItemType Directory -Force $tmp | Out-Null
.\.venv\Scripts\mcp-scorecard scan --cmd C:\nvm4w\nodejs\npx.cmd -y @modelcontextprotocol/server-filesystem@2026.1.14 $tmp
```

Observed result:

- server name: `secure-filesystem-server`
- score: `40/100`
- finding count: `3`
- rule hits:
  - `dangerous_fs_write_tool` on `write_file`
  - `dangerous_fs_write_tool` on `edit_file`
  - `dangerous_fs_write_tool` on `create_directory`

Why this is a useful risky case:

- the server legitimately exposes filesystem mutation tools
- the low score reflects blast radius, not exploitability
- this is exactly the kind of capability many teams want surfaced in CI

Caveat:

- this server can still be entirely appropriate in a constrained environment
- `MCP Scorecard` reports deterministic findings, not business intent

## How To Read These Results

- a high score is not a guarantee of safety
- a low score is not a public accusation
- a low score does not mean malicious intent
- the findings are best used as a review signal before adoption
