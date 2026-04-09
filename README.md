# MCP Scorecard

[![Build Status](https://github.com/aak204/MCP-Trust-Kit/actions/workflows/ci.yml/badge.svg)](https://github.com/aak204/MCP-Trust-Kit/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/aak204/MCP-Trust-Kit?sort=semver)](https://github.com/aak204/MCP-Trust-Kit/releases)
[![License](https://img.shields.io/github/license/aak204/MCP-Trust-Kit?v=1)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)

![MCP Scorecard terminal run showing Total Score 40/100 and dangerous filesystem write findings](docs/assets/filesystem-scan-hero.svg)

**Deterministic, CI-first quality scorecard for MCP servers.**

`MCP Scorecard` is an open-source infrastructure tool for reviewing MCP servers before they enter
real workflows. It launches a server locally over `stdio`, discovers its tools, applies a
deterministic ruleset, and produces reviewable scores and findings across:

- `conformance`
- `security`
- `ergonomics`
- `metadata`

The output is built for CI: stable terminal summaries, a machine-readable JSON scorecard report,
and SARIF for code-scanning systems.

This project is intentionally not an AI wrapper. It does not depend on LLM scoring, hidden
judgment, or hosted analysis. The goal is a repeatable, auditable baseline that engineering teams
can gate on in pull requests and release pipelines.

## What This Is

`MCP Scorecard` is a deterministic quality scorecard for MCP servers.

It is designed for cases where teams need to answer questions like:

- Is this server surface reviewable before we adopt it?
- Does it expose capabilities that deserve extra scrutiny in CI?
- Are the tool names, descriptions, and schemas clear enough for human review?
- Can we produce a stable machine-readable report for automation and policy?

Today the tool focuses on local `stdio` MCP servers and a deterministic scoring model that is easy
to explain, test, and version.

## Why This Exists

MCP servers are infrastructure. They define callable tool surfaces that agents, runtimes, and
automation can invoke. That means they should be reviewed with the same seriousness as other
integration boundaries.

In practice, teams often evaluate MCP servers ad hoc:

- descriptions are vague
- schemas are weak or underconstrained
- high-risk capabilities are discovered late
- CI has no consistent baseline

`MCP Scorecard` turns that first-line review into a deterministic contract:

- run it locally
- run it in CI
- inspect category scores and findings
- export JSON and SARIF
- keep the result reviewable over time

## What It Checks

The current score model uses four explicit buckets.

### Conformance

Checks whether the server surface is structurally well-formed and reviewable as an MCP interface.

Examples:

- duplicate tool names
- missing schema type
- arbitrary top-level properties
- critical input fields not marked required

### Security

Checks for exposed capabilities that materially increase blast radius or deserve explicit review.

Examples:

- command execution
- filesystem mutation
- network and HTTP request primitives
- download-and-execute patterns

### Ergonomics

Checks whether the server surface is understandable enough for humans and automation to review
without guessing.

Examples:

- overly generic tool names
- vague descriptions
- weak input schemas
- filesystem mutation tools without visible scope hints

### Metadata

Checks whether basic descriptive metadata is present and whether destructive behavior is made easy
to spot.

Examples:

- missing tool descriptions
- descriptions that explicitly advertise broad destructive access

## What It Does Not Promise

`MCP Scorecard` is intentionally narrow and honest about scope.

It does **not** promise:

- that a high score means a server is safe
- that a low score means a server is malicious
- runtime exploitability analysis
- deployment or isolation verification
- business intent classification
- human approval policy evaluation outside the server surface
- LLM-based scoring
- hosted scanning or registry-backed certification claims

The score measures **deterministic, reviewable properties only**.

That is the point of the tool.

## Quickstart Local

Scan the included insecure demo server:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
mcp-scorecard scan --cmd python examples/insecure-server/server.py
```

Generate JSON and SARIF and enforce a score gate:

```bash
mcp-scorecard scan \
  --min-score 80 \
  --json-out mcp-scorecard-report.json \
  --sarif mcp-scorecard-report.sarif \
  --cmd python examples/insecure-server/server.py
```

The scanner launches `--cmd` directly without a shell. In practice that means `python`, `npx`,
`uvx`, or a compiled binary can all work as long as you pass the real executable and args.

The preferred CLI name for `v1.0.0` is `mcp-scorecard`. The legacy `mcp-trust` command remains
available as a compatibility alias. The Python module remains `mcp_trust`.

<details>
<summary>Windows (PowerShell)</summary>

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .[dev]
.\.venv\Scripts\mcp-scorecard scan --cmd .\.venv\Scripts\python examples\insecure-server\server.py
```

</details>

## GitHub Actions Quickstart

Drop this workflow into your repository:

```yaml
name: MCP Scorecard

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

      - name: Run MCP Scorecard
        id: scorecard
        uses: aak204/MCP-Trust-Kit@v1.0.0
        with:
          cmd: python path/to/your/server.py
          min-score: "80"
          json-out: mcp-scorecard-report.json
          sarif-out: mcp-scorecard-report.sarif
          markdown-out: mcp-scorecard-summary.md

      - name: Use Scorecard Outputs
        if: always()
        run: |
          echo "total score: ${{ steps.scorecard.outputs.total-score }}"
          echo "passed: ${{ steps.scorecard.outputs.passed }}"
          echo 'category scores: ${{ steps.scorecard.outputs.category-scores }}'

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: mcp-scorecard-report.sarif
```

The action preserves the current local use case but packages it as a CI-first scorecard step.

Inputs:

- `cmd`
- `min-score`
- `json-out`
- `sarif-out`
- `markdown-out`

Outputs:

- `total-score`
- `category-scores`
- `passed`

Each run also writes a PR-friendly Markdown summary to the GitHub Actions step summary. If
`markdown-out` is set, the same summary is written to a file inside the workspace.

The current action reference stays `aak204/MCP-Trust-Kit@v1.0.0` while the repository name remains
unchanged for compatibility.

## Example Output

Current terminal output for [`examples/insecure-server`](examples/insecure-server/README.md):

```text
Generator: MCP Scorecard (mcp-scorecard 1.0.0)
Report Schema: mcp-scorecard-report@1.0
Scan Timestamp: 2026-04-09T15:49:48.930250+00:00
Server: Insecure Demo Server
Version: 0.1.0
Protocol: 2025-11-25
Target: stdio:[".\\.venv\\Scripts\\python","examples\\insecure-server\\server.py"]
Target Description: Local MCP server launched over stdio.
Tools: 4
Finding Counts: total=7, error=2, warning=5, info=0
Total Score: 10/100
Why This Score: Score is driven mainly by security findings in command execution and file system and ergonomics findings.
Score Meaning: Deterministic CI-first quality scorecard based on conformance, security-relevant capabilities, ergonomics, and metadata hygiene.
Category Scores:
- conformance: 90/100 (findings: 1, penalties: 10)
- security: 60/100 (findings: 2, penalties: 40)
- ergonomics: 60/100 (findings: 4, penalties: 40)
- metadata: 100/100 (findings: 0, penalties: 0)
Findings By Bucket:
- security: 2 findings, penalties: 40
  - ERROR dangerous_exec_tool [exec_command]: Tool 'exec_command' appears to expose host command execution.
  - ERROR dangerous_fs_write_tool [write_file]: Tool 'write_file' appears to provide filesystem write access.
- ergonomics: 4 findings, penalties: 40
  - WARNING weak_input_schema [debug_payload]: Tool 'debug_payload' exposes a weak input schema that leaves free-form input underconstrained.
  - WARNING overly_generic_tool_name [do_it]: Tool 'do_it' uses an overly generic name that hides its behavior.
  - WARNING vague_tool_description [do_it]: Tool 'do_it' uses a vague description that does not explain its behavior clearly.
  - WARNING write_tool_without_scope_hint [write_file]: Tool 'write_file' modifies the filesystem without any visible scope hint.
- conformance: 1 finding, penalties: 10
  - WARNING schema_allows_arbitrary_properties [debug_payload]: Tool 'debug_payload' allows arbitrary additional input properties.
Limitations:
- Low score means more deterministic findings or higher-risk exposed surface, not malicious intent.
- High score means fewer deterministic findings, not a guarantee of safety.
```

Sample artifacts in this repository:

- [sample-reports/insecure-server.report.json](sample-reports/insecure-server.report.json)
- [sample-reports/insecure-server.report.sarif](sample-reports/insecure-server.report.sarif)
- [sample-reports/insecure-server.terminal.md](sample-reports/insecure-server.terminal.md)

## Score Model Summary

The score model is deliberately simple.

1. Start at `100`
2. Apply fixed deterministic penalties for findings
3. Clamp scores to `0..100`
4. Compute bucket scores the same way for `conformance`, `security`, `ergonomics`, and `metadata`

Severity mapping in the current release line:

| Severity | Penalty |
| --- | --- |
| `info` | `0` |
| `warning` | `10` |
| `error` | `20` |

Every check carries explicit metadata:

- `id`
- `title`
- `bucket`
- `severity`
- `rationale`

Every report exposes:

- total score
- category scores
- finding counts
- findings with full metadata
- grouped findings by bucket
- why this score
- score meaning and limitations

This keeps the output reviewable, testable, and stable in CI.

## Output Formats

`MCP Scorecard` currently emits four practical outputs:

### Terminal Summary

Human-readable summary for local runs and CI logs.

### JSON V1 Scorecard Report

Canonical machine-readable report format. The stable V1 top-level shape is:

- `schema`
- `generator`
- `scan`
- `inventory`
- `scorecard`
- `checks`
- `findings`
- `grouped_findings`
- `metadata`

### SARIF

For GitHub code scanning and other SARIF-capable consumers. SARIF remains aligned with the current
findings model and includes scorecard metadata on the SARIF run.

### GitHub Actions Step Summary

PR-friendly Markdown summary with total score, pass/fail, and category scores.

JUnit is intentionally out of scope for the current release surface.

## What The Score Means

The score is a deterministic review signal.

- High score does **not** mean safe
- Low score does **not** mean malicious
- The score measures deterministic, reviewable properties only

That means the score is useful as:

- a CI gate
- a review baseline
- a release artifact
- an input to broader engineering judgment

It is not a substitute for runtime controls, sandboxing, environment isolation, or human approval.

## Limitations

Current limitations are explicit:

- primary transport focus is local `stdio`
- checks are static and deterministic, not dynamic or behavioral
- runtime isolation is out of scope
- exploitability claims are out of scope
- business intent is out of scope
- LLM scoring is out of scope
- hosted scanning is out of scope

This scope is intentional. A smaller deterministic contract is more useful in CI than a broader
but opaque system.

## Validated On Real MCP Servers

Validation date: `2026-03-29`

| Server | Source | Result | Notes |
| --- | --- | --- | --- |
| `examples/insecure-server` | local demo | `10/100` | intentionally low-scoring deterministic fixture |
| `@modelcontextprotocol/server-memory@2026.1.26` | official public package | `100/100` | no findings under current deterministic rules |
| `@modelcontextprotocol/server-filesystem@2026.1.14` | official public package | `40/100` | legitimate filesystem mutation surface is surfaced for review |

Commands, caveats, and findings:

- [docs/validated-servers.md](docs/validated-servers.md)

## Output And Architecture References

- [docs/architecture.md](docs/architecture.md)
- [docs/validated-servers.md](docs/validated-servers.md)
- [docs/assets/filesystem-scan-hero.svg](docs/assets/filesystem-scan-hero.svg)
- [examples/insecure-server/README.md](examples/insecure-server/README.md)
- [.github/workflows/example.yml](.github/workflows/example.yml)

## Roadmap

Near-term work after the current release surface:

- expand deterministic checks across `conformance`, `security`, `ergonomics`, and `metadata`
- improve SARIF location mapping when source context is available
- add more real-world validation cases and sample reports
- add more transport options once the current score contract stays stable
- clean up remaining compatibility naming around repo/package/action references

Not on the immediate path:

- LLM scoring in the core engine
- hosted scorecard service
- registry integration in the release path
- certification-style claims

## Contributing

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
python -m pytest
python -m ruff check .
python -m mypy
```

Good contribution areas:

- new deterministic checks with tests
- `stdio` transport hardening
- reporter improvements that preserve stable output
- reproducible validation cases
- documentation and sample artifacts

## License

Apache-2.0. See [LICENSE](LICENSE).
