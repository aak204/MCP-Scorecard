# Insecure Server Terminal Output

```text
Generator: MCP Scorecard (mcp-scorecard 1.0.0)
Report Schema: mcp-scorecard-report@1.0
Scan Timestamp: 2026-04-09T16:08:35.505980+00:00
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
