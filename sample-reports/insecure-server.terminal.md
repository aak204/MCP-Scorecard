# Insecure Server Terminal Output

```text
Server: Insecure Demo Server
Version: 0.1.0
Protocol: 2025-11-25
Target: stdio:[".\\.venv\\Scripts\\python","examples\\insecure-server\\server.py"]
Tools: 4
Findings: 7
Severity: error=2, warning=5, info=0
Total Score: 10/100
Score Meaning: Deterministic surface-risk score based on protocol/tool hygiene and risky exposed capabilities.
Why This Score: Score is driven mainly by detected command execution and file system issues.
High-Risk Capabilities: command execution, file system, external side effects
Review First: write_file, exec_command, debug_payload, do_it
Category Scores:
- spec: 60/100 (penalties: 40)
- auth: 100/100 (penalties: 0)
- secrets: 100/100 (penalties: 0)
- tool_surface: 50/100 (penalties: 50)
Top Findings:
- ERROR dangerous_exec_tool [exec_command]: Tool 'exec_command' appears to expose host command execution.
- ERROR dangerous_fs_write_tool [write_file]: Tool 'write_file' appears to provide filesystem write access.
- WARNING schema_allows_arbitrary_properties [debug_payload]: Tool 'debug_payload' allows arbitrary additional input properties.
- WARNING weak_input_schema [debug_payload]: Tool 'debug_payload' exposes a weak input schema that leaves free-form input underconstrained.
- WARNING overly_generic_tool_name [do_it]: Tool 'do_it' uses an overly generic name that hides its behavior.
Score Limits:
- Low score means higher exposed surface risk, not malicious intent.
- High score means fewer deterministic findings, not a guarantee of safety.
```
