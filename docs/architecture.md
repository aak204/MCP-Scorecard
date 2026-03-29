# Architecture

`MCP Trust Kit` keeps the `v0.4.0` pipeline intentionally small and deterministic.

```mermaid
flowchart LR
    A[Local MCP server command] --> B[stdio transport]
    B --> C[Normalization]
    C --> D[Rules registry]
    D --> E[Scoring engine]
    E --> F[Terminal summary]
    E --> G[JSON report]
    E --> H[SARIF report]
    F --> I[CLI and GitHub Actions]
    G --> I
    H --> I
```

Key properties:

- one MCP transport for `v0.4.0`: local `stdio`
- one deterministic rule per file
- one deterministic surface-risk scoring engine
- output layer formats an already-built `Report`
