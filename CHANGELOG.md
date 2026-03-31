# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project uses Semantic Versioning.

## [0.5.0] - 2026-03-31

Integration-driven release.

### Added

- explicit `scan_timestamp` field in JSON reports for downstream temporal-decay consumers
- matching scan timestamp metadata in SARIF run properties and invocation metadata
- release-ready interface contract for Layer 1 style static baseline consumers

### Changed

- bumped report schema version to `0.5`
- refreshed release docs and README examples for `v0.5.0`
- regenerated sample artifacts from the current scanner output

### Notes

- `generated_at` is retained for backward compatibility
- `scan_timestamp` is the canonical cross-layer timestamp field going forward

## [0.4.0] - 2026-03-29

First practically useful public release.

### Added

- expanded deterministic ruleset for schema hygiene and risky exposed capabilities
- capability-aware risk categories in findings and report summaries
- terminal summary sections for score meaning, why-score explanation, high-risk capabilities, and review-first tools
- repo CI workflow at `.github/workflows/ci.yml`

### Changed

- repositioned the score as deterministic surface risk rather than abstract trust
- refined `weak_input_schema` to avoid penalizing empty object schemas for no-arg tools by default
- Bash-first README and validation docs, with Windows examples moved behind details or separate notes
- real-world validation docs refreshed against public MCP servers

### Fixed

- filesystem delete heuristic no longer false-positives on `directory_tree` and `get_file_info`
- public example and sample artifacts regenerated from current scanner behavior

## [0.3.0] - 2026-03-29

Initial public release.

### Added

- local `stdio` MCP discovery transport with deterministic handshake and tool listing
- normalized data models for servers, tools, findings, reports, and score breakdowns
- deterministic v0 ruleset for tool hygiene and risky tool surface
- stable penalty-based scoring engine with category breakdowns
- terminal summary, JSON report, and SARIF export
- `mcp-trust scan` CLI with score gating and release-friendly exit codes
- composite GitHub Action for CI usage
- demo MCP servers, sample reports, and release docs

### Changed

- release surface hardened for public GitHub usage
- README rewritten for quickstart, GitHub Actions, scoring, and sample artifacts

### Fixed

- CLI examples aligned on `--cmd`
- sample artifacts regenerated from current real scanner behavior
- package license metadata normalized to SPDX form for distribution metadata
