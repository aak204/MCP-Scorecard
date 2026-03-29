"""SARIF report serialization for GitHub code scanning."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from mcp_trust import __version__
from mcp_trust.models import Finding, FindingLevel, Report, RuleDescriptor

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"


class SarifReporter:
    """Render a report into a minimal useful SARIF 2.1.0 document."""

    reporter_id = "sarif"
    default_filename = "mcp-trust-report.sarif"

    def render(self, report: Report) -> str:
        """Render the report as formatted SARIF JSON."""
        sarif_data = report_to_sarif_data(report)
        return json.dumps(sarif_data, indent=2, sort_keys=False) + "\n"


def report_to_sarif_data(report: Report) -> dict[str, object]:
    """Return a SARIF-compatible representation of a report."""
    rule_descriptors = tuple(report.rule_descriptors.values())
    artifact_uri = _infer_artifact_uri(report)

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCP Trust Kit",
                        "semanticVersion": __version__,
                        "rules": [
                            _serialize_rule_descriptor(rule_descriptor)
                            for rule_descriptor in rule_descriptors
                        ],
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "workingDirectory": {"uri": Path.cwd().as_uri()},
                    }
                ],
                "results": [
                    _serialize_result(
                        finding,
                        report.rule_descriptors,
                        artifact_uri,
                        rule_descriptors,
                    )
                    for finding in report.findings
                ],
            }
        ],
    }


def _serialize_rule_descriptor(rule_descriptor: RuleDescriptor) -> dict[str, object]:
    """Serialize one rule descriptor for SARIF."""
    level = _map_level(rule_descriptor.severity)
    return {
        "id": rule_descriptor.rule_id,
        "name": rule_descriptor.name,
        "shortDescription": {"text": rule_descriptor.name},
        "fullDescription": {"text": rule_descriptor.summary},
        "defaultConfiguration": {"level": level},
        "help": {
            "text": (
                f"{rule_descriptor.summary} "
                f"Severity: {rule_descriptor.severity.value}. "
                f"Score impact: {rule_descriptor.score_impact}."
            )
        },
        "properties": {
            "tags": list(_build_rule_tags(rule_descriptor)),
            "precision": "medium",
            "problem.severity": _map_problem_severity(rule_descriptor.severity),
            "risk_category": rule_descriptor.risk_category.value,
            "score_category": rule_descriptor.score_category.value,
            "score_impact": rule_descriptor.score_impact,
        },
    }


def _serialize_result(
    finding: Finding,
    rule_descriptors: dict[str, RuleDescriptor],
    artifact_uri: str | None,
    ordered_rule_descriptors: tuple[RuleDescriptor, ...],
) -> dict[str, object]:
    """Serialize one finding into a SARIF result."""
    result: dict[str, object] = {
        "ruleId": finding.rule_id,
        "ruleIndex": _rule_index(finding.rule_id, ordered_rule_descriptors),
        "level": _map_level(finding.severity),
        "message": {"text": finding.message},
        "partialFingerprints": {
            "primaryLocationLineHash": _fingerprint(finding, artifact_uri),
        },
        "properties": {
            "risk_category": finding.risk_category.value,
            "score_category": finding.score_category.value,
            "score_impact": finding.score_impact,
            "tool_name": finding.tool_name,
            "finding_category": None if finding.category is None else finding.category.value,
            "evidence": list(finding.evidence),
        },
    }

    if artifact_uri is not None:
        location: dict[str, object] = {
            "physicalLocation": {
                "artifactLocation": {"uri": artifact_uri},
                "region": {"startLine": 1},
            }
        }
        if finding.evidence:
            location["message"] = {"text": finding.evidence[0]}
        result["locations"] = [location]

    rule_descriptor = rule_descriptors.get(finding.rule_id)
    if rule_descriptor is not None:
        result["rule"] = {"id": rule_descriptor.rule_id}

    return result


def _map_level(level: FindingLevel) -> str:
    """Map internal finding severity to SARIF severity."""
    if level is FindingLevel.ERROR:
        return "error"
    if level is FindingLevel.WARNING:
        return "warning"
    return "note"


def _map_problem_severity(level: FindingLevel) -> str:
    """Map finding severity to SARIF non-security problem severity."""
    if level is FindingLevel.ERROR:
        return "error"
    if level is FindingLevel.WARNING:
        return "warning"
    return "recommendation"


def _build_rule_tags(rule_descriptor: RuleDescriptor) -> tuple[str, ...]:
    """Return stable SARIF tags for a rule."""
    tags = list(rule_descriptor.tags)
    tags.append(rule_descriptor.category.value)
    tags.append(rule_descriptor.risk_category.value)
    tags.append(rule_descriptor.score_category.value)
    return tuple(dict.fromkeys(tags))


def _rule_index(rule_id: str, ordered_rule_descriptors: tuple[RuleDescriptor, ...]) -> int:
    """Return the SARIF rule index for a finding."""
    for index, rule_descriptor in enumerate(ordered_rule_descriptors):
        if rule_descriptor.rule_id == rule_id:
            return index
    raise KeyError(f"Missing rule descriptor for SARIF result {rule_id!r}.")


def _fingerprint(finding: Finding, artifact_uri: str | None) -> str:
    """Return a stable partial fingerprint for one finding."""
    fingerprint_source = "|".join(
        [
            finding.rule_id,
            finding.tool_name or "",
            finding.message,
            artifact_uri or "",
            *finding.evidence,
        ]
    )
    return hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()


def _infer_artifact_uri(report: Report) -> str | None:
    """Infer a useful file location for SARIF results when possible."""
    mcp_metadata = report.server.metadata.get("mcp")
    if not isinstance(mcp_metadata, dict):
        return None

    command = mcp_metadata.get("command")
    if not isinstance(command, list):
        return None

    for part in command[1:]:
        normalized = _normalize_path_candidate(part)
        if normalized is not None:
            return normalized

    if command:
        return _normalize_path_candidate(command[0])
    return None


def _normalize_path_candidate(candidate: object) -> str | None:
    """Normalize a command argument into a SARIF artifact URI when possible."""
    if not isinstance(candidate, str) or not candidate.strip():
        return None

    path = Path(candidate)
    suffix = path.suffix.lower()
    looks_like_file = suffix in {
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".mjs",
        ".cjs",
        ".rb",
        ".go",
        ".java",
    }
    has_path_separator = "\\" in candidate or "/" in candidate

    if not looks_like_file and not has_path_separator:
        return None

    if path.is_absolute():
        try:
            path = path.relative_to(Path.cwd())
        except ValueError:
            return path.as_posix()

    return path.as_posix()
