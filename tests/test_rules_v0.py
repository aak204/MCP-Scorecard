from __future__ import annotations

import sys
from pathlib import Path

from mcp_trust.models import (
    FindingCategory,
    FindingLevel,
    NormalizedServer,
    NormalizedTool,
    RiskCategory,
    ScoreCategory,
)
from mcp_trust.rules.dangerous_exec_tool import DangerousExecToolRule
from mcp_trust.rules.dangerous_fs_delete_tool import DangerousFsDeleteToolRule
from mcp_trust.rules.dangerous_fs_write_tool import DangerousFsWriteToolRule
from mcp_trust.rules.dangerous_http_request_tool import DangerousHttpRequestToolRule
from mcp_trust.rules.dangerous_network_tool import DangerousNetworkToolRule
from mcp_trust.rules.dangerous_shell_download_exec import DangerousShellDownloadExecRule
from mcp_trust.rules.duplicate_tool_names import DuplicateToolNamesRule
from mcp_trust.rules.missing_required_for_critical_fields import (
    MissingRequiredForCriticalFieldsRule,
)
from mcp_trust.rules.missing_schema_type import MissingSchemaTypeRule
from mcp_trust.rules.missing_tool_description import MissingToolDescriptionRule
from mcp_trust.rules.overly_generic_tool_name import OverlyGenericToolNameRule
from mcp_trust.rules.schema_allows_arbitrary_properties import (
    SchemaAllowsArbitraryPropertiesRule,
)
from mcp_trust.rules.tool_description_mentions_destructive_access import (
    ToolDescriptionMentionsDestructiveAccessRule,
)
from mcp_trust.rules.v0 import RULES_V0, build_v0_rule_registry
from mcp_trust.rules.vague_tool_description import VagueToolDescriptionRule
from mcp_trust.rules.weak_input_schema import WeakInputSchemaRule
from mcp_trust.rules.write_tool_without_scope_hint import WriteToolWithoutScopeHintRule
from mcp_trust.scoring import ScoringEngine
from mcp_trust.transports import StdioServerConfig, StdioTransport

INSECURE_SERVER = (
    Path(__file__).resolve().parents[1] / "examples" / "insecure-server" / "server.py"
)


def _server(*tools: NormalizedTool) -> NormalizedServer:
    return NormalizedServer(target="stdio://test-server", tools=tools)


def test_v0_ruleset_contains_expected_rules_in_order() -> None:
    registry = build_v0_rule_registry()

    assert registry.rule_ids == (
        "duplicate_tool_names",
        "missing_tool_description",
        "overly_generic_tool_name",
        "vague_tool_description",
        "missing_schema_type",
        "schema_allows_arbitrary_properties",
        "weak_input_schema",
        "missing_required_for_critical_fields",
        "dangerous_exec_tool",
        "dangerous_shell_download_exec",
        "dangerous_fs_write_tool",
        "dangerous_fs_delete_tool",
        "dangerous_http_request_tool",
        "dangerous_network_tool",
        "write_tool_without_scope_hint",
        "tool_description_mentions_destructive_access",
    )
    assert tuple(rule.rule_id for rule in RULES_V0) == registry.rule_ids


def test_metadata_rules_emit_expected_findings() -> None:
    server = _server(
        NormalizedTool(name="do_it"),
        NormalizedTool(name="do_it", description="Helps with stuff."),
    )

    duplicate_finding = DuplicateToolNamesRule().evaluate(server)
    missing_description_finding = MissingToolDescriptionRule().evaluate(server)
    generic_name_findings = OverlyGenericToolNameRule().evaluate(server)
    vague_findings = VagueToolDescriptionRule().evaluate(server)

    assert len(duplicate_finding) == 1
    assert duplicate_finding[0].severity is FindingLevel.ERROR
    assert duplicate_finding[0].category is FindingCategory.TOOL_IDENTITY
    assert duplicate_finding[0].score_category is ScoreCategory.SPEC
    assert duplicate_finding[0].risk_category is RiskCategory.METADATA_HYGIENE

    assert len(missing_description_finding) == 1
    assert missing_description_finding[0].severity is FindingLevel.WARNING
    assert missing_description_finding[0].category is FindingCategory.TOOL_DESCRIPTION
    assert "description=<missing>" in missing_description_finding[0].evidence

    assert [finding.tool_name for finding in generic_name_findings] == ["do_it", "do_it"]
    assert all(
        finding.risk_category is RiskCategory.METADATA_HYGIENE
        for finding in generic_name_findings
    )

    assert [finding.tool_name for finding in vague_findings] == ["do_it"]
    assert vague_findings[0].evidence == (
        "description='Helps with stuff.'",
        "word_count=3",
        "matched_phrase='helps with stuff'",
    )


def test_schema_rules_emit_expected_findings_and_skip_no_arg_empty_object_tools() -> None:
    server = _server(
        NormalizedTool(
            name="debug_payload",
            description="Accept an arbitrary debug payload.",
            input_schema={
                "type": "object",
                "description": "Arbitrary debug payload.",
                "additionalProperties": True,
            },
        ),
        NormalizedTool(
            name="submit_request",
            description="Submit an input payload.",
            input_schema={},
        ),
        NormalizedTool(
            name="fetch_url",
            description="Fetch a URL.",
            input_schema={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                },
                "required": [],
                "additionalProperties": False,
            },
        ),
        NormalizedTool(
            name="get_current_time",
            description="Return the current time.",
            input_schema={
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        ),
    )

    schema_type_findings = MissingSchemaTypeRule().evaluate(server)
    schema_open_findings = SchemaAllowsArbitraryPropertiesRule().evaluate(server)
    weak_schema_findings = WeakInputSchemaRule().evaluate(server)
    missing_required_findings = MissingRequiredForCriticalFieldsRule().evaluate(server)

    assert [finding.tool_name for finding in schema_type_findings] == ["submit_request"]
    assert [finding.tool_name for finding in schema_open_findings] == ["debug_payload"]
    assert [finding.tool_name for finding in weak_schema_findings] == ["debug_payload"]
    assert weak_schema_findings[0].evidence == (
        "matched_heuristic=inputful_tool_with_empty_object_schema",
    )
    assert [finding.tool_name for finding in missing_required_findings] == ["fetch_url"]
    assert missing_required_findings[0].evidence == (
        "critical_fields=['url']",
        "required_fields=[]",
    )


def test_capability_rules_emit_expected_findings() -> None:
    server = _server(
        NormalizedTool(
            name="exec_command",
            description="Execute an arbitrary shell command on the host machine.",
            input_schema={
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                },
                "required": ["command"],
                "additionalProperties": False,
            },
        ),
        NormalizedTool(
            name="write_file",
            description="Write text content to any file path on disk.",
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
                "additionalProperties": False,
            },
        ),
        NormalizedTool(
            name="delete_file",
            description="Delete any file from disk without validation.",
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        ),
        NormalizedTool(
            name="http_fetch",
            description="Issue an HTTP request to a remote API.",
            input_schema={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                },
                "required": ["url"],
                "additionalProperties": False,
            },
        ),
        NormalizedTool(
            name="connect_socket",
            description="Open a raw network socket to a remote host.",
            input_schema={
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "port": {"type": "integer"},
                },
                "required": ["host", "port"],
                "additionalProperties": False,
            },
        ),
        NormalizedTool(
            name="download_exec",
            description="Download a remote payload and execute it as a shell command.",
            input_schema={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "command": {"type": "string"},
                },
                "required": ["url", "command"],
                "additionalProperties": False,
            },
        ),
    )

    exec_findings = DangerousExecToolRule().evaluate(server)
    fs_findings = DangerousFsWriteToolRule().evaluate(server)
    fs_delete_findings = DangerousFsDeleteToolRule().evaluate(server)
    http_findings = DangerousHttpRequestToolRule().evaluate(server)
    network_findings = DangerousNetworkToolRule().evaluate(server)
    download_exec_findings = DangerousShellDownloadExecRule().evaluate(server)
    scope_findings = WriteToolWithoutScopeHintRule().evaluate(server)
    destructive_description_findings = (
        ToolDescriptionMentionsDestructiveAccessRule().evaluate(server)
    )

    assert [finding.tool_name for finding in exec_findings] == ["exec_command", "download_exec"]
    assert exec_findings[0].risk_category is RiskCategory.COMMAND_EXECUTION
    assert "input_keys=['command']" in exec_findings[0].evidence

    assert [finding.tool_name for finding in fs_findings] == ["write_file"]
    assert fs_findings[0].risk_category is RiskCategory.FILE_SYSTEM
    assert "path_keys=['path']" in fs_findings[0].evidence

    assert [finding.tool_name for finding in fs_delete_findings] == ["delete_file"]
    assert fs_delete_findings[0].severity is FindingLevel.ERROR

    assert [finding.tool_name for finding in http_findings] == ["http_fetch", "download_exec"]
    assert [finding.tool_name for finding in network_findings] == ["connect_socket"]
    assert [finding.tool_name for finding in download_exec_findings] == ["download_exec"]

    assert [finding.tool_name for finding in scope_findings] == ["write_file", "delete_file"]
    assert [finding.tool_name for finding in destructive_description_findings] == ["delete_file"]


def test_fs_delete_rule_avoids_rm_substring_false_positives() -> None:
    server = _server(
        NormalizedTool(
            name="directory_tree",
            description="Return a recursive directory tree.",
            input_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": False,
            },
        ),
        NormalizedTool(
            name="get_file_info",
            description="Retrieve file metadata.",
            input_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": False,
            },
        ),
    )

    assert DangerousFsDeleteToolRule().evaluate(server) == ()


def test_v0_ruleset_finds_expected_issues_on_insecure_server() -> None:
    transport = StdioTransport()
    server = transport.scan(
        StdioServerConfig.from_command(
            (sys.executable, str(INSECURE_SERVER)),
            timeout_seconds=1.0,
        )
    )
    report = ScoringEngine(build_v0_rule_registry()).evaluate(server)

    assert tuple(finding.rule_id for finding in report.findings) == (
        "overly_generic_tool_name",
        "vague_tool_description",
        "schema_allows_arbitrary_properties",
        "weak_input_schema",
        "dangerous_exec_tool",
        "dangerous_fs_write_tool",
        "write_tool_without_scope_hint",
    )
    assert report.score.penalty_points == 90
    assert report.score.final_score == 10
    assert report.score.category_breakdown[ScoreCategory.SPEC].score == 60
    assert report.score.category_breakdown[ScoreCategory.TOOL_SURFACE].score == 50
    assert all(finding.title is not None for finding in report.findings)
    assert all(finding.evidence for finding in report.findings)
