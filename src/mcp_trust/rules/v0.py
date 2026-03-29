"""Default deterministic ruleset for MCP Trust Kit v0."""

from __future__ import annotations

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
from mcp_trust.rules.registry import RuleRegistry
from mcp_trust.rules.schema_allows_arbitrary_properties import (
    SchemaAllowsArbitraryPropertiesRule,
)
from mcp_trust.rules.tool_description_mentions_destructive_access import (
    ToolDescriptionMentionsDestructiveAccessRule,
)
from mcp_trust.rules.vague_tool_description import VagueToolDescriptionRule
from mcp_trust.rules.weak_input_schema import WeakInputSchemaRule
from mcp_trust.rules.write_tool_without_scope_hint import WriteToolWithoutScopeHintRule

RULES_V0 = (
    DuplicateToolNamesRule(),
    MissingToolDescriptionRule(),
    OverlyGenericToolNameRule(),
    VagueToolDescriptionRule(),
    MissingSchemaTypeRule(),
    SchemaAllowsArbitraryPropertiesRule(),
    WeakInputSchemaRule(),
    MissingRequiredForCriticalFieldsRule(),
    DangerousExecToolRule(),
    DangerousShellDownloadExecRule(),
    DangerousFsWriteToolRule(),
    DangerousFsDeleteToolRule(),
    DangerousHttpRequestToolRule(),
    DangerousNetworkToolRule(),
    WriteToolWithoutScopeHintRule(),
    ToolDescriptionMentionsDestructiveAccessRule(),
)


def build_v0_rule_registry() -> RuleRegistry:
    """Return the default ordered ruleset for MCP Trust Kit v0."""
    return RuleRegistry.from_rules(RULES_V0)
