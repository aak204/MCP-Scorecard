"""Shared deterministic tool-surface heuristics used by multiple rules."""

from __future__ import annotations

from collections.abc import Iterable

from mcp_trust.models import JSONValue

GENERIC_INPUT_KEYS = (
    "input",
    "payload",
    "data",
    "body",
    "request",
    "params",
    "parameters",
    "options",
    "query",
    "filter",
    "command",
)
CRITICAL_KEYS = (
    "path",
    "url",
    "uri",
    "endpoint",
    "host",
    "port",
    "command",
    "source",
    "destination",
    "content",
    "body",
)
PATH_KEYS = ("path", "file_path", "filepath", "filename", "target_path", "directory")
CONTENT_KEYS = ("content", "text", "body", "data", "contents")
URL_KEYS = ("url", "uri", "endpoint", "host", "webhook_url")
SCOPE_HINTS = (
    "allowed directories",
    "allowed directory",
    "within allowed",
    "working directory",
    "workspace",
    "sandbox",
    "project directory",
    "scoped",
)
INPUTFUL_TOOL_MARKERS = (
    "input",
    "payload",
    "data",
    "body",
    "request",
    "query",
    "search",
    "debug",
    "submit",
    "send",
)


def normalize_text(value: str | None) -> str:
    """Return a lower-cased string for heuristics."""
    return "" if value is None else value.strip().lower()


def schema_type(input_schema: dict[str, JSONValue]) -> str | None:
    """Return the top-level schema type when it is a string."""
    raw_type = input_schema.get("type")
    return raw_type if isinstance(raw_type, str) else None


def schema_properties(input_schema: dict[str, JSONValue]) -> dict[str, JSONValue]:
    """Return object properties when present, otherwise an empty mapping."""
    raw_properties = input_schema.get("properties")
    if not isinstance(raw_properties, dict):
        return {}
    return raw_properties


def schema_property_names(input_schema: dict[str, JSONValue]) -> tuple[str, ...]:
    """Return normalized schema property names."""
    return tuple(key.lower() for key in schema_properties(input_schema))


def schema_required_fields(input_schema: dict[str, JSONValue]) -> tuple[str, ...]:
    """Return normalized required field names."""
    raw_required = input_schema.get("required")
    if not isinstance(raw_required, list):
        return ()
    required_fields: list[str] = []
    for item in raw_required:
        if isinstance(item, str):
            normalized = item.strip().lower()
            if normalized:
                required_fields.append(normalized)
    return tuple(required_fields)


def additional_properties(input_schema: dict[str, JSONValue]) -> JSONValue | None:
    """Return the ``additionalProperties`` value when present."""
    return input_schema.get("additionalProperties")


def matching_markers(text: str, markers: Iterable[str]) -> tuple[str, ...]:
    """Return stable marker matches for the provided normalized text."""
    return tuple(marker for marker in markers if marker in text)


def matching_keys(property_names: Iterable[str], keys: Iterable[str]) -> tuple[str, ...]:
    """Return stable key matches against normalized property names."""
    property_name_set = tuple(property_names)
    return tuple(key for key in keys if key in property_name_set)


def has_scope_hint(
    *,
    description: str | None,
    input_schema: dict[str, JSONValue],
) -> bool:
    """Return whether the description or schema hints at scoped side effects."""
    normalized_description = normalize_text(description)
    if any(marker in normalized_description for marker in SCOPE_HINTS):
        return True

    properties = schema_properties(input_schema)
    for property_name, property_schema in properties.items():
        normalized_name = property_name.lower()
        if normalized_name in {"root", "workspace", "allowed_directory", "scope"}:
            return True
        if isinstance(property_schema, dict):
            raw_description = property_schema.get("description")
            property_description = normalize_text(
                raw_description if isinstance(raw_description, str) else None
            )
            if any(marker in property_description for marker in SCOPE_HINTS):
                return True

    return False


def looks_like_inputful_tool(name: str, description: str | None) -> bool:
    """Return whether the tool name or description implies free-form input."""
    normalized_name = normalize_text(name)
    normalized_description = normalize_text(description)
    return any(marker in normalized_name for marker in INPUTFUL_TOOL_MARKERS) or any(
        marker in normalized_description for marker in INPUTFUL_TOOL_MARKERS
    )
