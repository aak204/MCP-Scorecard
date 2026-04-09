"""Minimal stdio MCP transport for local tool discovery."""

from __future__ import annotations

import json
import subprocess
import threading
import time
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
from queue import Empty, Queue
from typing import TextIO, cast

from mcp_trust import __package_name__, __version__
from mcp_trust.models import JSONValue, NormalizedServer, NormalizedTool
from mcp_trust.transport import (
    ProtocolError,
    ServerStartupError,
    Transport,
    TransportTimeoutError,
)

MCP_PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS = (
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
)


@dataclass(slots=True, frozen=True)
class StdioServerConfig:
    """Configuration for launching a local MCP server over stdio."""

    command: tuple[str, ...]
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        normalized_command = tuple(part.strip() for part in self.command)
        if not normalized_command:
            raise ValueError("stdio command must not be empty.")
        if any(not part for part in normalized_command):
            raise ValueError("stdio command must not contain empty arguments.")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero.")

        object.__setattr__(self, "command", normalized_command)

    @classmethod
    def from_command(
        cls,
        command: Sequence[str],
        *,
        timeout_seconds: float = 10.0,
    ) -> StdioServerConfig:
        """Build a config from an arbitrary string sequence."""
        return cls(command=tuple(command), timeout_seconds=timeout_seconds)

    @property
    def target(self) -> str:
        """Return a deterministic target string used by normalized reports."""
        serialized_command = json.dumps(
            list(self.command),
            ensure_ascii=True,
            separators=(",", ":"),
        )
        return f"stdio:{serialized_command}"


@dataclass(slots=True)
class StdioTransport(Transport[StdioServerConfig]):
    """Launch a local MCP server over stdio and discover its tools."""

    transport_name: str = "stdio"
    protocol_version: str = MCP_PROTOCOL_VERSION

    def scan(self, target: StdioServerConfig) -> NormalizedServer:
        """Launch the server, negotiate MCP, and return normalized tools."""
        with _StdioSession(target, protocol_version=self.protocol_version) as session:
            initialize_result = session.initialize()
            tools = session.list_tools()

        return _normalize_server(target, initialize_result, tools)


class _StdioSession:
    """Single subprocess-backed MCP session used for discovery."""

    def __init__(self, config: StdioServerConfig, *, protocol_version: str) -> None:
        self._config = config
        self._protocol_version = protocol_version
        self._process: subprocess.Popen[str] | None = None
        self._stdout_queue: Queue[str | None] = Queue()
        self._stderr_lines: deque[str] = deque(maxlen=20)
        self._next_request_id = 1

    def __enter__(self) -> _StdioSession:
        try:
            self._process = subprocess.Popen(
                list(self._config.command),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                bufsize=1,
            )
        except OSError as exc:
            raise ServerStartupError(
                f"Failed to start stdio server command {self._config.command!r}: {exc}"
            ) from exc

        assert self._process.stdout is not None
        assert self._process.stderr is not None

        threading.Thread(
            target=self._pump_stdout,
            args=(self._process.stdout,),
            daemon=True,
        ).start()
        threading.Thread(
            target=self._pump_stderr,
            args=(self._process.stderr,),
            daemon=True,
        ).start()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        """Terminate the subprocess and release stdio resources."""
        process = self._process
        if process is None:
            return

        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()

        try:
            process.wait(timeout=0.2)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=0.5)

        self._process = None

    def initialize(self) -> dict[str, JSONValue]:
        """Perform the MCP initialization sequence."""
        result = self.request(
            "initialize",
            {
                "protocolVersion": self._protocol_version,
                "capabilities": {},
                "clientInfo": {
                    "name": __package_name__,
                    "version": __version__,
                },
            },
        )

        protocol_version = result.get("protocolVersion")
        if not isinstance(protocol_version, str):
            raise ProtocolError("initialize result.protocolVersion must be a string.")
        if protocol_version not in SUPPORTED_PROTOCOL_VERSIONS:
            raise ProtocolError(
                "Server responded with unsupported protocol version "
                f"{protocol_version!r}."
            )

        capabilities = result.get("capabilities")
        if not isinstance(capabilities, dict):
            raise ProtocolError("initialize result.capabilities must be an object.")
        if not isinstance(capabilities.get("tools"), dict):
            raise ProtocolError(
                "Server did not advertise tools capability during initialize."
            )

        server_info = result.get("serverInfo")
        if not isinstance(server_info, dict):
            raise ProtocolError("initialize result.serverInfo must be an object.")

        server_name = server_info.get("name")
        if not isinstance(server_name, str):
            raise ProtocolError("initialize result.serverInfo.name must be a string.")

        server_version = server_info.get("version")
        if server_version is not None and not isinstance(server_version, str):
            raise ProtocolError(
                "initialize result.serverInfo.version must be a string when present."
            )

        instructions = result.get("instructions")
        if instructions is not None and not isinstance(instructions, str):
            raise ProtocolError(
                "initialize result.instructions must be a string when present."
            )

        self.notify("notifications/initialized")
        return result

    def list_tools(self) -> tuple[NormalizedTool, ...]:
        """Fetch and normalize the full tools list, including pagination."""
        normalized_tools: list[NormalizedTool] = []
        seen_cursors: set[str] = set()
        next_cursor: str | None = None

        while True:
            params: dict[str, JSONValue] | None = None
            if next_cursor is not None:
                params = {"cursor": next_cursor}

            result = self.request("tools/list", params)
            raw_tools = result.get("tools")
            if not isinstance(raw_tools, list):
                raise ProtocolError("tools/list result.tools must be a list.")

            normalized_tools.extend(_normalize_tool(tool_payload) for tool_payload in raw_tools)

            raw_next_cursor = result.get("nextCursor")
            if raw_next_cursor is None:
                return tuple(normalized_tools)
            if not isinstance(raw_next_cursor, str) or not raw_next_cursor.strip():
                raise ProtocolError(
                    "tools/list result.nextCursor must be a non-empty string when present."
                )
            if raw_next_cursor in seen_cursors:
                raise ProtocolError(
                    f"tools/list returned repeated cursor {raw_next_cursor!r}."
                )

            seen_cursors.add(raw_next_cursor)
            next_cursor = raw_next_cursor

    def request(
        self,
        method: str,
        params: dict[str, JSONValue] | None = None,
    ) -> dict[str, JSONValue]:
        """Send one JSON-RPC request and wait for its matching response."""
        request_id = self._next_request_id
        self._next_request_id += 1

        payload: dict[str, JSONValue] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
        }
        if params is not None:
            payload["params"] = params

        self._send_message(payload)
        response = self._read_response(request_id, request_method=method)

        error = response.get("error")
        if error is not None:
            raise ProtocolError(
                f"Server returned JSON-RPC error for {method}: {self._format_error(error)}"
                f"{self._stderr_tail()}"
            )

        result = response.get("result")
        if not isinstance(result, dict):
            raise ProtocolError(f"{method} result must be an object.{self._stderr_tail()}")
        return result

    def notify(
        self,
        method: str,
        params: dict[str, JSONValue] | None = None,
    ) -> None:
        """Send one JSON-RPC notification."""
        payload: dict[str, JSONValue] = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params is not None:
            payload["params"] = params
        self._send_message(payload)

    def _send_message(self, message: dict[str, JSONValue]) -> None:
        """Serialize and send one newline-delimited JSON-RPC message."""
        process = self._require_process()
        if process.stdin is None or process.stdin.closed:
            raise ServerStartupError(
                "Cannot write to stdio server because stdin is not available."
            )

        serialized = json.dumps(message, ensure_ascii=True, separators=(",", ":"))
        try:
            process.stdin.write(serialized)
            process.stdin.write("\n")
            process.stdin.flush()
        except OSError as exc:
            raise ServerStartupError(
                f"Failed to write to stdio server {self._config.command!r}: {exc}"
            ) from exc

    def _read_response(self, request_id: int, *, request_method: str) -> dict[str, JSONValue]:
        """Read messages until the matching response for ``request_id`` arrives."""
        deadline = time.monotonic() + self._config.timeout_seconds

        while True:
            message = self._read_message(deadline, request_method=request_method)
            method_value = message.get("method")

            if isinstance(method_value, str):
                message_id = message.get("id")
                if message_id is None:
                    continue
                if method_value == "ping":
                    self._send_message(
                        {
                            "jsonrpc": "2.0",
                            "id": message_id,
                            "result": {},
                        }
                    )
                    continue

                self._send_message(
                    {
                        "jsonrpc": "2.0",
                        "id": message_id,
                        "error": {
                            "code": -32601,
                            "message": (
                                "Client does not support server request method "
                                f"{method_value!r} during discovery."
                            ),
                        },
                    }
                )
                raise ProtocolError(
                    f"Server sent unsupported request {method_value!r} during discovery."
                    f"{self._stderr_tail()}"
                )

            if message.get("id") != request_id:
                raise ProtocolError(
                    "Received unexpected response id "
                    f"{message.get('id')!r} while waiting for {request_method}."
                    f"{self._stderr_tail()}"
                )

            return message

    def _read_message(self, deadline: float, *, request_method: str) -> dict[str, JSONValue]:
        """Read one JSON-RPC message from stdout with timeout handling."""
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TransportTimeoutError(
                f"Timed out waiting for response to {request_method} after "
                f"{self._config.timeout_seconds:.1f}s.{self._stderr_tail()}"
            )

        try:
            raw_line = self._stdout_queue.get(timeout=remaining)
        except Empty as exc:
            raise TransportTimeoutError(
                f"Timed out waiting for response to {request_method} after "
                f"{self._config.timeout_seconds:.1f}s.{self._stderr_tail()}"
            ) from exc

        if raw_line is None:
            process = self._require_process()
            exit_code = process.poll()
            error_message = (
                f"Server exited with code {exit_code} while waiting for response to "
                f"{request_method}.{self._stderr_tail()}"
            )
            if request_method == "initialize":
                raise ServerStartupError(error_message)
            raise ProtocolError(error_message)

        stripped_line = raw_line.strip()
        if not stripped_line:
            return self._read_message(deadline, request_method=request_method)

        try:
            payload = json.loads(stripped_line)
        except json.JSONDecodeError as exc:
            raise ProtocolError(
                "Server wrote invalid JSON to stdout: "
                f"{stripped_line!r}.{self._stderr_tail()}"
            ) from exc

        if isinstance(payload, list):
            raise ProtocolError("JSON-RPC batch messages are not supported by this client.")
        if not isinstance(payload, dict):
            raise ProtocolError("Server message must be a JSON object.")
        return cast(dict[str, JSONValue], payload)

    def _pump_stdout(self, stream: TextIO) -> None:
        """Read stdout lines and hand them to the main thread."""
        try:
            for line in stream:
                self._stdout_queue.put(line)
        finally:
            self._stdout_queue.put(None)

    def _pump_stderr(self, stream: TextIO) -> None:
        """Capture recent stderr lines for diagnostics."""
        for line in stream:
            stripped = line.rstrip()
            if stripped:
                self._stderr_lines.append(stripped)

    def _format_error(self, error: JSONValue) -> str:
        """Return a readable summary for a JSON-RPC error payload."""
        if not isinstance(error, dict):
            return repr(error)

        code = error.get("code")
        message = error.get("message")
        if isinstance(code, int) and isinstance(message, str):
            return f"[{code}] {message}"
        return repr(error)

    def _stderr_tail(self) -> str:
        """Return a short stderr suffix for diagnostics."""
        if not self._stderr_lines:
            return ""
        return "\nStderr tail:\n" + "\n".join(self._stderr_lines)

    def _require_process(self) -> subprocess.Popen[str]:
        """Return the live subprocess object."""
        process = self._process
        if process is None:
            raise ServerStartupError("stdio server process is not running.")
        return process


def _normalize_server(
    config: StdioServerConfig,
    initialize_result: dict[str, JSONValue],
    tools: tuple[NormalizedTool, ...],
) -> NormalizedServer:
    """Convert initialize metadata and tools into the internal server model."""
    server_info = initialize_result["serverInfo"]
    capabilities = initialize_result["capabilities"]
    protocol_version = initialize_result["protocolVersion"]

    assert isinstance(server_info, dict)
    assert isinstance(capabilities, dict)
    assert isinstance(protocol_version, str)

    metadata: dict[str, JSONValue] = {
        "mcp": {
            "protocolVersion": protocol_version,
            "capabilities": capabilities,
            "transport": "stdio",
            "command": list(config.command),
        }
    }

    instructions = initialize_result.get("instructions")
    if isinstance(instructions, str):
        cast(dict[str, JSONValue], metadata["mcp"])["instructions"] = instructions

    raw_version = server_info.get("version")
    version = raw_version if isinstance(raw_version, str) else None

    return NormalizedServer(
        target=config.target,
        name=cast(str, server_info["name"]),
        version=version,
        tools=tools,
        metadata=metadata,
    )


def _normalize_tool(tool_payload: JSONValue) -> NormalizedTool:
    """Convert one MCP tool payload into the internal tool model."""
    if not isinstance(tool_payload, dict):
        raise ProtocolError("tools/list result.tools entries must be objects.")

    raw_name = tool_payload.get("name")
    if not isinstance(raw_name, str):
        raise ProtocolError("tool.name must be a string.")

    raw_description = tool_payload.get("description")
    if raw_description is not None and not isinstance(raw_description, str):
        raise ProtocolError(
            f"tool {raw_name!r} description must be a string when present."
        )

    raw_input_schema = tool_payload.get("inputSchema")
    if not isinstance(raw_input_schema, dict):
        raise ProtocolError(f"tool {raw_name!r} inputSchema must be an object.")

    metadata: dict[str, JSONValue] = {}

    raw_title = tool_payload.get("title")
    if raw_title is not None:
        if not isinstance(raw_title, str):
            raise ProtocolError(f"tool {raw_name!r} title must be a string when present.")
        metadata["title"] = raw_title

    raw_annotations = tool_payload.get("annotations")
    if raw_annotations is not None:
        if not isinstance(raw_annotations, dict):
            raise ProtocolError(
                f"tool {raw_name!r} annotations must be an object when present."
            )
        metadata["annotations"] = raw_annotations

    return NormalizedTool(
        name=raw_name,
        description=raw_description,
        input_schema=raw_input_schema,
        metadata=metadata,
    )
