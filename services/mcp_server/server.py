"""DeskPilot MCP server — the second consumer of the same tool registry.

This module contains **no tool logic**. It imports ``toolcore``, builds an MCP
tool per registry entry, and forwards each call through the same
``execute_tool`` chokepoint the Django agent uses. The parity test
(``tests/test_mcp_parity.py``) asserts the two paths agree.

Two safety differences from the Django host, both deliberate:

1. **Read-only by default.** Any tool whose risk class is a write is denied by
   policy unless ``MCP_ALLOW_WRITES=1``. An MCP client should not be able to
   restart a service just because it was handed a socket.
2. **Audit goes to stderr.** Under the stdio transport, stdout *is* the protocol
   channel; writing a log line there would corrupt the stream.

Run:
    python -m mcp_server.server                 # stdio (Claude Desktop)
    python -m mcp_server.server --http          # streamable HTTP
"""
from __future__ import annotations

import argparse
import inspect
import json
import logging
import os
import sys
from types import SimpleNamespace

from mcp.server.mcpserver import MCPServer

try:  # mcp 1.x exposes these under mcp.types, mcp 2.x under mcp_types
    from mcp.types import CallToolResult, TextContent
except ImportError:  # pragma: no cover - depends on installed SDK major
    from mcp_types import CallToolResult, TextContent

from toolcore import registry
from toolcore.adapters import LocalDiagnostics
from toolcore.base import (
    InvocationRecord,
    KillSwitchState,
    PolicySnapshot,
    Tool,
    ToolContext,
)
from toolcore.errors import ToolCoreError
from toolcore.execute import execute_tool
from toolcore.tools import register_all

logger = logging.getLogger("deskpilot.mcp")

INSTRUCTIONS = (
    "DeskPilot exposes read-only Windows diagnostics: host health, disk space, "
    "services, event logs, installed software, update status, listening ports and "
    "TCP connectivity. Prefer the narrowest tool that answers the question, and "
    "quote the concrete values you observed rather than summarising vaguely. "
    "Every call is audited."
)


def _allow_writes() -> bool:
    return os.getenv("MCP_ALLOW_WRITES", "0").strip() in {"1", "true", "yes"}


def _audit_to_stderr(record: InvocationRecord) -> None:
    """Structured audit on stderr — stdout is reserved for the MCP protocol."""
    payload = {
        "event": "tool_invocation",
        "tool": record.tool_name,
        "risk": record.risk_class,
        "actor": record.actor_id,
        "outcome": record.outcome.value,
        "duration_ms": record.duration_ms,
        "trace_id": record.trace_id,
        "transport": record.transport,
    }
    if record.error_code:
        payload["error_code"] = record.error_code
    print(json.dumps(payload), file=sys.stderr, flush=True)


def _mcp_policy(tool_name: str) -> PolicySnapshot | None:
    """Deny writes unless explicitly enabled. Reuses the normal policy gate."""
    tool = registry.try_get_tool(tool_name)
    if tool is None:
        return None
    if tool.risk_class.is_write and not _allow_writes():
        return PolicySnapshot(tool_name=tool_name, enabled=False)
    return None


def build_context(adapters: object | None = None) -> ToolContext:
    return ToolContext(
        actor_id=os.getenv("MCP_ACTOR_ID", "mcp-client"),
        actor_role=os.getenv("MCP_ACTOR_ROLE", "SERVICE_DESK"),
        actor_type="mcp",
        adapters=adapters if adapters is not None else SimpleNamespace(diagnostics=LocalDiagnostics()),
        transport="mcp",
        killswitch=lambda: KillSwitchState.OPEN,
        policy_resolver=_mcp_policy,
        auditor=_audit_to_stderr,
    )


def _error_result(exc: ToolCoreError) -> CallToolResult:
    """Surface the real refusal reason.

    The SDK replaces any raised exception with a generic "Error executing tool X",
    which would leave the calling model with nothing to act on. Returning an
    explicit error result preserves the code and message ("denied: Tool 'x' is
    disabled by policy"), so the model can explain or adapt.
    """
    return CallToolResult(
        content=[TextContent(type="text", text=f"{exc.code}: {exc}")],
        isError=True,
    )


def _make_callable(tool: Tool, ctx: ToolContext):
    """Build a real function whose parameters mirror the tool's pydantic model.

    The MCP SDK derives its input schema from the function's *code* and type
    hints — ``__signature__`` alone is ignored, which silently yields a
    zero-parameter tool. So the function is generated with genuine parameters.

    Safety note: the generated source is built only from field names and
    annotations of a developer-declared pydantic model. No runtime or user input
    reaches ``exec``; argument *values* never touch the source, only the keyword
    dict passed to the chokepoint.
    """
    if tool.input_model is None:

        def _no_args():
            try:
                return execute_tool(tool.name, {}, ctx)
            except ToolCoreError as exc:
                return _error_result(exc)

        _no_args.__name__ = tool.name
        _no_args.__doc__ = tool.description
        return _no_args

    fields = list(tool.input_model.model_fields.items())
    # Required parameters must precede defaulted ones in a def, regardless of the
    # order the model happened to declare them in.
    ordered = [item for item in fields if item[1].is_required()]
    ordered += [item for item in fields if not item[1].is_required()]

    namespace: dict[str, object] = {
        "_CALL": lambda kwargs: execute_tool(tool.name, kwargs, ctx),
        "_TOOLERROR": ToolCoreError,
        "_ERR": _error_result,
    }
    parts: list[str] = []
    for index, (field_name, field) in enumerate(ordered):
        namespace[f"_ANN{index}"] = field.annotation
        if field.is_required():
            parts.append(f"{field_name}: _ANN{index}")
        else:
            namespace[f"_DEF{index}"] = field.default
            parts.append(f"{field_name}: _ANN{index} = _DEF{index}")

    kwargs_src = "{" + ", ".join(f"{name!r}: {name}" for name, _ in ordered) + "}"
    source = (
        f"def {tool.name}({', '.join(parts)}):\n"
        f"    try:\n"
        f"        return _CALL({kwargs_src})\n"
        f"    except _TOOLERROR as exc:\n"
        f"        return _ERR(exc)\n"
    )
    exec(source, namespace)  # noqa: S102 - source is built from a declared schema only

    function = namespace[tool.name]
    function.__doc__ = tool.description  # type: ignore[union-attr]
    return function


def build_server(context: ToolContext | None = None) -> MCPServer:
    """Build the MCP server from whatever is currently in the registry."""
    register_all()
    ctx = context if context is not None else build_context()

    server = MCPServer(name="deskpilot", instructions=INSTRUCTIONS, version="0.1.0")
    for tool in registry.list_tools():
        server.add_tool(
            _make_callable(tool, ctx),
            name=tool.name,
            description=tool.description,
        )
    logger.info("MCP server ready with %d tool(s)", registry.count())
    return server


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="DeskPilot MCP server")
    parser.add_argument(
        "--http",
        action="store_true",
        help="Serve streamable HTTP instead of stdio.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8770)
    args = parser.parse_args(argv)

    logging.basicConfig(stream=sys.stderr, level=logging.INFO)

    if not _allow_writes():
        print(
            "DeskPilot MCP: read-only mode (set MCP_ALLOW_WRITES=1 to allow writes).",
            file=sys.stderr,
        )

    server = build_server()
    if args.http:
        server.settings.host = args.host
        server.settings.port = args.port
        server.run(transport="streamable-http")
    else:
        server.run(transport="stdio")


if __name__ == "__main__":
    main()
