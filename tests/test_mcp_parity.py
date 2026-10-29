"""MCP parity: one registry, two consumers, provably the same behaviour.

This is the test behind the claim "the same tools, exposed over MCP". It asserts
three things: every registry tool is exposed, the input schemas agree, and a call
through MCP returns exactly what a direct ``execute_tool`` call returns.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from mcp_server.server import build_context, build_server
from toolcore import Tool, registry
from toolcore.execute import execute_tool
from toolcore.risk import RiskClass


@pytest.fixture(autouse=True)
def quiet_audit(monkeypatch):
    """The MCP auditor writes JSON to stderr; silence it so test output stays readable."""
    monkeypatch.setattr("mcp_server.server._audit_to_stderr", lambda record: None)


def _build(adapters):
    context = build_context(adapters=adapters)
    return context, build_server(context)


def _exposed(server) -> dict:
    return {tool.name: tool for tool in asyncio.run(server.list_tools())}


def test_every_registry_tool_is_exposed_over_mcp(adapters):
    _, server = _build(adapters)

    assert set(_exposed(server)) == {tool.name for tool in registry.list_tools()}


def test_schemas_match_the_internal_registry(adapters):
    _, server = _build(adapters)
    exposed = _exposed(server)

    mismatches = []
    for tool in registry.list_tools():
        spec = tool.spec()["input_schema"]
        mcp_schema = exposed[tool.name].input_schema or {}

        registry_props = set((spec.get("properties") or {}).keys())
        mcp_props = set((mcp_schema.get("properties") or {}).keys())
        registry_required = set(spec.get("required") or [])
        mcp_required = set(mcp_schema.get("required") or [])

        if registry_props != mcp_props or registry_required != mcp_required:
            mismatches.append(
                {
                    "tool": tool.name,
                    "registry_props": sorted(registry_props),
                    "mcp_props": sorted(mcp_props),
                    "registry_required": sorted(registry_required),
                    "mcp_required": sorted(mcp_required),
                }
            )

    assert not mismatches, mismatches


def test_enums_and_required_flags_survive_the_round_trip(adapters):
    _, server = _build(adapters)
    exposed = _exposed(server)

    events = exposed["read_event_log"].input_schema
    assert events["properties"]["log"]["enum"] == ["system", "application", "security"]
    assert events["properties"]["level"]["enum"] == [
        "all",
        "critical",
        "error",
        "warning",
        "information",
    ]

    connectivity = exposed["test_connectivity"].input_schema
    assert set(connectivity["required"]) == {"host", "port"}


@pytest.mark.parametrize(
    ("name", "args"),
    [
        ("get_system_health", {"sample_seconds": 0}),
        ("get_disk_health", {}),
        ("list_services", {"name_filter": None, "state": "all", "detail": False}),
        ("read_event_log", {"log": "system", "level": "error", "hours": 24, "limit": 20}),
        ("get_installed_software", {"name_contains": None}),
        ("get_windows_update_status", {}),
        ("list_listening_ports", {"include_loopback": False}),
        ("test_connectivity", {"host": "intranet.example", "port": 443, "timeout": 3.0}),
    ],
)
def test_both_paths_return_the_same_result(adapters, name, args):
    context, server = _build(adapters)

    direct = execute_tool(name, args, context)
    result = asyncio.run(server.call_tool(name, args, None))

    assert result.is_error is not True
    via_mcp = json.loads(result.content[0].text)
    assert via_mcp == direct


def test_mcp_denies_writes_by_default(adapters, monkeypatch):
    """A write tool must be refused over MCP unless writes are explicitly enabled."""
    monkeypatch.delenv("MCP_ALLOW_WRITES", raising=False)
    registry.register(
        Tool(
            name="t_mcp_write",
            description="",
            handler=lambda _ctx, _args: {"ran": True},
            risk_class=RiskClass.WRITE_REVERSIBLE,
        )
    )
    try:
        _, server = _build(adapters)
        result = asyncio.run(server.call_tool("t_mcp_write", {}, None))

        assert result.is_error is True
        # The refusal reason must reach the client, not be swallowed by the SDK.
        assert "disabled by policy" in result.content[0].text
    finally:
        registry.unregister("t_mcp_write")


def test_mcp_allows_writes_when_explicitly_enabled(adapters, monkeypatch):
    monkeypatch.setenv("MCP_ALLOW_WRITES", "1")
    registry.register(
        Tool(
            name="t_mcp_write_on",
            description="",
            handler=lambda _ctx, _args: {"ran": True},
            risk_class=RiskClass.WRITE_REVERSIBLE,
            approval_required=False,
        )
    )
    try:
        _, server = _build(adapters)
        result = asyncio.run(server.call_tool("t_mcp_write_on", {}, None))

        assert json.loads(result.content[0].text) == {"ran": True}
    finally:
        registry.unregister("t_mcp_write_on")
