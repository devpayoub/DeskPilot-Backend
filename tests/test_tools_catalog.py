"""The tool catalog: shape, risk classes, and argument wiring for all eight tools."""
from __future__ import annotations

import pytest

from apps.guardrails.context import build_context
from toolcore import registry
from toolcore.errors import ToolValidationError
from toolcore.execute import execute_tool
from toolcore.risk import RiskClass, WRITE_DESTRUCTIVE, WRITE_REVERSIBLE

pytestmark = pytest.mark.django_db

DIAGNOSTIC_TOOLS = {
    "get_system_health",
    "get_disk_health",
    "list_services",
    "read_event_log",
    "list_listening_ports",
    "test_connectivity",
    "get_installed_software",
    "get_windows_update_status",
}
IDENTITY_READ_TOOLS = {"lookup_user", "get_group_membership"}
WRITE_TOOLS = {
    "restart_service",
    "clear_temp_files",
    "flush_dns_cache",
    "unlock_account",
    "reset_password",
    "add_group_member",
    "remove_group_member",
}
EXPECTED = DIAGNOSTIC_TOOLS | IDENTITY_READ_TOOLS | WRITE_TOOLS


def test_catalog_contains_the_expected_tools():
    assert {tool.name for tool in registry.list_tools()} == EXPECTED


def test_every_diagnostic_tool_is_read_only():
    for name in DIAGNOSTIC_TOOLS:
        tool = registry.get_tool(name)
        assert tool.risk_class is RiskClass.READ, name
        assert tool.spec()["requires_approval"] is False, name


def test_identity_read_tools_are_read_only():
    for name in IDENTITY_READ_TOOLS:
        tool = registry.get_tool(name)
        assert tool.risk_class is RiskClass.READ, name
        assert tool.spec()["requires_approval"] is False, name


def test_write_tools_declare_their_risk():
    assert registry.get_tool("restart_service").risk_class is WRITE_REVERSIBLE
    assert registry.get_tool("clear_temp_files").risk_class is WRITE_DESTRUCTIVE
    assert registry.get_tool("flush_dns_cache").risk_class is WRITE_REVERSIBLE
    assert registry.get_tool("unlock_account").risk_class is WRITE_REVERSIBLE
    assert registry.get_tool("reset_password").risk_class is WRITE_DESTRUCTIVE
    assert registry.get_tool("add_group_member").risk_class is WRITE_REVERSIBLE
    assert registry.get_tool("remove_group_member").risk_class is WRITE_DESTRUCTIVE


def test_every_write_tool_requires_approval_except_the_harmless_one():
    for name in WRITE_TOOLS - {"flush_dns_cache"}:
        assert registry.get_tool(name).spec()["requires_approval"] is True, name
    # Gating a no-op action would only train people to approve without reading.
    assert registry.get_tool("flush_dns_cache").spec()["requires_approval"] is False


def test_every_write_tool_supports_dry_run():
    """An approver who cannot see what will change is not really approving."""
    for name in WRITE_TOOLS:
        assert registry.get_tool(name).spec()["dry_run_supported"] is True, name


def test_write_tools_are_never_open_to_requesters():
    """A requester must not be able to change anything, even with approval."""
    for name in WRITE_TOOLS:
        allowed = registry.get_tool(name).allowed_roles
        assert allowed is not None, name
        assert "REQUESTER" not in allowed, name
        assert "ADMIN" in allowed, name


def test_every_tool_declares_a_domain_and_description():
    for tool in registry.list_tools():
        assert tool.description.strip(), tool.name
        assert tool.domain, tool.name


def test_read_event_log_forwards_its_arguments(desk_user, adapters, fake_diagnostics):
    ctx = build_context(desk_user, adapters=adapters)

    execute_tool(
        "read_event_log",
        {"log": "application", "level": "warning", "hours": 6, "limit": 5},
        ctx,
    )

    assert fake_diagnostics.calls == [("read_event_log", ("application", "warning", 6, 5))]


def test_read_event_log_rejects_an_unknown_log(desk_user, adapters):
    ctx = build_context(desk_user, adapters=adapters)

    with pytest.raises(ToolValidationError):
        execute_tool("read_event_log", {"log": "syslog"}, ctx)


def test_read_event_log_rejects_an_out_of_range_window(desk_user, adapters):
    ctx = build_context(desk_user, adapters=adapters)

    with pytest.raises(ToolValidationError):
        execute_tool("read_event_log", {"hours": 999}, ctx)


def test_connectivity_requires_host_and_port(desk_user, adapters):
    ctx = build_context(desk_user, adapters=adapters)

    with pytest.raises(ToolValidationError):
        execute_tool("test_connectivity", {"host": "example.org"}, ctx)


def test_connectivity_rejects_an_out_of_range_port(desk_user, adapters):
    ctx = build_context(desk_user, adapters=adapters)

    with pytest.raises(ToolValidationError):
        execute_tool("test_connectivity", {"host": "example.org", "port": 70000}, ctx)


def test_connectivity_forwards_a_valid_call(desk_user, adapters, fake_diagnostics):
    ctx = build_context(desk_user, adapters=adapters)

    result = execute_tool(
        "test_connectivity", {"host": "intranet.example", "port": 443, "timeout": 2.5}, ctx
    )

    assert result["reachable"] is True
    assert fake_diagnostics.calls == [("connectivity", ("intranet.example", 443, 2.5))]


def test_installed_software_forwards_the_filter(desk_user, adapters, fake_diagnostics):
    ctx = build_context(desk_user, adapters=adapters)

    result = execute_tool("get_installed_software", {"name_contains": "7-Zip"}, ctx)

    assert result["count"] == 2
    assert fake_diagnostics.calls == [("installed_software", ("7-Zip",))]


def test_windows_update_status_reports_pending_count(desk_user, adapters):
    ctx = build_context(desk_user, adapters=adapters)

    result = execute_tool("get_windows_update_status", {}, ctx)

    assert result["pending_count"] == 3
    assert result["pending_reboot"] is False


def test_listening_ports_respects_the_loopback_flag(desk_user, adapters, fake_diagnostics):
    ctx = build_context(desk_user, adapters=adapters)

    execute_tool("list_listening_ports", {"include_loopback": True}, ctx)

    assert fake_diagnostics.calls == [("listening_ports", (True,))]


def test_no_arg_tools_reject_stray_arguments(desk_user, adapters):
    ctx = build_context(desk_user, adapters=adapters)

    with pytest.raises(ToolValidationError):
        execute_tool("get_windows_update_status", {"verbose": True}, ctx)
