"""The audit trail: exactly one row per attempt, including refusals.

These are the tests behind the CV claim "every tool call is audited".
"""
from __future__ import annotations

import json

import pytest
from pydantic import BaseModel, ConfigDict

from apps.guardrails.context import build_context
from apps.guardrails.models import ToolInvocation
from toolcore import Tool, registry
from toolcore.errors import ToolExecutionError, ToolNotFound, ToolValidationError
from toolcore.execute import execute_tool
from toolcore.redaction import args_hash
from toolcore.risk import RiskClass

pytestmark = pytest.mark.django_db


class _PasswordArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sam: str
    new_password: str


def test_successful_call_writes_exactly_one_audit_row(desk_user, adapters):
    ctx = build_context(desk_user, adapters=adapters)

    result = execute_tool("get_system_health", {"sample_seconds": 0}, ctx)

    assert result["hostname"] == "TEST-HOST"
    assert ToolInvocation.objects.count() == 1

    row = ToolInvocation.objects.get()
    assert row.tool_name == "get_system_health"
    assert row.outcome == "ok"
    assert row.risk_class == "READ"
    assert row.actor_type == "human"
    assert row.actor_id == str(desk_user.pk)
    assert row.trace_id == ctx.trace_id
    assert row.duration_ms >= 0
    assert row.args_hash == args_hash({"sample_seconds": 0})


def test_unknown_tool_records_one_denial(desk_user, adapters):
    ctx = build_context(desk_user, adapters=adapters)

    with pytest.raises(ToolNotFound):
        execute_tool("this_tool_does_not_exist", {}, ctx)

    assert ToolInvocation.objects.count() == 1
    row = ToolInvocation.objects.get()
    assert row.outcome == "denied"
    assert row.risk_class == "UNKNOWN"
    assert row.error_code == "tool_not_found"


def test_invalid_arguments_record_one_error_row(desk_user, adapters):
    ctx = build_context(desk_user, adapters=adapters)

    with pytest.raises(ToolValidationError):
        execute_tool("list_services", {"state": "exploded"}, ctx)

    row = ToolInvocation.objects.get()
    assert row.outcome == "error"
    assert row.risk_class == "READ"
    assert row.error_code == "invalid_arguments"


def test_unexpected_handler_exception_is_recorded_as_error(desk_user, adapters):
    def boom(_ctx, _args):
        raise RuntimeError("adapter exploded")

    registry.register(Tool(name="t_boom", description="", handler=boom))
    try:
        ctx = build_context(desk_user, adapters=adapters)
        with pytest.raises(ToolExecutionError):
            execute_tool("t_boom", {}, ctx)

        row = ToolInvocation.objects.get(tool_name="t_boom")
        assert row.outcome == "error"
        assert row.error_code == "tool_failed"
        assert "adapter exploded" in row.error_message
    finally:
        registry.unregister("t_boom")


def test_one_row_per_call_across_mixed_outcomes(desk_user, adapters):
    ctx = build_context(desk_user, adapters=adapters)

    execute_tool("get_disk_health", {}, ctx)
    execute_tool("list_services", {}, ctx)
    with pytest.raises(ToolNotFound):
        execute_tool("ghost", {}, ctx)

    assert ToolInvocation.objects.count() == 3
    assert ToolInvocation.objects.filter(outcome="ok").count() == 2
    assert ToolInvocation.objects.filter(outcome="denied").count() == 1


def test_sensitive_arguments_are_never_persisted(desk_user, adapters):
    registry.register(
        Tool(
            name="t_password",
            description="",
            handler=lambda _ctx, args: {"reset": True},
            input_model=_PasswordArgs,
            risk_class=RiskClass.WRITE_DESTRUCTIVE,
        )
    )
    try:
        ctx = build_context(desk_user, adapters=adapters, approval_token=args_hash({"sam": "a.trabelsi", "new_password": "hunter2"}))
        execute_tool("t_password", {"sam": "a.trabelsi", "new_password": "hunter2"}, ctx)

        row = ToolInvocation.objects.get(tool_name="t_password")
        assert row.args_redacted["sam"] == "a.trabelsi"
        assert row.args_redacted["new_password"] == "***"
        assert "hunter2" not in json.dumps(row.args_redacted)
    finally:
        registry.unregister("t_password")
