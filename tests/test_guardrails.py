"""The guardrail gates: policy, role authorization, kill switch, approval."""
from __future__ import annotations

import pytest

from apps.accounts.models import Role
from apps.guardrails import killswitch
from apps.guardrails.context import build_context
from apps.guardrails.models import ToolInvocation, ToolPolicy
from apps.guardrails.policy import invalidate_policy_cache, resolve_policy
from toolcore import Tool, registry
from toolcore.base import KillSwitchState
from toolcore.errors import ApprovalRequired, ToolDenied
from toolcore.execute import execute_tool
from toolcore.redaction import args_hash
from toolcore.risk import RiskClass

pytestmark = pytest.mark.django_db


@pytest.fixture
def write_tool():
    """A reversible write tool that records whether it actually ran."""
    calls: list[dict] = []

    def handler(_ctx, args):
        calls.append(args)
        return {"done": True}

    registry.register(
        Tool(
            name="t_write",
            description="",
            handler=handler,
            risk_class=RiskClass.WRITE_REVERSIBLE,
            dry_run_supported=False,
        )
    )
    yield calls
    registry.unregister("t_write")


@pytest.fixture
def technician_only_tool():
    registry.register(
        Tool(
            name="t_tech_only",
            description="",
            handler=lambda _ctx, _args: {"ok": True},
            allowed_roles=frozenset({Role.TECHNICIAN, Role.ADMIN}),
        )
    )
    yield
    registry.unregister("t_tech_only")


# ---------------------------------------------------------------------------
# Approval gate
# ---------------------------------------------------------------------------
def test_write_without_approval_is_refused_and_never_runs(desk_user, adapters, write_tool):
    ctx = build_context(desk_user, adapters=adapters)

    with pytest.raises(ApprovalRequired):
        execute_tool("t_write", {}, ctx)

    assert write_tool == [], "handler must not run before approval"
    row = ToolInvocation.objects.get(tool_name="t_write")
    assert row.outcome == "approval_required"
    assert row.risk_class == "WRITE_REVERSIBLE"


def test_approval_token_allows_the_write(desk_user, adapters, write_tool):
    ctx = build_context(desk_user, adapters=adapters, approval_token=args_hash({}))

    assert execute_tool("t_write", {}, ctx) == {"done": True}
    assert write_tool == [{}]
    assert ToolInvocation.objects.get(tool_name="t_write").outcome == "ok"


def test_dry_run_on_a_write_without_dry_run_support_is_denied(desk_user, adapters, write_tool):
    ctx = build_context(desk_user, adapters=adapters, dry_run=True, approval_token=args_hash({}))

    with pytest.raises(ToolDenied):
        execute_tool("t_write", {}, ctx)

    assert write_tool == [], "a dry-run must never execute a real write"


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------
def test_policy_can_disable_a_tool(desk_user, adapters):
    ToolPolicy.objects.create(tool_name="get_disk_health", enabled=False)
    ctx = build_context(desk_user, adapters=adapters)

    with pytest.raises(ToolDenied, match="disabled by policy"):
        execute_tool("get_disk_health", {}, ctx)


def test_policy_can_raise_risk_to_force_approval_on_a_read_tool(desk_user, adapters):
    ToolPolicy.objects.create(tool_name="get_disk_health", risk_class="WRITE_DESTRUCTIVE")
    ctx = build_context(desk_user, adapters=adapters)

    with pytest.raises(ApprovalRequired):
        execute_tool("get_disk_health", {}, ctx)


def test_policy_cannot_lower_declared_risk(desk_user, adapters, write_tool):
    """A policy row saying READ must not turn a write into an unapproved read."""
    ToolPolicy.objects.create(tool_name="t_write", risk_class="READ")
    ctx = build_context(desk_user, adapters=adapters)

    with pytest.raises(ApprovalRequired):
        execute_tool("t_write", {}, ctx)

    assert write_tool == []


def test_policy_cache_is_invalidated_on_demand(db):
    ToolPolicy.objects.create(tool_name="get_disk_health", enabled=True)
    assert resolve_policy("get_disk_health").enabled is True

    ToolPolicy.objects.filter(tool_name="get_disk_health").update(enabled=False)
    assert resolve_policy("get_disk_health").enabled is True, "should still be cached"

    invalidate_policy_cache("get_disk_health")
    assert resolve_policy("get_disk_health").enabled is False


# ---------------------------------------------------------------------------
# Role authorization
# ---------------------------------------------------------------------------
def test_role_below_the_allowlist_is_denied(requester_user, adapters, technician_only_tool):
    ctx = build_context(requester_user, adapters=adapters)

    with pytest.raises(ToolDenied, match="may not call"):
        execute_tool("t_tech_only", {}, ctx)


def test_role_on_the_allowlist_is_allowed(technician_user, adapters, technician_only_tool):
    ctx = build_context(technician_user, adapters=adapters)

    assert execute_tool("t_tech_only", {}, ctx) == {"ok": True}


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------
def test_halted_denies_even_reads(desk_user, adapters):
    killswitch.set_state(KillSwitchState.HALTED)
    ctx = build_context(desk_user, adapters=adapters)

    with pytest.raises(ToolDenied, match="halted"):
        execute_tool("get_system_health", {"sample_seconds": 0}, ctx)


def test_paused_allows_reads_but_denies_writes(desk_user, adapters, write_tool):
    killswitch.set_state(KillSwitchState.PAUSED)
    ctx = build_context(desk_user, adapters=adapters, approval_token=args_hash({}))

    assert execute_tool("get_disk_health", {}, ctx)["any_low_space"] is True

    with pytest.raises(ToolDenied, match="paused"):
        execute_tool("t_write", {}, ctx)
    assert write_tool == []


def test_kill_switch_defaults_to_open(db):
    assert killswitch.get_state() is KillSwitchState.OPEN


def test_unknown_kill_switch_value_fails_closed(db):
    from django.core.cache import cache

    cache.set(killswitch.CACHE_KEY, "banana")
    assert killswitch.get_state() is KillSwitchState.HALTED
