"""The database-backed fake tenant, plus the identity tools on top of it."""
from __future__ import annotations

import pytest

from apps.directory.adapters import DatabaseDirectory
from apps.directory.models import DirectoryGroup, Employee
from apps.directory.vault import retrieve_password
from apps.agent.models import AgentRun
from apps.guardrails import approvals
from apps.guardrails.context import build_context
from apps.guardrails.models import ApprovalRequest
from apps.helpdesk.services import create_ticket
from tests.directory_contract import SAM, GROUP, DirectoryContract
from toolcore.errors import ToolDenied
from toolcore.execute import execute_tool
from toolcore.redaction import args_hash

pytestmark = pytest.mark.django_db


@pytest.fixture
def seeded():
    vpn, _ = DirectoryGroup.objects.get_or_create(name="VPN Users")
    admins, _ = DirectoryGroup.objects.get_or_create(
        name="Domain Admins", defaults={"is_privileged": True}
    )
    employee = Employee.objects.create(
        external_id="fake-j.doe",
        sam=SAM,
        upn="j.doe@deskpilot.test",
        display_name="Jane Doe",
        email="j.doe@deskpilot.test",
        department="Finance",
        title="Analyst",
        locked_out=True,
        bad_password_count=6,
    )
    employee.groups.set([vpn])
    return employee


@pytest.fixture
def directory(seeded) -> DatabaseDirectory:
    return DatabaseDirectory()


class TestDatabaseDirectory(DirectoryContract):
    """Runs the shared contract against the fake tenant."""

    def test_unlock_clears_the_lockout_and_the_counter(self, directory, seeded):
        assert seeded.locked_out is True

        result = directory.unlock_account(SAM, dry_run=False)

        seeded.refresh_from_db()
        assert result["unlocked"] is True
        assert seeded.locked_out is False
        assert seeded.bad_password_count == 0

    def test_unlock_dry_run_leaves_the_account_locked(self, directory, seeded):
        result = directory.unlock_account(SAM, dry_run=True)

        seeded.refresh_from_db()
        assert result["dry_run"] is True
        assert seeded.locked_out is True, "a dry run must not unlock anything"


# ---------------------------------------------------------------------------
# The identity tools, through the chokepoint
# ---------------------------------------------------------------------------
def test_lookup_user_tool_reports_the_account_state(desk_user, seeded):
    context = build_context(desk_user)

    result = execute_tool("lookup_user", {"query": SAM}, context)

    assert result["found"] is True
    assert result["user"]["locked_out"] is True
    assert GROUP in result["user"]["groups"]


def test_lookup_user_tool_handles_a_miss(desk_user, seeded):
    context = build_context(desk_user)

    result = execute_tool("lookup_user", {"query": "nobody.here"}, context)

    assert result["found"] is False
    assert result["user"] is None


def test_reset_password_never_returns_the_secret(technician_user, seeded):
    """The generated password must not appear anywhere the model can read."""
    context = build_context(
        technician_user,
        approval_token=args_hash({"sam": SAM, "force_change": True}),
    )

    result = execute_tool("reset_password", {"sam": SAM, "force_change": True}, context)

    assert "password" not in result
    assert "password_reference" in result

    # The secret is retrievable by a human, once.
    stored = retrieve_password(result["password_reference"])
    assert len(stored.reveal_password()) >= 16
    assert stored.sam == SAM
    # ...but the column itself must not hold it in the clear.
    assert SAM not in stored.password_ciphertext
    assert stored.password_ciphertext.startswith("gAAAAA"), "Fernet token expected"


def _context_with_approval_recorder(user):
    """Mirror what the agent runtime does: persist an approval when one is needed."""
    run = AgentRun.objects.create(
        ticket=create_ticket(subject="account issue", body="cannot sign in"),
        objective="o",
        status=AgentRun.Status.RUNNING,
    )
    context = build_context(
        user, on_approval_required=lambda approval: approvals.create_approval(run, approval)
    )
    return context, run


def test_reset_password_pauses_for_approval(technician_user, seeded):
    context, run = _context_with_approval_recorder(technician_user)

    with pytest.raises(Exception) as excinfo:
        execute_tool("reset_password", {"sam": SAM, "force_change": True}, context)

    assert "approval" in str(excinfo.value).lower()
    request = ApprovalRequest.objects.get(run=run)
    assert request.tool_name == "reset_password"
    assert request.risk_class == "WRITE_DESTRUCTIVE"
    assert request.dry_run_ok is True
    assert "password" not in (request.preview or {}), "a preview must not contain a secret"


def test_privileged_group_change_is_denied_at_the_tool_layer(technician_user, seeded):
    context = build_context(
        technician_user,
        approval_token=args_hash({"group": "Domain Admins", "sam": SAM}),
    )

    with pytest.raises(ToolDenied, match="privileged group"):
        execute_tool("add_group_member", {"group": "Domain Admins", "sam": SAM}, context)


def test_privileged_group_is_refused_before_any_approval_is_created(
    technician_user, seeded
):
    """No approval can authorise this, so no approver should ever be asked."""
    context, run = _context_with_approval_recorder(technician_user)

    with pytest.raises(ToolDenied, match="privileged group"):
        execute_tool("add_group_member", {"group": "Domain Admins", "sam": SAM}, context)

    assert ApprovalRequest.objects.filter(run=run).count() == 0


def test_a_requester_cannot_look_up_users(requester_user, seeded):
    context = build_context(requester_user)

    with pytest.raises(ToolDenied, match="may not call"):
        execute_tool("lookup_user", {"query": SAM}, context)


def test_group_membership_change_requires_approval(technician_user, seeded):
    context, run = _context_with_approval_recorder(technician_user)

    with pytest.raises(Exception):
        execute_tool("add_group_member", {"group": GROUP, "sam": SAM}, context)

    request = ApprovalRequest.objects.get(run=run)
    assert request.risk_class == "WRITE_REVERSIBLE"
    assert request.dry_run_ok is True
    assert request.preview["already_member"] is True
