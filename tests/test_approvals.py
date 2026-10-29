"""The approval flow: nothing runs before a human says so, and then exactly once."""
from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from apps.accounts.models import CustomUser, Role
from apps.agent.models import AgentRun, AgentStep
from apps.agent.services import create_run, execute_run, resume_run
from apps.agent.tasks import resume_agent_run
from apps.guardrails import approvals
from apps.guardrails.context import build_context
from apps.guardrails.models import ApprovalRequest
from apps.helpdesk.models import Ticket
from apps.helpdesk.services import create_ticket
from apps.llm.chat_client import ChatUsage
from toolcore.adapters.remediation import SimulatedHost
from toolcore.errors import ToolDenied
from toolcore.execute import execute_tool
from toolcore.redaction import args_hash

pytestmark = pytest.mark.django_db

CLEAR_ARGS = {"root": "user_temp", "max_gb": 1.0}

FINAL = {
    "disposition": "auto_resolved",
    "category": "hardware",
    "priority": "P3",
    "diagnosis": "Temp files filled the volume.",
    "summary": "Temporary files were cleared.",
    "confidence": 0.8,
}


def scripted(actions: list[dict]):
    remaining = list(actions)

    def _call(system, user, *, timeout):
        if not remaining:
            raise AssertionError("scripted LLM ran out of actions")
        return remaining.pop(0), ChatUsage(model="m", prompt_tokens=100, completion_tokens=20)

    return _call


@pytest.fixture
def ticket() -> Ticket:
    return create_ticket(subject="Disk full", body="Cannot save files.", device_hostname="DESK-01")


@pytest.fixture
def paused_run(ticket):
    """A run that proposed clear_temp_files and stopped at the approval gate."""
    run = create_run(ticket)
    run = execute_run(
        run,
        llm_call=scripted(
            [{"thought": "free space", "tool": "clear_temp_files", "args": CLEAR_ARGS}]
        ),
    )
    return run


# ---------------------------------------------------------------------------
# The gate itself
# ---------------------------------------------------------------------------
def test_proposing_a_write_creates_an_approval_and_runs_nothing(paused_run):
    assert paused_run.status == AgentRun.Status.AWAITING_APPROVAL

    request = ApprovalRequest.objects.get()
    assert request.status == ApprovalRequest.Status.PENDING
    assert request.tool_name == "clear_temp_files"
    assert request.risk_class == "WRITE_DESTRUCTIVE"
    assert request.step_no == 1

    step = paused_run.steps.get(step_no=1)
    assert step.status == AgentStep.Status.REQUIRES_APPROVAL
    assert step.result["requires_approval"] is True
    assert "bytes_removed" not in (step.result.get("result") or {})


def test_the_approval_is_bound_to_the_validated_arguments(paused_run):
    request = ApprovalRequest.objects.get()

    assert request.args_hash == args_hash(CLEAR_ARGS)
    assert request.args_redacted == CLEAR_ARGS


def test_the_approval_carries_a_dry_run_preview(paused_run):
    request = ApprovalRequest.objects.get()

    assert request.dry_run_ok is True
    assert request.preview["dry_run"] is True
    assert request.preview["bytes_removable"] > 0
    assert request.preview["simulated"] is True, "SAFE_MODE must be on by default"


def test_the_agent_runs_against_a_simulated_host_by_default():
    context = build_context(None, actor_role="TECHNICIAN")

    assert isinstance(context.adapters.remediation, SimulatedHost)


# ---------------------------------------------------------------------------
# Approve → execute exactly once
# ---------------------------------------------------------------------------
def test_approving_executes_the_step_and_continues_the_run(paused_run, technician_user):
    request = ApprovalRequest.objects.get()
    approvals.approve(request, technician_user, "looks safe")

    run = resume_run(
        paused_run,
        ApprovalRequest.objects.get(pk=request.pk),
        llm_call=scripted([{"thought": "done", "final": FINAL}]),
    )

    assert run.status == AgentRun.Status.FINISHED

    step = run.steps.get(step_no=1)
    assert step.status == AgentStep.Status.OK
    assert step.result["ok"] is True
    assert step.result["result"]["bytes_removed"] > 0

    request.refresh_from_db()
    assert request.status == ApprovalRequest.Status.CONSUMED
    assert request.decided_by == technician_user


def test_resuming_counts_the_approved_step_as_a_tool_call(paused_run, technician_user):
    """The paused step never charged the loop's tool-call budget; resuming must."""
    request = ApprovalRequest.objects.get()
    approvals.approve(request, technician_user)

    run = resume_run(
        paused_run,
        ApprovalRequest.objects.get(pk=request.pk),
        llm_call=scripted([{"thought": "done", "final": FINAL}]),
    )

    assert run.tool_calls == 1
    assert run.iterations == 2  # the proposing step, then the concluding decision


def test_an_approval_cannot_be_used_twice(paused_run, technician_user):
    request = ApprovalRequest.objects.get()
    approvals.approve(request, technician_user)
    approvals.consume(request)

    with pytest.raises(ValueError, match="already been used"):
        approvals.consume(ApprovalRequest.objects.get(pk=request.pk))


def test_approving_twice_is_idempotent(paused_run, technician_user):
    request = ApprovalRequest.objects.get()

    first = approvals.approve(request, technician_user)
    second = approvals.approve(ApprovalRequest.objects.get(pk=request.pk), technician_user)

    assert first.status == second.status == ApprovalRequest.Status.APPROVED
    assert ApprovalRequest.objects.count() == 1


def test_rejecting_never_executes_and_ends_the_run(paused_run, technician_user):
    request = ApprovalRequest.objects.get()
    approvals.reject(request, technician_user, "do not delete anything")

    from apps.agent.services import reject_pending

    run = reject_pending(request.run, note="do not delete anything", actor="tech@deskpilot.test")

    assert run.status == AgentRun.Status.FAILED
    assert "rejected" in run.error

    step = run.steps.get(step_no=1)
    assert step.status == AgentStep.Status.REQUIRES_APPROVAL, "the step never executed"

    run.ticket.refresh_from_db()
    assert run.ticket.status == Ticket.Status.NEW


# ---------------------------------------------------------------------------
# Expiry and replay protection
# ---------------------------------------------------------------------------
def test_an_expired_approval_cannot_be_approved(paused_run, technician_user):
    request = ApprovalRequest.objects.get()
    ApprovalRequest.objects.filter(pk=request.pk).update(
        expires_at=timezone.now() - timedelta(minutes=1)
    )

    with pytest.raises(ValueError, match="expired"):
        approvals.approve(ApprovalRequest.objects.get(pk=request.pk), technician_user)


def test_an_expired_approval_cannot_be_consumed(paused_run, technician_user):
    request = ApprovalRequest.objects.get()
    approvals.approve(request, technician_user)
    ApprovalRequest.objects.filter(pk=request.pk).update(
        expires_at=timezone.now() - timedelta(minutes=1)
    )

    with pytest.raises(ValueError, match="expired"):
        approvals.consume(ApprovalRequest.objects.get(pk=request.pk))


def test_a_token_for_other_arguments_is_refused_by_the_chokepoint():
    """Approving one argument set must not authorise a different one (TOCTOU)."""
    token_for_different_args = args_hash({"root": "windows_temp", "max_gb": 1.0})
    context = build_context(None, actor_role="TECHNICIAN", approval_token=token_for_different_args)

    with pytest.raises(ToolDenied, match="does not match these arguments"):
        execute_tool("clear_temp_files", CLEAR_ARGS, context)


def test_a_token_for_the_same_arguments_is_accepted():
    context = build_context(
        None, actor_role="TECHNICIAN", approval_token=args_hash(CLEAR_ARGS)
    )

    result = execute_tool("clear_temp_files", CLEAR_ARGS, context)

    assert result["simulated"] is True


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
def test_pending_approvals_are_listed(admin_client, paused_run):
    response = admin_client.get("/api/v1/guardrails/approvals/")

    assert response.status_code == 200
    rows = response.json()["results"]
    assert len(rows) == 1
    assert rows[0]["tool_name"] == "clear_temp_files"
    assert rows[0]["dry_run_ok"] is True


def test_a_desk_user_cannot_approve_a_technician_only_tool(desk_client, paused_run):
    request = ApprovalRequest.objects.get()

    response = desk_client.post(
        f"/api/v1/guardrails/approvals/{request.pk}/approve/", {}, format="json"
    )

    assert response.status_code == 403
    request.refresh_from_db()
    assert request.status == ApprovalRequest.Status.PENDING


def test_an_admin_can_approve_and_the_resume_is_enqueued(
    admin_client, paused_run, monkeypatch, django_capture_on_commit_callbacks
):
    calls: list[tuple[int, int]] = []
    monkeypatch.setattr(
        resume_agent_run, "delay", lambda run_id, approval_id: calls.append((run_id, approval_id))
    )
    request = ApprovalRequest.objects.get()

    with django_capture_on_commit_callbacks(execute=True):
        response = admin_client.post(
            f"/api/v1/guardrails/approvals/{request.pk}/approve/",
            {"note": "approved in test"},
            format="json",
        )

    assert response.status_code == 200
    assert response.json()["status"] == "approved"
    assert response.json()["decision_note"] == "approved in test"
    assert calls == [(paused_run.pk, request.pk)]


def test_rejecting_via_the_api_marks_the_request(admin_client, paused_run):
    request = ApprovalRequest.objects.get()

    response = admin_client.post(
        f"/api/v1/guardrails/approvals/{request.pk}/reject/", {"note": "no"}, format="json"
    )

    assert response.status_code == 200
    assert response.json()["status"] == "rejected"
    paused_run.refresh_from_db()
    assert paused_run.status == AgentRun.Status.FAILED


# ---------------------------------------------------------------------------
# Segregation of duties: the person who reported it does not sign it off
# ---------------------------------------------------------------------------
def _paused_run_raised_by(user):
    """A destructive proposal on a ticket that ``user`` raised themselves."""
    ticket = create_ticket(
        subject="Disk full", body="Cannot save files.", requester=user
    )
    return execute_run(
        create_run(ticket),
        llm_call=scripted(
            [{"thought": "free space", "tool": "clear_temp_files", "args": CLEAR_ARGS}]
        ),
    )


def test_the_person_who_raised_a_ticket_cannot_approve_a_destructive_fix(
    technician_user,
):
    """A valid role is not the same thing as the right person."""
    run = _paused_run_raised_by(technician_user)
    request = ApprovalRequest.objects.get(run=run)

    with pytest.raises(approvals.SelfApprovalDenied):
        approvals.approve(request, technician_user)

    assert (
        ApprovalRequest.objects.get(pk=request.pk).status
        == ApprovalRequest.Status.PENDING
    ), "a refused self-approval must leave the request open for someone else"


def test_a_different_technician_can_approve_the_same_request(technician_user):
    run = _paused_run_raised_by(technician_user)
    request = ApprovalRequest.objects.get(run=run)
    other = CustomUser.objects.create_user(
        email="tech2@deskpilot.test", password="x", role=Role.TECHNICIAN
    )

    approvals.approve(request, other)

    assert ApprovalRequest.objects.get(pk=request.pk).decided_by_id == other.pk


def test_reversible_changes_are_exempt_from_the_self_approval_rule(technician_user):
    """Requiring a second pair of eyes to restart the spooler only trains clicking."""
    ticket = create_ticket(
        subject="Spooler down", body="Nothing prints.", requester=technician_user
    )
    record = ApprovalRequest.objects.create(
        run=create_run(ticket),
        tool_name="restart_service",
        risk_class="WRITE_REVERSIBLE",
        args_redacted={"name": "Spooler"},
        args_hash="deadbeef",
        expires_at=timezone.now() + timedelta(minutes=30),
    )

    approvals.approve(record, technician_user)

    assert (
        ApprovalRequest.objects.get(pk=record.pk).status
        == ApprovalRequest.Status.APPROVED
    )


def test_the_api_refuses_self_approval_with_403(technician_user, technician_client):
    run = _paused_run_raised_by(technician_user)
    request = ApprovalRequest.objects.get(run=run)

    response = technician_client.post(
        f"/api/v1/guardrails/approvals/{request.pk}/approve/", {}, format="json"
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "self_approval_denied"
