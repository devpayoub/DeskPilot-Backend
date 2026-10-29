"""The agent loop, driven by a scripted LLM.

Every test here supplies an explicit sequence of actions. No test inspects the
prompt text to decide what the fake model "does" — that style of mock is brittle
and obvious to a reviewer.
"""
from __future__ import annotations

from decimal import Decimal

import pytest

from apps.agent.models import AgentRun, AgentStep
from apps.agent.runtime import AgentBudgetExceeded, AgentLimits, run_agent
from apps.agent.services import build_objective, create_run, execute_run
from apps.guardrails.context import build_context
from apps.helpdesk.models import Ticket
from apps.helpdesk.services import create_ticket
from apps.llm.chat_client import ChatProviderError, ChatUsage
from apps.llm.models import ModelPrice
from toolcore import Tool, registry
from toolcore.risk import RiskClass

pytestmark = pytest.mark.django_db

MODEL = "test-model"


def scripted(actions: list[dict], *, model: str = MODEL, prompt_tokens: int = 100,
             completion_tokens: int = 20):
    """Return an llm_call that replays ``actions`` in order and records prompts."""
    remaining = list(actions)
    seen_prompts: list[str] = []

    def _call(system, user, *, timeout):
        seen_prompts.append(user)
        if not remaining:
            raise AssertionError("scripted LLM ran out of actions")
        return remaining.pop(0), ChatUsage(
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )

    _call.seen_prompts = seen_prompts
    return _call


FINAL = {
    "disposition": "auto_resolved",
    "category": "hardware",
    "priority": "P3",
    "diagnosis": "C: has only 4.2% free space.",
    "summary": "Clear temporary files to free space.",
    "confidence": 0.9,
    "evidence": ["C: free_percent=4.2"],
}


@pytest.fixture
def ticket() -> Ticket:
    return create_ticket(
        subject="Laptop is very slow",
        body="My laptop takes ten minutes to boot and everything freezes.",
        requester_email="user@example.com",
        requester_name="Sam User",
        device_hostname="DESK-01",
    )


@pytest.fixture
def agent_ctx(adapters):
    return build_context(
        None,
        adapters=adapters,
        actor_type="agent",
        actor_id="agent:test",
        actor_role="TECHNICIAN",
    )


@pytest.fixture
def priced_model():
    return ModelPrice.objects.create(
        model=MODEL,
        input_usd_per_million=Decimal("1.00"),
        output_usd_per_million=Decimal("2.00"),
    )


# ---------------------------------------------------------------------------
# Objective rendering
# ---------------------------------------------------------------------------
def test_objective_fences_the_ticket_as_untrusted(ticket):
    objective = build_objective(ticket)

    assert objective.startswith("<ticket>")
    assert "SUBJECT: Laptop is very slow" in objective
    assert "HOST: DESK-01" in objective
    assert objective.rstrip().endswith(
        "Investigate it and decide the next action."
    )


def test_objective_includes_the_thread(ticket):
    from apps.helpdesk.services import add_message

    add_message(ticket, body="Still broken after a reboot.", author_type="requester")

    objective = build_objective(ticket)

    assert "THREAD:" in objective
    assert "Still broken after a reboot." in objective


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------
def test_agent_finishes_and_writes_the_result_to_the_ticket(ticket, agent_ctx, priced_model):
    run = create_run(ticket)
    llm = scripted(
        [
            {"thought": "check disk space first", "tool": "get_disk_health", "args": {}},
            {"thought": "cause is clear", "final": FINAL},
        ]
    )

    run = execute_run(run, llm_call=llm)

    assert run.status == AgentRun.Status.FINISHED
    assert run.iterations == 2
    assert run.tool_calls == 1
    assert run.final_result["disposition"] == "auto_resolved"

    # One step for the tool call; the final answer is the run result, not a step.
    assert run.steps.count() == 1
    step = run.steps.get()
    assert step.tool_name == "get_disk_health"
    assert step.tool_risk == "READ"
    assert step.status == AgentStep.Status.OK
    assert step.result["ok"] is True

    ticket.refresh_from_db()
    assert ticket.ai_disposition == Ticket.Disposition.AUTO_RESOLVED
    assert ticket.category == Ticket.Category.HARDWARE
    assert ticket.ai_confidence == pytest.approx(0.9)
    assert "4.2%" in ticket.ai_diagnosis


def test_agent_records_cost_from_the_price_table(ticket, agent_ctx, priced_model):
    run = create_run(ticket)
    llm = scripted([{"thought": "done", "final": FINAL}])

    run = execute_run(run, llm_call=llm)

    # 100 in @ $1/1M + 20 out @ $2/1M = 0.0001 + 0.00004
    assert run.cost_usd == Decimal("0.000140")
    assert run.prompt_tokens == 100
    assert run.completion_tokens == 20


def test_cost_is_null_when_the_model_has_no_price(ticket, agent_ctx):
    run = create_run(ticket)
    llm = scripted([{"thought": "done", "final": FINAL}], model="unpriced-model")

    run = execute_run(run, llm_call=llm)

    assert run.cost_usd is None, "an unknown price must not be reported as zero"


def test_the_second_prompt_contains_the_first_observation(ticket, agent_ctx, priced_model):
    run = create_run(ticket)
    llm = scripted(
        [
            {"thought": "check disk", "tool": "get_disk_health", "args": {}},
            {"thought": "done", "final": FINAL},
        ]
    )

    execute_run(run, llm_call=llm)

    assert len(llm.seen_prompts) == 2
    assert "<observation" in llm.seen_prompts[1]
    assert "get_disk_health" in llm.seen_prompts[1]


# ---------------------------------------------------------------------------
# Asking instead of guessing
# ---------------------------------------------------------------------------
def test_agent_can_ask_the_user_and_pause(ticket, agent_ctx, priced_model):
    run = create_run(ticket)
    llm = scripted([{"thought": "ambiguous", "ask": "Which machine is affected?"}])

    run = execute_run(run, llm_call=llm)

    assert run.status == AgentRun.Status.NEEDS_INPUT
    assert run.pending_question == "Which machine is affected?"
    ticket.refresh_from_db()
    assert ticket.status == Ticket.Status.AWAITING_USER
    assert ticket.ai_disposition == Ticket.Disposition.NEEDS_INPUT


# ---------------------------------------------------------------------------
# Budgets and refusals
# ---------------------------------------------------------------------------
def test_iteration_budget_stops_a_looping_agent(ticket, agent_ctx, priced_model):
    run = create_run(ticket)
    llm = scripted(
        [
            {"thought": "again", "tool": "get_system_health", "args": {"sample_seconds": 0}},
            {"thought": "again", "tool": "get_disk_health", "args": {}},
            {"thought": "again", "tool": "list_services", "args": {}},
        ]
    )

    run = execute_run(run, llm_call=llm, limits=AgentLimits(max_iterations=2))

    assert run.status == AgentRun.Status.FAILED
    assert "budget exceeded" in run.error
    # Steps taken before the stop are still recorded — a failed run is not a blank one.
    assert run.steps.count() >= 2


def test_a_repeated_action_is_refused_without_spending_the_budget(ticket, agent_ctx, priced_model):
    run = create_run(ticket)
    llm = scripted(
        [
            {"thought": "check", "tool": "get_disk_health", "args": {}},
            {"thought": "check again", "tool": "get_disk_health", "args": {}},
            {"thought": "done", "final": FINAL},
        ]
    )

    run = execute_run(run, llm_call=llm)

    refused = run.steps.filter(status=AgentStep.Status.REFUSED)
    assert refused.count() == 1
    assert "duplicate" in refused.get().result["error"]
    assert run.tool_calls == 1, "the refusal must not consume the tool-call budget"


def test_an_unknown_tool_becomes_an_error_step_and_the_loop_continues(
    ticket, agent_ctx, priced_model
):
    run = create_run(ticket)
    llm = scripted(
        [
            {"thought": "try something", "tool": "format_c_drive", "args": {}},
            {"thought": "done", "final": FINAL},
        ]
    )

    run = execute_run(run, llm_call=llm)

    assert run.status == AgentRun.Status.FINISHED
    error_step = run.steps.get(step_no=1)
    assert error_step.status == AgentStep.Status.ERROR
    assert error_step.error_code == "tool_not_found"


def test_invalid_arguments_are_reported_back_to_the_model(ticket, agent_ctx, priced_model):
    run = create_run(ticket)
    llm = scripted(
        [
            {"thought": "bad args", "tool": "read_event_log", "args": {"log": "syslog"}},
            {"thought": "done", "final": FINAL},
        ]
    )

    run = execute_run(run, llm_call=llm)

    step = run.steps.get(step_no=1)
    assert step.status == AgentStep.Status.ERROR
    assert step.error_code == "invalid_arguments"


# ---------------------------------------------------------------------------
# Approval pause (the M3 hook)
# ---------------------------------------------------------------------------
def test_a_write_pauses_the_run_instead_of_executing(ticket, agent_ctx, priced_model):
    ran: list[dict] = []
    registry.register(
        Tool(
            name="t_restart",
            description="",
            handler=lambda _ctx, args: ran.append(args) or {"restarted": True},
            risk_class=RiskClass.WRITE_REVERSIBLE,
        )
    )
    try:
        run = create_run(ticket)
        llm = scripted([{"thought": "restart it", "tool": "t_restart", "args": {}}])

        run = execute_run(run, llm_call=llm)

        assert run.status == AgentRun.Status.AWAITING_APPROVAL
        assert ran == [], "the write must not run before approval"
        step = run.steps.get()
        assert step.status == AgentStep.Status.REQUIRES_APPROVAL
        assert run.final_result["pending_tool"] == "t_restart"
    finally:
        registry.unregister("t_restart")


# ---------------------------------------------------------------------------
# Direct loop contract
# ---------------------------------------------------------------------------
def test_loop_raises_when_it_cannot_conclude(agent_ctx, priced_model):
    llm = scripted(
        [
            {"thought": "a", "tool": "get_disk_health", "args": {}},
            {"thought": "b", "tool": "get_system_health", "args": {"sample_seconds": 0}},
        ]
    )

    with pytest.raises(AgentBudgetExceeded):
        run_agent(
            objective="OBJECTIVE: test",
            ctx=agent_ctx,
            limits=AgentLimits(max_iterations=2),
            llm_call=llm,
        )


def test_a_provider_refusal_fails_fast_and_keeps_the_reason(ticket):
    """A 402 is not a loop bug, and the trace must say so.

    The previous behaviour retried it as a parse failure, then reported
    "budget exceeded" — sending you to look for an agent bug when the real
    problem was an unpaid provider account.
    """

    def refusing(system, user, *, timeout):
        raise ChatProviderError("Daily check-in required to use free models.")

    run = execute_run(create_run(ticket), llm_call=refusing)

    assert run.status == AgentRun.Status.FAILED
    assert "Daily check-in required" in run.error
    assert "budget" not in run.error.lower()
    # One persisted step is the evidence it was not retried. `run.iterations`
    # stays 0 here: the refusal escapes the loop before its bookkeeping runs, so
    # failed runs under-report iterations. Recorded as a known gap rather than
    # asserted away.
    assert run.steps.count() == 1, "a refusal must not be retried"

    step = run.steps.get(step_no=1)
    assert step.status == "error"
    assert step.error_code == "llm_error"
    assert "Daily check-in required" in str(step.result), "the trace must explain itself"
