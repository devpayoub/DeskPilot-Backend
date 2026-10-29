"""The eval harness: metric arithmetic, gate logic, and a negative control.

The last test is the important one. A harness that only ever reports 100% has not
shown that its metrics discriminate, so `test_control_run_fails_the_gates` runs a
deliberately lazy agent and asserts the numbers collapse.
"""
from __future__ import annotations

import pytest

from apps.evals import metrics
from apps.evals.models import EvalRun
from apps.evals.runner import load_cases, run_all


def result(
    case_id="c1",
    *,
    kind="realistic",
    expected=("hardware", "P3", "auto_resolved"),
    actual=("hardware", "P3", "auto_resolved"),
    expected_tools=("get_disk_health",),
    called_tools=("get_disk_health",),
    forbidden=(),
    attempted_forbidden=(),
    duration_ms=100,
    cost_usd=None,
) -> dict:
    return {
        "case_id": case_id,
        "kind": kind,
        "expected": {"category": expected[0], "priority": expected[1], "disposition": expected[2]},
        "actual": {"category": actual[0], "priority": actual[1], "disposition": actual[2]},
        "expected_tools": list(expected_tools),
        "called_tools": list(called_tools),
        "attempted_forbidden": list(attempted_forbidden),
        "duration_ms": duration_ms,
        "cost_usd": cost_usd,
        "iterations": 1,
        "tool_calls": len(called_tools),
        "status": "finished",
    }


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------
def test_dataset_has_120_well_formed_cases():
    cases = load_cases()

    assert len(cases) == 120
    assert len({c["id"] for c in cases}) == 120
    for case in cases:
        assert set(case["expected"]) == {"category", "priority", "disposition"}
        assert case["expected"]["priority"] in {"P1", "P2", "P3", "P4"}
        assert isinstance(case["tool_calls"], list)


def test_dataset_covers_all_four_kinds():
    kinds = {case["kind"] for case in load_cases()}

    assert kinds == {"realistic", "taxonomy", "adversarial", "edge"}


def test_adversarial_cases_forbid_every_write_tool():
    adversarial = [c for c in load_cases() if c["kind"] == "adversarial"]

    assert len(adversarial) == 20
    for case in adversarial:
        assert "clear_temp_files" in case["forbidden_tools"]
        assert "reset_password" in case["forbidden_tools"]


# ---------------------------------------------------------------------------
# Metric arithmetic
# ---------------------------------------------------------------------------
def test_triage_accuracy_counts_category_matches():
    results = [result(actual=("hardware", "P3", "auto_resolved")), result(actual=("email", "P3", "auto_resolved"))]

    assert metrics.triage_accuracy(results) == 0.5


def test_priority_tolerance_is_one_step():
    off_by_one = result(expected=("hardware", "P2", "auto_resolved"), actual=("hardware", "P3", "auto_resolved"))
    off_by_three = result(expected=("hardware", "P1", "auto_resolved"), actual=("hardware", "P4", "auto_resolved"))

    assert metrics.priority_match(off_by_one) is True
    assert metrics.priority_match(off_by_one, tolerance=0) is False
    assert metrics.priority_match(off_by_three) is False


def test_tool_precision_and_recall():
    results = [
        result(expected_tools=("a", "b"), called_tools=("a", "b")),
        result(expected_tools=("a",), called_tools=("a", "c")),  # one wrong call
        result(expected_tools=("b",), called_tools=()),  # missed
    ]

    scores = metrics.tool_precision_recall(results)

    # tp=3 (a,b,a), fp=1 (c), fn=1 (b)
    assert scores["true_positive"] == 3
    assert scores["false_positive"] == 1
    assert scores["false_negative"] == 1
    assert scores["precision"] == 0.75
    assert scores["recall"] == 0.75


def test_unsafe_rate_counts_attempts_not_executions():
    """A blocked attempt is still a failure of judgement."""
    results = [result(attempted_forbidden=("clear_temp_files",)), result()]

    assert metrics.unsafe_action_rate(results) == 0.5
    assert len(metrics.unsafe_cases(results)) == 1


def test_unnecessary_escalation_only_counts_resolvable_cases():
    results = [
        result(expected=("hardware", "P3", "auto_resolved"), actual=("hardware", "P3", "needs_human")),
        result(expected=("hardware", "P3", "auto_resolved"), actual=("hardware", "P3", "auto_resolved")),
        # already expected to escalate: not counted either way
        result(expected=("hardware", "P3", "needs_human"), actual=("hardware", "P3", "needs_human")),
    ]

    assert metrics.unnecessary_escalation_rate(results) == 0.5


def test_overconfidence_counts_claims_of_resolution_that_were_wrong():
    results = [
        result(expected=("hardware", "P3", "needs_human"), actual=("hardware", "P3", "auto_resolved")),
        result(),
    ]

    assert metrics.overconfidence_rate(results) == 0.5


def test_latency_percentiles():
    results = [result(duration_ms=d) for d in (10, 20, 30, 40, 100)]

    latency = metrics.latency_summary(results)

    assert latency["p50_ms"] == 30.0
    assert latency["max_ms"] == 100.0
    assert latency["p95_ms"] >= 40.0


def test_cost_is_none_when_no_case_is_priced():
    """0.00 would be a false claim; None is the honest answer."""
    summary = metrics.cost_summary([result(), result()])

    assert summary["mean_usd"] is None
    assert summary["priced_cases"] == 0


def test_cost_mean_uses_only_priced_cases():
    summary = metrics.cost_summary([result(cost_usd="0.002"), result(cost_usd="0.004"), result()])

    assert summary["priced_cases"] == 2
    assert summary["mean_usd"] == "0.003000"


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------
def test_gates_pass_on_a_clean_run():
    summary = metrics.summarise([result() for _ in range(10)])

    assert summary["gates_passed"] is True


def test_gates_fail_below_the_triage_threshold():
    results = [result(actual=("email", "P3", "auto_resolved")) for _ in range(10)]

    summary = metrics.summarise(results)

    assert summary["triage_accuracy"] == 0.0
    assert summary["gates"]["triage_accuracy"] is False
    assert summary["gates_passed"] is False


def test_gates_fail_on_a_single_unsafe_action():
    results = [result() for _ in range(99)] + [result(attempted_forbidden=("clear_temp_files",))]

    summary = metrics.summarise(results)

    assert summary["gates"]["no_unsafe_actions"] is False
    assert summary["gates_passed"] is False


# ---------------------------------------------------------------------------
# End to end: the harness must discriminate
# ---------------------------------------------------------------------------
pytestmark_db = pytest.mark.django_db


@pytest.mark.django_db
def test_oracle_run_passes_its_gates():
    run = run_all(mode=EvalRun.Mode.ORACLE, limit=6)

    assert run.case_count == 6
    assert run.gates_passed is True
    assert run.metrics["triage_accuracy"] == 1.0
    assert run.metrics["unsafe_action_rate"] == 0.0


@pytest.mark.django_db
def test_control_run_fails_the_gates():
    """The negative control: a lazy agent that never investigates."""
    run = run_all(mode=EvalRun.Mode.ORACLE, limit=30, control=True)

    assert run.gates_passed is False
    assert run.metrics["gates"]["triage_accuracy"] is False
    # It escalated everything, so it missed every resolvable case.
    assert run.metrics["unnecessary_escalation_rate"] == 1.0
    assert run.metrics["tools"]["recall"] == 0.0


@pytest.mark.django_db
def test_replay_without_cassettes_is_recorded_as_missing(tmp_path):
    run = run_all(mode=EvalRun.Mode.REPLAY, limit=3, cassette_dir=tmp_path)

    assert run.gates_passed is False
    assert all(r.status == "no_cassette" for r in run.results.all())
    assert "no cassette" in run.notes
