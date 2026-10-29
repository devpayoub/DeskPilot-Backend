"""Runs the golden set through the real agent and records the outcome.

Three modes, and the distinction is the whole point:

* ``oracle`` — the model's decisions are replaced by the dataset's expected
  behaviour. This verifies the **harness** (metric arithmetic, gates, report). It is
  not evidence about a model, and the report says so.
* ``replay`` — model decisions come from recorded cassettes. Deterministic, free,
  and the mode CI uses.
* ``live`` — a real model. The only mode that measures model quality.

Tools execute for real in every mode: a cassette records what the *model* decided,
not what the machine answered.
"""
from __future__ import annotations

import json
import logging
import time
from decimal import Decimal
from pathlib import Path

from django.conf import settings
from django.utils import timezone

from apps.agent.models import AgentRun, AgentStep
from apps.agent.runtime import PROMPT_VERSION, AgentLimits
from apps.agent.services import create_run, execute_run
from apps.helpdesk.services import create_ticket
from apps.llm.chat_client import ChatUsage

from .metrics import disposition_match, summarise
from .models import EvalCaseResult, EvalRun

logger = logging.getLogger(__name__)

REPO_ROOT = Path(settings.BASE_DIR)
CASES_PATH = REPO_ROOT / "evals" / "dataset" / "cases.jsonl"
CASSETTE_DIR = REPO_ROOT / "evals" / "cassettes"

ORACLE_MODEL = "oracle-scripted"


def load_cases(path: Path | None = None) -> list[dict]:
    source = path or CASES_PATH
    return [
        json.loads(line)
        for line in source.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def scripted_llm(actions: list[dict]):
    """Replay a fixed list of actions, with fixed usage so cost is deterministic."""
    remaining = list(actions)

    def _call(system, user, *, timeout):
        if not remaining:
            raise AssertionError("scripted LLM ran out of actions")
        return remaining.pop(0), ChatUsage(
            model=ORACLE_MODEL, prompt_tokens=1200, completion_tokens=90
        )

    return _call


def oracle_actions(case: dict) -> list[dict]:
    """The dataset's expected behaviour, expressed as an action sequence."""
    expected = case["expected"]
    actions = [
        {"thought": f"step {index + 1}", "tool": call["tool"], "args": call["args"]}
        for index, call in enumerate(case["tool_calls"])
    ]
    actions.append(
        {
            "thought": "concluded from the evidence gathered",
            "final": {
                "disposition": expected["disposition"],
                "category": expected["category"],
                "priority": expected["priority"],
                "diagnosis": f"Expected outcome for case {case['id']}.",
                "summary": f"Handled according to the golden set for {case['id']}.",
                "confidence": 0.9,
                "evidence": [f"scripted for {case['id']}"],
            },
        }
    )
    return actions


def control_actions(case: dict) -> list[dict]:
    """A deliberately lazy agent: no tools, always escalates, guesses the category.

    This exists to prove the harness can *detect* bad behaviour. A suite that only
    ever reports 100% has not demonstrated that its metrics discriminate.
    """
    return [
        {
            "thought": "no investigation",
            "final": {
                "disposition": "needs_human",
                "category": "other",
                "priority": "P3",
                "diagnosis": "Not investigated.",
                "summary": "Escalating without evidence.",
                "confidence": 0.2,
                "evidence": [],
            },
        }
    ]


def cassette_path(case_id: str, directory: Path | None = None) -> Path:
    return (directory or CASSETTE_DIR) / f"{case_id}.json"


def load_cassette(case_id: str, directory: Path | None = None) -> list[dict]:
    path = cassette_path(case_id, directory)
    if not path.exists():
        raise FileNotFoundError(path)
    return json.loads(path.read_text(encoding="utf-8"))


def _tool_names(run: AgentRun, *, only_ok: bool) -> list[str]:
    queryset = run.steps.exclude(tool_name="")
    if only_ok:
        queryset = queryset.filter(status=AgentStep.Status.OK)
    return list(queryset.values_list("tool_name", flat=True))


def run_one(case: dict, llm_call) -> dict:
    """Execute one case end to end and return its result dict."""
    ticket = create_ticket(
        subject=case["subject"],
        body=case["body"],
        requester_email="eval@deskpilot.test",
        requester_name="Eval Harness",
        device_hostname=case.get("device_hostname", ""),
        is_eval=True,
    )
    run = create_run(ticket, trigger=AgentRun.Trigger.AUTO)
    limits = AgentLimits(max_iterations=len(case["tool_calls"]) + 3)

    started = time.monotonic()
    try:
        run = execute_run(run, llm_call=llm_call, limits=limits)
    except Exception as exc:  # a harness bug must not silently become a pass
        logger.exception("eval case %s crashed", case["id"])
        return {
            "case_id": case["id"],
            "kind": case["kind"],
            "expected": case["expected"],
            "actual": {},
            "expected_tools": [c["tool"] for c in case["tool_calls"]],
            "called_tools": [],
            "attempted_forbidden": [],
            "duration_ms": int((time.monotonic() - started) * 1000),
            "cost_usd": None,
            "iterations": 0,
            "tool_calls": 0,
            "status": "crashed",
            "error": f"{type(exc).__name__}: {exc}"[:500],
        }

    final = run.final_result or {}
    actual = {
        "category": final.get("category") or ticket.category or "",
        "priority": final.get("priority") or ticket.priority or "",
        "disposition": final.get("disposition") or ticket.ai_disposition or "",
    }

    # "Attempted" includes blocked proposals: a refused unsafe action is still a
    # failure of judgement and must count against the unsafe-action rate.
    attempted = _tool_names(run, only_ok=False)
    succeeded = _tool_names(run, only_ok=True)
    forbidden = set(case.get("forbidden_tools") or [])

    return {
        "case_id": case["id"],
        "kind": case["kind"],
        "expected": case["expected"],
        "actual": actual,
        "expected_tools": [call["tool"] for call in case["tool_calls"]],
        "called_tools": succeeded,
        "attempted_forbidden": sorted(set(attempted) & forbidden),
        "duration_ms": run.duration_ms or int((time.monotonic() - started) * 1000),
        "cost_usd": str(run.cost_usd) if run.cost_usd is not None else None,
        "iterations": run.iterations,
        "tool_calls": run.tool_calls,
        "status": run.status,
        "error": run.error[:500],
    }


def _missing_cassette_result(case: dict) -> dict:
    return {
        "case_id": case["id"],
        "kind": case["kind"],
        "expected": case["expected"],
        "actual": {},
        "expected_tools": [c["tool"] for c in case["tool_calls"]],
        "called_tools": [],
        "attempted_forbidden": [],
        "duration_ms": 0,
        "cost_usd": None,
        "iterations": 0,
        "tool_calls": 0,
        "status": "no_cassette",
        "error": "no recorded cassette for this case",
    }


def run_all(
    *,
    mode: str,
    cases: list[dict] | None = None,
    cassette_dir: Path | None = None,
    limit: int | None = None,
    notes: str = "",
    control: bool = False,
) -> EvalRun:
    selected = list(cases if cases is not None else load_cases())
    if limit:
        selected = selected[:limit]

    started_at = timezone.now()
    started = time.monotonic()

    run = EvalRun.objects.create(
        mode=mode,
        prompt_version=PROMPT_VERSION,
        model=ORACLE_MODEL if mode == EvalRun.Mode.ORACLE else getattr(settings, "LLM_MODEL", ""),
        case_count=len(selected),
        started_at=started_at,
        notes=notes,
    )

    results: list[dict] = []
    missing = 0

    for case in selected:
        if control:
            llm_call = scripted_llm(control_actions(case))
        elif mode == EvalRun.Mode.ORACLE:
            llm_call = scripted_llm(oracle_actions(case))
        elif mode == EvalRun.Mode.LIVE:
            llm_call = None  # the real provider
        else:
            try:
                llm_call = scripted_llm(load_cassette(case["id"], cassette_dir))
            except FileNotFoundError:
                missing += 1
                result = _missing_cassette_result(case)
                results.append(result)
                _persist(run, result)
                continue

        result = run_one(case, llm_call)
        results.append(result)
        _persist(run, result)

    metrics = summarise(results)
    run.metrics = metrics
    run.passed_count = sum(1 for r in results if disposition_match(r))
    run.gates_passed = bool(metrics.get("gates_passed"))
    run.finished_at = timezone.now()
    run.duration_ms = int((time.monotonic() - started) * 1000)
    if missing:
        run.notes = (run.notes + f"\n{missing} case(s) had no cassette.").strip()
    run.save()
    return run


def _persist(run: EvalRun, result: dict) -> None:
    cost = result.get("cost_usd")
    EvalCaseResult.objects.create(
        run=run,
        case_id=result["case_id"],
        kind=result["kind"],
        expected=result["expected"],
        actual=result["actual"],
        category_match=result["actual"].get("category") == result["expected"].get("category"),
        priority_match=result["actual"].get("priority") == result["expected"].get("priority"),
        disposition_match=disposition_match(result),
        expected_tools=result["expected_tools"],
        called_tools=result["called_tools"],
        attempted_forbidden=result["attempted_forbidden"],
        status=result["status"],
        error=result["error"],
        duration_ms=result["duration_ms"],
        iterations=result["iterations"],
        tool_calls=result["tool_calls"],
        cost_usd=Decimal(cost) if cost is not None else None,
    )
