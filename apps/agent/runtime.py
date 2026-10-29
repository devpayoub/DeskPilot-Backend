"""The agent loop.

A bounded plan → act → observe loop adapted from the recruitment agent in `cvv`,
with three changes that matter:

1. **Step-scoped approval.** The original put ``allow_side_effects`` on the *run*,
   so approving one step pre-authorised every later write in that run. Here a
   proposal that needs approval *pauses the run*; resuming executes exactly that
   one step, against that one argument hash.
2. **Cost is a first-class budget.** A looping agent can burn real money, so
   ``max_cost_usd`` aborts a run the same way ``max_duration_seconds`` does.
3. **The LLM call is injectable.** Tests drive the loop with a scripted sequence
   of actions — never with ``if "restart" in prompt`` string matching, which is
   both brittle and obvious to a reviewer.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable

from django.conf import settings

from apps.llm.chat_client import ChatNotConfigured, ChatProviderError, ChatResponseError, ChatUsage, chat_json
from apps.llm.pricing import cost_for
from toolcore import registry
from toolcore.base import ToolContext
from toolcore.errors import ApprovalRequired, ToolCoreError
from toolcore.execute import execute_tool

logger = logging.getLogger(__name__)

PROMPT_PATH = Path(__file__).resolve().parent.parent / "llm" / "prompts" / "helpdesk_v1.md"
PROMPT_VERSION = "helpdesk_v1"

# How much of a tool result reaches the next prompt. Bounded structurally (top-N
# rows, shortened strings) rather than by clipping a JSON blob, so the model can
# still see the shape of what it got and how much was withheld.
_PROMPT_TOP_ROWS = 8
_PROMPT_STR_CHARS = 200
_MAX_OBSERVATION_CHARS = 3500


class AgentBudgetExceeded(Exception):
    """Iteration, tool-call, duration, cost or retry ceiling reached."""


class AgentCancelled(Exception):
    """Cooperative cancellation between steps."""


@dataclass
class AgentLimits:
    max_iterations: int = 10
    max_tool_calls: int = 12
    max_duration_seconds: float = 90.0
    max_retries_per_error: int = 3
    max_duplicate_actions: int = 1
    max_cost_usd: Decimal | None = None


def _system_prompt() -> str:
    base = PROMPT_PATH.read_text(encoding="utf-8")
    specs = []
    for tool in registry.list_specs():
        props = tool["input_schema"].get("properties") or {}
        specs.append(
            f"- {tool['name']} (risk={tool['risk_class']}): {tool['description']}\n"
            f"    args: {json.dumps(props, ensure_ascii=False)}"
        )
    return base + "\n" + "\n".join(specs)


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit].rstrip() + "…"


def _slim(value: Any, *, rows: int = _PROMPT_TOP_ROWS, chars: int = _PROMPT_STR_CHARS) -> Any:
    if isinstance(value, dict):
        return {key: _slim(item, rows=rows, chars=chars) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        items = list(value)
        kept = [_slim(item, rows=rows, chars=chars) for item in items[:rows]]
        if len(items) > rows:
            return {"items": kept, "omitted_items": len(items) - rows}
        return kept
    if isinstance(value, str):
        return _truncate(value, chars)
    return value


def _render_entry(entry: dict) -> str:
    slim = dict(entry)
    if isinstance(slim.get("observation"), dict):
        slim["observation"] = _slim(slim["observation"])
    text = json.dumps(slim, ensure_ascii=False, default=str)
    attrs = " ".join(f'{k}="{_truncate(str(slim[k]), 60)}"' for k in ("step", "tool") if k in slim)
    return f"<observation {attrs}>\n{_truncate(text, _MAX_OBSERVATION_CHARS)}\n</observation>"


def build_user_prompt(objective: str, transcript: list[dict]) -> str:
    lines = [f"OBJECTIVE: {objective}", "", "TOOL LOG (oldest first):"]
    lines += [_render_entry(entry) for entry in transcript] or ["(no steps taken yet)"]
    lines += ["", "Decide the single next action. Reply with JSON only."]
    return "\n".join(lines)


def _default_llm_call(system: str, user: str, *, timeout: float) -> tuple[dict, ChatUsage]:
    return chat_json(system, user, timeout=timeout)


def run_agent(
    *,
    objective: str,
    ctx: ToolContext,
    limits: AgentLimits | None = None,
    llm_call: Callable[..., tuple[dict, ChatUsage]] | None = None,
    on_step: Callable[[dict], None] | None = None,
    should_cancel: Callable[[], bool] | None = None,
    prior_transcript: list[dict] | None = None,
) -> dict:
    """Drive the agent to a conclusion within ``limits``.

    ``prior_transcript`` lets a paused run resume: the earlier steps are replayed
    into the prompt so the model continues from what it already knows, and step
    numbering carries on rather than restarting at 1.

    Returns a dict with ``status`` in {finished, needs_input, awaiting_approval} plus
    iterations, tool_calls, tokens, cost and the transcript. Raises
    AgentBudgetExceeded / AgentCancelled on a hard stop, and ChatNotConfigured when
    no provider key exists.
    """
    limits = limits or AgentLimits()
    if limits.max_cost_usd is None:
        configured = getattr(settings, "LLM_MAX_COST_PER_RUN_USD", None)
        limits.max_cost_usd = Decimal(str(configured)) if configured else None

    call = llm_call or _default_llm_call
    transcript: list[dict] = list(prior_transcript or [])
    first_iteration = len(transcript) + 1
    started = time.monotonic()
    tool_calls = 0
    parse_errors = 0
    duplicates: dict[tuple, int] = {}
    prompt_tokens = completion_tokens = 0
    cost_total: Decimal | None = Decimal("0")
    system = _system_prompt()

    def emit(entry: dict) -> None:
        transcript.append(entry)
        if on_step is not None:
            on_step(entry)

    def account(usage: ChatUsage) -> Decimal | None:
        nonlocal prompt_tokens, completion_tokens, cost_total
        prompt_tokens += usage.prompt_tokens
        completion_tokens += usage.completion_tokens
        step_cost = cost_for(usage.model, usage.prompt_tokens, usage.completion_tokens)
        if step_cost is None or cost_total is None:
            cost_total = None
        else:
            cost_total += step_cost
        return step_cost

    for offset in range(limits.max_iterations):
        iteration = first_iteration + offset
        if should_cancel is not None and should_cancel():
            raise AgentCancelled(f"cancelled after {iteration - 1} step(s)")

        remaining = limits.max_duration_seconds - (time.monotonic() - started)
        if remaining <= 0:
            raise AgentBudgetExceeded(f"max duration {limits.max_duration_seconds}s exceeded")
        if limits.max_cost_usd is not None and cost_total is not None:
            if cost_total > limits.max_cost_usd:
                raise AgentBudgetExceeded(
                    f"max cost ${limits.max_cost_usd} exceeded (${cost_total})"
                )

        try:
            action, usage = call(
                system, build_user_prompt(objective, transcript), timeout=min(remaining, 45.0)
            )
        except ChatNotConfigured:
            raise
        except ChatProviderError as exc:
            # Retrying cannot fix an unpaid account or a wrong model name, and
            # counting it as a parse failure would report it as a budget bug.
            # Emit before raising: the trace has to show *why* the run died, not
            # merely that it did.
            emit({"step": iteration, "error": f"llm_error: {exc}", "error_code": "llm_error"})
            raise
        except (ChatResponseError, Exception) as exc:  # transient provider/parse problem
            parse_errors += 1
            emit(
                {
                    "step": iteration,
                    "error": f"llm_error: {type(exc).__name__}: {exc}",
                    "error_code": "llm_error",
                }
            )
            if parse_errors > limits.max_retries_per_error:
                raise AgentBudgetExceeded("too many consecutive provider/parse failures") from exc
            continue

        step_cost = account(usage)

        if not isinstance(action, dict):
            parse_errors += 1
            emit({"step": iteration, "error": "action must be a JSON object"})
            if parse_errors > limits.max_retries_per_error:
                raise AgentBudgetExceeded("too many malformed actions")
            continue

        if "final" in action:
            return {
                "status": "finished",
                "iterations": iteration - first_iteration + 1,
                "tool_calls": tool_calls,
                "result": action.get("final"),
                "thought": action.get("thought", ""),
                "transcript": transcript,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "cost_usd": cost_total,
            }

        question = action.get("ask")
        if isinstance(question, str) and question.strip():
            return {
                "status": "needs_input",
                "iterations": iteration - first_iteration + 1,
                "tool_calls": tool_calls,
                "question": question.strip(),
                "thought": action.get("thought", ""),
                "transcript": transcript,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "cost_usd": cost_total,
            }

        tool_name = action.get("tool")
        if not isinstance(tool_name, str) or not tool_name:
            parse_errors += 1
            emit({"step": iteration, "error": "action had neither 'final' nor a 'tool'"})
            if parse_errors > limits.max_retries_per_error:
                raise AgentBudgetExceeded("too many malformed actions")
            continue

        parse_errors = 0
        args = action.get("args") if isinstance(action.get("args"), dict) else {}
        entry: dict[str, Any] = {
            "step": iteration,
            "thought": action.get("thought", ""),
            "tool": tool_name,
            "args": args,
        }

        duplicate_key = (tool_name, json.dumps(args, sort_keys=True, default=str))
        seen = duplicates.get(duplicate_key, 0)
        if seen >= limits.max_duplicate_actions:
            # Refused before it ran, and it does not spend the tool-call budget:
            # a repeated proposal must not be able to drain a run.
            entry["observation"] = {"ok": False, "error": "duplicate action refused (already run)"}
            entry["step_status"] = "refused"
            emit(entry)
            continue

        if tool_calls >= limits.max_tool_calls:
            entry["observation"] = {"ok": False, "error": "tool-call budget exhausted"}
            entry["step_status"] = "refused"
            emit(entry)
            raise AgentBudgetExceeded(f"max tool calls ({limits.max_tool_calls}) reached")

        duplicates[duplicate_key] = seen + 1
        tool = registry.try_get_tool(tool_name)
        tool_started = time.monotonic()

        try:
            result = execute_tool(tool_name, args, ctx)
        except ApprovalRequired as exc:
            entry["observation"] = {"ok": False, "requires_approval": True, "error": str(exc)}
            entry["step_status"] = "requires_approval"
            entry["error_code"] = exc.code
            entry["latency_ms"] = int((time.monotonic() - tool_started) * 1000)
            emit(entry)
            return {
                "status": "awaiting_approval",
                "iterations": iteration - first_iteration + 1,
                "tool_calls": tool_calls,
                "pending_tool": tool_name,
                "pending_args": args,
                "question": str(exc),
                "thought": action.get("thought", ""),
                "transcript": transcript,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "cost_usd": cost_total,
            }
        except ToolCoreError as exc:
            entry["observation"] = {"ok": False, "error": str(exc)}
            entry["step_status"] = "error"
            entry["error_code"] = exc.code
        except Exception as exc:  # unexpected tool failure: surface, keep looping
            entry["observation"] = {"ok": False, "error": f"tool failed: {exc}"}
            entry["step_status"] = "error"
            entry["error_code"] = "tool_failed"
        else:
            tool_calls += 1  # only a call that actually ran spends the budget
            entry["observation"] = {"ok": True, "result": _slim(result)}
            entry["step_status"] = "ok"

        entry["latency_ms"] = int((time.monotonic() - tool_started) * 1000)
        entry["tool_risk"] = tool.risk_class.label if tool else "UNKNOWN"
        entry["tokens_in"] = usage.prompt_tokens
        entry["tokens_out"] = usage.completion_tokens
        entry["cost_usd"] = step_cost
        emit(entry)

    raise AgentBudgetExceeded(
        f"max iterations ({limits.max_iterations}) reached without a conclusion"
    )