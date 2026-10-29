"""The single chokepoint every tool call passes through.

Gate order matters. The kill switch is checked before the registry so a halted
system cannot even be probed; the risk class is resolved before the write check so
``paused`` only blocks writes; and the approval gate runs *after* argument
validation so the hash that gets frozen is the validated one.

Two deliberate fail-closed decisions:

* If the kill switch or the policy resolver raises, the call is **denied**. A
  guardrail that fails open is not a guardrail. The exception is logged.
* If the auditor raises, the call is **not** undone — the action already
  happened — but it is logged at ERROR so the gap is visible. Audit must never
  mask the real outcome, in either direction.
"""
from __future__ import annotations

import hmac
import logging
import time
from dataclasses import replace
from typing import Any, Mapping

from .base import (
    ApprovalContext,
    InvocationRecord,
    KillSwitchState,
    Outcome,
    PolicySnapshot,
    Tool,
    ToolContext,
)
from .errors import (
    ApprovalRequired,
    ToolCoreError,
    ToolDenied,
    ToolExecutionError,
    ToolNotFound,
    ToolValidationError,
)
from .redaction import args_hash, redact_args, redact_text
from .registry import get_tool
from .risk import RiskClass

logger = logging.getLogger(__name__)


def _build_preview(tool: Tool, ctx: ToolContext, validated: dict) -> tuple[Any, bool]:
    """Run the tool in dry-run mode to show a human what would change.

    Only tools that declare ``dry_run_supported`` are called; for the rest the
    preview is ``None`` and ``dry_run_ok`` is False, so the approval screen can
    say plainly that the approver is acting without a preview.
    """
    if not tool.dry_run_supported:
        return None, False
    try:
        preview = tool.handler(replace(ctx, dry_run=True), dict(validated))
        return preview, True
    except Exception as exc:  # a broken dry-run must not block the approval
        logger.warning("dry-run failed for tool=%s: %s", tool.name, exc)
        return {"error": f"dry-run failed: {type(exc).__name__}: {exc}"}, False


def _safe_killswitch(ctx: ToolContext) -> KillSwitchState:
    try:
        return ctx.killswitch()
    except Exception:
        logger.exception("kill switch read failed; failing closed (HALTED)")
        return KillSwitchState.HALTED


def _safe_policy(ctx: ToolContext, name: str) -> PolicySnapshot | None:
    try:
        return ctx.policy_resolver(name)
    except Exception as exc:
        logger.exception("policy lookup failed for tool=%s; failing closed", name)
        raise ToolDenied(f"Policy could not be resolved for '{name}'; refusing to run.") from exc


def _audit(ctx: ToolContext, record: InvocationRecord) -> None:
    try:
        ctx.auditor(record)
    except Exception:
        logger.exception(
            "AUDIT FAILED tool=%s outcome=%s trace=%s",
            record.tool_name,
            record.outcome.value,
            record.trace_id,
        )


def execute_tool(name: str, args: Mapping[str, Any] | None, ctx: ToolContext) -> Any:
    """Validate, authorize, gate and run one tool call. Audits exactly once."""
    started = time.monotonic()
    if args is None:
        raw_args: Any = {}
    elif isinstance(args, Mapping):
        raw_args = dict(args)
    else:
        # Not an object: leave it as-is so validation rejects it with a clear message.
        raw_args = args
    redacted = redact_args(raw_args)
    arg_hash = args_hash(raw_args)

    tool: Tool | None = None
    risk: RiskClass | None = None
    outcome = Outcome.ERROR
    error_code: str | None = None
    error_message: str | None = None

    try:
        # -- Gate 1: kill switch (halt denies before anything is looked up) ------
        state = _safe_killswitch(ctx)
        if state is KillSwitchState.HALTED:
            raise ToolDenied("All tool execution is halted by the kill switch.")

        # -- Gate 2: registry ---------------------------------------------------
        tool = get_tool(name)
        risk = tool.risk_class

        # -- Gate 3: policy -----------------------------------------------------
        policy = _safe_policy(ctx, name)
        allowed_roles = tool.allowed_roles
        if policy is not None:
            if not policy.enabled:
                raise ToolDenied(f"Tool '{name}' is disabled by policy.")
            if policy.risk_class is not None:
                risk = max(risk, policy.risk_class)  # policy may raise, never lower
            if policy.allowed_roles is not None:
                allowed_roles = policy.allowed_roles

        # -- Gate 1b: paused blocks writes only, so it needs the risk class ------
        if state is KillSwitchState.PAUSED and risk.is_write:
            raise ToolDenied("Write actions are paused by the kill switch.")

        # -- Gate 4: role authorization -----------------------------------------
        if allowed_roles is not None and ctx.actor_role not in allowed_roles:
            raise ToolDenied(
                f"Role '{ctx.actor_role or 'none'}' may not call '{name}'."
            )

        # -- Gate 5: schema validation ------------------------------------------
        validated = tool.validate(raw_args)

        # A guard refuses what no approval could authorise, before a human is asked.
        if tool.guard is not None:
            tool.guard(validated)

        # The approval is bound to the *validated* arguments, so approving one
        # argument set can never execute a different one (TOCTOU defence).
        validated_digest = args_hash(validated)

        # -- Gate 10: approval gate ---------------------------------------------
        needs_approval = tool.resolved_approval_required(risk)
        if policy is not None and policy.requires_approval is not None:
            needs_approval = policy.requires_approval

        if needs_approval:
            if not ctx.approval_token:
                preview, dry_run_ok = _build_preview(tool, ctx, validated)
                ctx.on_approval_required(
                    ApprovalContext(
                        tool_name=name,
                        risk_class=risk.label,
                        args_redacted=redact_args(validated),
                        args_hash=validated_digest,
                        rationale=tool.description,
                        preview=preview,
                        dry_run_ok=dry_run_ok,
                    )
                )
                raise ApprovalRequired(
                    f"Tool '{name}' changes state and requires human approval."
                )
            if not hmac.compare_digest(ctx.approval_token, validated_digest):
                raise ToolDenied(
                    "Approval token does not match these arguments; refusing to run."
                )

        # -- Guard: never "dry-run" a write by silently executing it -------------
        if ctx.dry_run and risk.is_write and not tool.dry_run_supported:
            raise ToolDenied(
                f"Tool '{name}' has no dry-run mode; refusing to execute it under a "
                "dry-run request."
            )

        # -- Gate 11: execute ----------------------------------------------------
        result = tool.handler(ctx, validated)
        outcome = Outcome.DRY_RUN if ctx.dry_run else Outcome.OK
        return result

    except ApprovalRequired as exc:
        outcome, error_code, error_message = Outcome.APPROVAL_REQUIRED, exc.code, str(exc)
        raise
    except ToolDenied as exc:
        outcome, error_code, error_message = Outcome.DENIED, exc.code, str(exc)
        raise
    except ToolNotFound as exc:
        outcome, error_code, error_message = Outcome.DENIED, exc.code, str(exc)
        raise
    except ToolValidationError as exc:
        outcome, error_code, error_message = Outcome.ERROR, exc.code, str(exc)
        raise
    except ToolCoreError as exc:
        outcome, error_code, error_message = Outcome.ERROR, exc.code, str(exc)
        raise
    except Exception as exc:
        outcome, error_code = Outcome.ERROR, "tool_failed"
        error_message = f"{type(exc).__name__}: {exc}"
        raise ToolExecutionError(
            f"Tool '{name}' raised unexpectedly: {type(exc).__name__}: {exc}"
        ) from exc
    finally:
        # RiskClass.READ is 0, so `or` chaining would silently fall through here.
        # Compare against None explicitly.
        effective_risk = risk if risk is not None else (tool.risk_class if tool is not None else None)
        _audit(
            ctx,
            InvocationRecord(
                tool_name=name,
                risk_class=effective_risk.label if effective_risk is not None else "UNKNOWN",
                actor_type=ctx.actor_type,
                actor_id=ctx.actor_id,
                outcome=outcome,
                args_hash=arg_hash,
                args_redacted=redacted,
                error_code=error_code,
                # Third-party text (adapter messages, SDK exceptions) can quote a
                # credential back at us. Scrub before it becomes a permanent row.
                error_message=redact_text(error_message),
                duration_ms=int((time.monotonic() - started) * 1000),
                trace_id=ctx.trace_id,
                transport=ctx.transport,
                dry_run=ctx.dry_run,
            ),
        )
