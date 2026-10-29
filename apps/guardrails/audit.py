"""Turns a toolcore InvocationRecord into a durable audit row.

Called from the chokepoint's ``finally`` block, so it runs for denials and
approval requests as well as successes. It never raises into the caller — the
chokepoint wraps it and logs at ERROR if it fails.
"""
from __future__ import annotations

from toolcore.base import InvocationRecord

from .models import ToolInvocation

_MAX_ERROR_CHARS = 2000


def record_invocation(record: InvocationRecord) -> ToolInvocation:
    payload = record.args_redacted
    if not isinstance(payload, (dict, list)):
        # args were not an object; keep the row valid JSON rather than losing it
        payload = {"value": payload}

    return ToolInvocation.objects.create(
        tool_name=record.tool_name[:120],
        risk_class=(record.risk_class or "UNKNOWN")[:20],
        actor_type=(record.actor_type or "agent")[:20],
        actor_id=str(record.actor_id or "")[:120],
        outcome=record.outcome.value,
        args_hash=record.args_hash[:64],
        args_redacted=payload,
        error_code=(record.error_code or "")[:60],
        error_message=(record.error_message or "")[:_MAX_ERROR_CHARS],
        duration_ms=max(0, int(record.duration_ms or 0)),
        trace_id=str(record.trace_id or "")[:64],
        transport=(record.transport or "internal")[:20],
        dry_run=bool(record.dry_run),
    )
