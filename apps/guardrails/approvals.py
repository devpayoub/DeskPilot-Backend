"""Approval lifecycle: create, decide, expire, consume.

The single invariant everything here protects: **an approval authorises exactly one
execution of exactly one argument set.** Everything else — expiry, consumption,
the hash check in the chokepoint — exists to hold that line.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from toolcore.base import ApprovalContext
from toolcore.risk import RiskClass

from .models import ApprovalRequest

logger = logging.getLogger(__name__)

DEFAULT_TTL_MINUTES = 30


class SelfApprovalDenied(ValueError):
    """The ticket's own requester tried to authorise a destructive change."""


def assert_not_self_approval(record: ApprovalRequest, user) -> None:
    """Refuse a destructive change approved by the person who reported the problem.

    This is segregation of duties, not a role check: the approver may hold a valid
    role and still be the wrong person. Reversible changes are exempt, because
    requiring a second technician to restart the print spooler only teaches people
    to click approve without reading.

    The check lives here rather than in the HTTP view so that any caller — the API,
    a management command, a future Slack bot — inherits it.
    """
    if record.risk_class != RiskClass.WRITE_DESTRUCTIVE.label:
        return

    ticket = getattr(getattr(record, "run", None), "ticket", None)
    if ticket is None or not ticket.requester_id:
        return

    approver_id = getattr(user, "pk", None)
    if approver_id and ticket.requester_id == approver_id:
        raise SelfApprovalDenied(
            "You raised this ticket. A destructive change on your own ticket "
            "needs a different approver."
        )


def create_approval(
    run, approval: ApprovalContext, *, ttl_minutes: int = DEFAULT_TTL_MINUTES
) -> ApprovalRequest:
    payload = approval.args_redacted
    if not isinstance(payload, (dict, list)):
        payload = {"value": payload}

    record = ApprovalRequest.objects.create(
        run=run,
        tool_name=approval.tool_name,
        risk_class=approval.risk_class,
        args_redacted=payload,
        args_hash=approval.args_hash,
        rationale=(approval.rationale or "")[:2000],
        preview=approval.preview,
        dry_run_ok=approval.dry_run_ok,
        expires_at=timezone.now() + timedelta(minutes=ttl_minutes),
    )
    logger.info(
        "approval requested id=%s tool=%s risk=%s run=%s",
        record.pk,
        record.tool_name,
        record.risk_class,
        getattr(run, "pk", None),
    )
    return record


def approve(record: ApprovalRequest, user, note: str = "") -> ApprovalRequest:
    """Approve a pending request. Refuses an expired or already-decided one."""
    with transaction.atomic():
        locked = ApprovalRequest.objects.select_for_update().get(pk=record.pk)
        if locked.status == ApprovalRequest.Status.APPROVED:
            return locked  # idempotent: a double click is not an error
        if locked.status != ApprovalRequest.Status.PENDING:
            raise ValueError(f"Approval is {locked.status}, not pending.")
        if locked.is_expired:
            locked.status = ApprovalRequest.Status.EXPIRED
            locked.save(update_fields=["status"])
            raise ValueError("Approval has expired.")

        assert_not_self_approval(locked, user)

        locked.status = ApprovalRequest.Status.APPROVED
        locked.decided_by = user
        locked.decided_at = timezone.now()
        locked.decision_note = note[:2000]
        locked.save(update_fields=["status", "decided_by", "decided_at", "decision_note"])
        return locked


def reject(record: ApprovalRequest, user, note: str = "") -> ApprovalRequest:
    with transaction.atomic():
        locked = ApprovalRequest.objects.select_for_update().get(pk=record.pk)
        if locked.status == ApprovalRequest.Status.REJECTED:
            return locked
        if locked.status != ApprovalRequest.Status.PENDING:
            raise ValueError(f"Approval is {locked.status}, not pending.")

        locked.status = ApprovalRequest.Status.REJECTED
        locked.decided_by = user
        locked.decided_at = timezone.now()
        locked.decision_note = note[:2000]
        locked.save(update_fields=["status", "decided_by", "decided_at", "decision_note"])
        return locked


def expire_stale() -> int:
    """Mark every pending request past its deadline as expired. Returns the count."""
    return ApprovalRequest.objects.filter(
        status=ApprovalRequest.Status.PENDING, expires_at__lte=timezone.now()
    ).update(status=ApprovalRequest.Status.EXPIRED)


def consume(record: ApprovalRequest) -> str:
    """Atomically spend an approval and return its argument hash.

    Raises ValueError if the approval is not usable. The hash returned is what the
    chokepoint compares against the validated arguments, so a token lifted from one
    request cannot authorise a different call.
    """
    with transaction.atomic():
        locked = ApprovalRequest.objects.select_for_update().get(pk=record.pk)
        if locked.status == ApprovalRequest.Status.CONSUMED:
            raise ValueError("Approval has already been used.")
        if locked.status == ApprovalRequest.Status.EXPIRED or locked.is_expired:
            raise ValueError("Approval has expired.")
        if locked.status != ApprovalRequest.Status.APPROVED:
            raise ValueError(f"Approval is {locked.status}, not approved.")

        locked.status = ApprovalRequest.Status.CONSUMED
        locked.consumed_at = timezone.now()
        locked.save(update_fields=["status", "consumed_at"])
        return locked.args_hash
