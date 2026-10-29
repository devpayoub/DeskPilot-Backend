"""Ticket operations. Kept in one place so the API, the agent and tests agree."""
from __future__ import annotations

from .models import Ticket, TicketMessage


def create_ticket(
    *,
    subject: str,
    body: str,
    requester_email: str = "",
    requester_name: str = "",
    requester=None,
    device_hostname: str = "",
    priority: str = Ticket.Priority.P3,
    is_eval: bool = False,
) -> Ticket:
    ticket = Ticket.objects.create(
        subject=subject,
        body=body,
        requester_email=requester_email,
        requester_name=requester_name,
        requester=requester,
        device_hostname=device_hostname,
        priority=priority,
        is_eval=is_eval,
    )
    TicketMessage.objects.create(
        ticket=ticket,
        author_type=TicketMessage.AuthorType.REQUESTER,
        author_name=requester_name,
        body=body,
    )
    return ticket


def add_message(
    ticket: Ticket,
    *,
    body: str,
    author_type: str = TicketMessage.AuthorType.HUMAN,
    author_name: str = "",
    is_internal: bool = False,
) -> TicketMessage:
    return TicketMessage.objects.create(
        ticket=ticket,
        author_type=author_type,
        author_name=author_name,
        body=body,
        is_internal=is_internal,
    )


def apply_agent_result(ticket: Ticket, final: dict, *, summary_key: str = "summary") -> Ticket:
    """Persist the agent's structured conclusion onto the ticket."""
    disposition = str(final.get("disposition") or "").strip()
    valid = {choice for choice, _ in Ticket.Disposition.choices}
    if disposition in valid:
        ticket.ai_disposition = disposition

    ticket.ai_summary = str(final.get(summary_key) or "")[:4000]
    ticket.ai_diagnosis = str(final.get("diagnosis") or "")[:4000]

    try:
        confidence = float(final.get("confidence"))
    except (TypeError, ValueError):
        confidence = None
    if confidence is not None:
        ticket.ai_confidence = min(max(confidence, 0.0), 1.0)

    category = str(final.get("category") or "").strip()
    if category in {choice for choice, _ in Ticket.Category.choices}:
        ticket.category = category

    priority = str(final.get("priority") or "").strip().upper()
    if priority in {choice for choice, _ in Ticket.Priority.choices}:
        ticket.priority = priority

    ticket.save(
        update_fields=[
            "ai_disposition",
            "ai_summary",
            "ai_diagnosis",
            "ai_confidence",
            "category",
            "priority",
            "updated_at",
        ]
    )
    return ticket
