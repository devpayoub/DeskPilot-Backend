"""Ticket and message models.

Two design notes worth defending:

* ``Ticket.number`` is null until the first save, then filled from the primary
  key. Generating a human-facing number from a sequence inside a transaction
  would serialise ticket creation for no benefit at this scale.
* ``ai_disposition`` is the field every auto-resolution claim is computed from.
  It is separate from ``status`` on purpose: an agent can *believe* it resolved
  something while a human has not yet closed it, and conflating the two is how
  auto-resolution rates get inflated.
"""
from __future__ import annotations

from django.conf import settings
from django.db import models


class Ticket(models.Model):
    class Status(models.TextChoices):
        NEW = "new", "New"
        IN_PROGRESS = "in_progress", "In progress"
        AWAITING_AGENT = "awaiting_agent", "Awaiting agent"
        AWAITING_USER = "awaiting_user", "Awaiting user"
        RESOLVED = "resolved", "Resolved"
        CLOSED = "closed", "Closed"

    class Priority(models.TextChoices):
        P1 = "P1", "P1 - Critical"
        P2 = "P2", "P2 - High"
        P3 = "P3", "P3 - Normal"
        P4 = "P4", "P4 - Low"

    class Category(models.TextChoices):
        HARDWARE = "hardware", "Hardware"
        SOFTWARE = "software", "Software"
        NETWORK = "network", "Network"
        ACCOUNT = "account", "Account"
        EMAIL = "email", "Email"
        PRINTER = "printer", "Printer"
        OTHER = "other", "Other"

    class Disposition(models.TextChoices):
        AUTO_RESOLVED = "auto_resolved", "Auto-resolved"
        NEEDS_HUMAN = "needs_human", "Needs human"
        NEEDS_INPUT = "needs_input", "Needs input"
        OUT_OF_SCOPE = "out_of_scope", "Out of scope"
        ESCALATED = "escalated", "Escalated"

    number = models.CharField(max_length=20, unique=True, null=True, blank=True)
    subject = models.CharField(max_length=255)
    body = models.TextField()
    requester_name = models.CharField(max_length=150, blank=True)
    requester_email = models.EmailField(blank=True)
    # Set only when a requester raises a ticket for themselves. Staff raising one
    # on someone's behalf leave it null — the person with the problem is not the
    # desk clerk. The self-approval guard needs this link to work at all: an email
    # string is free text and would fail open on a blank field.
    requester = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="raised_tickets",
        help_text="The account that raised this ticket, when it is not a desk user.",
    )
    device_hostname = models.CharField(
        max_length=120,
        blank=True,
        help_text="Host the ticket concerns. Used later for scope binding.",
    )
    # The account this ticket belongs to. Nullable only so rows written before
    # tenancy existed can be migrated; the API always sets it. PROTECT rather than
    # CASCADE because deleting a customer account should be a deliberate act, not a
    # side effect that silently takes their ticket history with it.
    organization = models.ForeignKey(
        "organizations.Organization",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="tickets",
        help_text="The account this ticket belongs to.",
    )

    # Eval runs create tickets through the same service as production. Without this
    # flag the harness would contaminate the very metrics the dashboard reports.
    is_eval = models.BooleanField(default=False, db_index=True)

    status = models.CharField(max_length=20, choices=Status.choices, default=Status.NEW)
    priority = models.CharField(max_length=2, choices=Priority.choices, default=Priority.P3)
    category = models.CharField(max_length=20, choices=Category.choices, blank=True)

    # Filled by the agent; never by a human directly.
    ai_disposition = models.CharField(max_length=20, choices=Disposition.choices, blank=True)
    ai_summary = models.TextField(blank=True)
    ai_diagnosis = models.TextField(blank=True)
    ai_confidence = models.FloatField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "-created_at"]),
            models.Index(fields=["ai_disposition", "-created_at"]),
            models.Index(fields=["organization", "-created_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.number or '(unsaved)'} {self.subject[:60]}"

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        if not self.number:
            self.number = f"T-{self.pk:06d}"
            super().save(update_fields=["number"])

    @property
    def latest_run(self):
        """The most recent agent run for this ticket, or None."""
        return self.agent_runs.order_by("-created_at").first()


class TicketMessage(models.Model):
    class AuthorType(models.TextChoices):
        REQUESTER = "requester", "Requester"
        AGENT = "agent", "Agent"
        HUMAN = "human", "Human agent"
        TOOL = "tool", "Tool"

    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name="messages")
    author_type = models.CharField(max_length=20, choices=AuthorType.choices)
    author_name = models.CharField(max_length=150, blank=True)
    body = models.TextField()
    is_internal = models.BooleanField(
        default=False, help_text="Internal notes are never shown to the requester."
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]
        indexes = [models.Index(fields=["ticket", "created_at"])]

    def __str__(self) -> str:
        return f"{self.author_type} on {self.ticket_id}: {self.body[:40]}"
