"""Guardrail persistence: per-tool policy and the append-only invocation audit.

``ToolInvocation`` is the table every CV claim about safety is derived from. It
records attempts, not just successes — a denied write is the evidence that the
guardrail worked, so it must be as durable as an executed one.
"""
from __future__ import annotations

from django.db import models

from toolcore.base import Outcome, PolicySnapshot
from toolcore.risk import RiskClass


class ToolPolicy(models.Model):
    """Per-tool policy. Absent row means "use the tool's own declaration"."""

    RISK_CHOICES = [(risk.label, risk.label) for risk in RiskClass]

    tool_name = models.CharField(max_length=120, unique=True)
    enabled = models.BooleanField(default=True)
    # Blank = defer to the risk class the tool declares in code.
    risk_class = models.CharField(max_length=20, choices=RISK_CHOICES, blank=True)
    # Null = derive from the risk class (writes need approval, reads do not).
    requires_approval = models.BooleanField(null=True, blank=True)
    # Empty list = no role restriction beyond authentication.
    allowed_roles = models.JSONField(default=list, blank=True)
    max_calls_per_run = models.PositiveIntegerField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["tool_name"]
        verbose_name_plural = "tool policies"

    def __str__(self) -> str:
        return f"{self.tool_name} ({'enabled' if self.enabled else 'disabled'})"

    def to_snapshot(self) -> PolicySnapshot:
        return PolicySnapshot(
            tool_name=self.tool_name,
            enabled=self.enabled,
            risk_class=RiskClass.from_label(self.risk_class) if self.risk_class else None,
            requires_approval=self.requires_approval,
            allowed_roles=frozenset(self.allowed_roles) if self.allowed_roles else None,
            max_calls_per_run=self.max_calls_per_run,
        )


class ApprovalRequest(models.Model):
    """A human decision that one specific write may run once.

    Bound to ``args_hash`` rather than to the tool, so approving "restart the
    Spooler" cannot authorise "restart the database". Consuming the approval marks
    it used; a second execution needs a second decision.
    """

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"
        EXPIRED = "expired", "Expired"
        CONSUMED = "consumed", "Consumed"

    run = models.ForeignKey(
        "agent.AgentRun", on_delete=models.CASCADE, related_name="approvals"
    )
    # Filled in once the corresponding AgentStep is persisted.
    step_no = models.PositiveIntegerField(null=True, blank=True)

    tool_name = models.CharField(max_length=120)
    risk_class = models.CharField(max_length=20)
    args_redacted = models.JSONField(default=dict, blank=True)
    args_hash = models.CharField(max_length=64, db_index=True)
    rationale = models.TextField(blank=True)
    preview = models.JSONField(null=True, blank=True)
    dry_run_ok = models.BooleanField(default=False)

    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    decided_by = models.ForeignKey(
        "accounts.CustomUser",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="approval_decisions",
    )
    decided_at = models.DateTimeField(null=True, blank=True)
    decision_note = models.TextField(blank=True)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "-created_at"]),
            models.Index(fields=["run", "status"]),
        ]

    def __str__(self) -> str:
        return f"Approval #{self.pk} {self.tool_name} [{self.status}]"

    @property
    def is_actionable(self) -> bool:
        return self.status == self.Status.PENDING and not self.is_expired

    @property
    def is_expired(self) -> bool:
        from django.utils import timezone

        return self.expires_at <= timezone.now()


class ToolInvocation(models.Model):
    """One row per tool attempt, from any actor: agent, MCP client, human, system."""

    OUTCOME_CHOICES = [(outcome.value, outcome.value) for outcome in Outcome]

    tool_name = models.CharField(max_length=120, db_index=True)
    risk_class = models.CharField(max_length=20)
    actor_type = models.CharField(max_length=20, default="agent")
    actor_id = models.CharField(max_length=120, blank=True)
    outcome = models.CharField(max_length=20, choices=OUTCOME_CHOICES, db_index=True)
    args_hash = models.CharField(max_length=64, db_index=True)
    args_redacted = models.JSONField(default=dict, blank=True)
    error_code = models.CharField(max_length=60, blank=True)
    error_message = models.TextField(blank=True)
    duration_ms = models.PositiveIntegerField(default=0)
    trace_id = models.CharField(max_length=64, blank=True, db_index=True)
    transport = models.CharField(max_length=20, default="internal")
    dry_run = models.BooleanField(default=False)
    # The account this attempt belongs to. Nullable because ``toolcore`` builds the
    # record without any Django knowledge, so the organisation is attached at the
    # persistence seam; rows written before tenancy existed have none.
    organization = models.ForeignKey(
        "organizations.Organization",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="tool_invocations",
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["tool_name", "-created_at"]),
            models.Index(fields=["outcome", "-created_at"]),
            models.Index(fields=["organization", "-created_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.created_at:%Y-%m-%d %H:%M:%S} {self.tool_name} [{self.outcome}]"

    @property
    def is_denial(self) -> bool:
        return self.outcome in (Outcome.DENIED.value, Outcome.APPROVAL_REQUIRED.value)
