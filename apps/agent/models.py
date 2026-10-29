"""Agent run and step records.

``AgentRun`` carries the numbers every cost and latency claim comes from, and
``AgentStep`` is the audit trail the console renders as a live trace. Steps are
written incrementally (``on_step``) so a cancelled or budget-exceeded run still
shows what it did before it stopped — a run that fails silently is worse than one
that fails loudly.
"""
from __future__ import annotations

from django.db import models


class AgentRun(models.Model):
    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        FINISHED = "finished", "Finished"
        FAILED = "failed", "Failed"
        AWAITING_APPROVAL = "awaiting_approval", "Awaiting approval"
        NEEDS_INPUT = "needs_input", "Needs input"
        CANCELLED = "cancelled", "Cancelled"

    class Trigger(models.TextChoices):
        MANUAL = "manual", "Manual"
        AUTO = "auto", "Automatic"

    ticket = models.ForeignKey(
        "helpdesk.Ticket", on_delete=models.CASCADE, related_name="agent_runs"
    )
    objective = models.TextField()
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.QUEUED)
    trigger = models.CharField(max_length=10, choices=Trigger.choices, default=Trigger.MANUAL)

    # Reproducibility: which model and which prompt version produced this result.
    model = models.CharField(max_length=120, blank=True)
    prompt_version = models.CharField(max_length=64, blank=True)

    prompt_tokens = models.PositiveIntegerField(default=0)
    completion_tokens = models.PositiveIntegerField(default=0)
    cost_usd = models.DecimalField(max_digits=10, decimal_places=6, null=True, blank=True)

    iterations = models.PositiveIntegerField(default=0)
    tool_calls = models.PositiveIntegerField(default=0)

    final_result = models.JSONField(null=True, blank=True)
    pending_question = models.TextField(blank=True)
    error = models.TextField(blank=True)

    client_request_id = models.CharField(max_length=120, null=True, blank=True, unique=True)

    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["ticket", "-created_at"]),
            models.Index(fields=["status", "-created_at"]),
        ]

    def __str__(self) -> str:
        return f"Run #{self.pk} [{self.status}] {self.objective[:50]}"

    @property
    def duration_ms(self) -> int | None:
        """Agent wall-clock time, excluding any human approval wait."""
        if not self.started_at or not self.finished_at:
            return None
        return int((self.finished_at - self.started_at).total_seconds() * 1000)


class AgentStep(models.Model):
    class Status(models.TextChoices):
        OK = "ok", "OK"
        ERROR = "error", "Error"
        REFUSED = "refused", "Refused"
        REQUIRES_APPROVAL = "requires_approval", "Requires approval"

    run = models.ForeignKey(AgentRun, on_delete=models.CASCADE, related_name="steps")
    step_no = models.PositiveIntegerField()
    thought = models.TextField(blank=True)
    tool_name = models.CharField(max_length=120, blank=True)
    tool_risk = models.CharField(max_length=20, blank=True)
    validated_args = models.JSONField(default=dict, blank=True)
    args_hash = models.CharField(max_length=64, blank=True)
    result = models.JSONField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OK)
    error_code = models.CharField(max_length=60, blank=True)
    latency_ms = models.PositiveIntegerField(default=0)
    tokens_in = models.PositiveIntegerField(default=0)
    tokens_out = models.PositiveIntegerField(default=0)
    cost_usd = models.DecimalField(max_digits=10, decimal_places=6, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["step_no"]
        unique_together = ("run", "step_no")
        indexes = [models.Index(fields=["run", "step_no"])]

    def __str__(self) -> str:
        return f"Step {self.step_no} {self.tool_name or '(answer)'} [{self.status}]"
