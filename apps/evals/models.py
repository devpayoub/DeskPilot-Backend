"""One row per eval run, and one per case, so a regression is attributable.

``metrics`` is stored as JSON rather than columns because the metric set is expected
to grow, and a new metric should not require a migration to become visible.
"""
from __future__ import annotations

from django.db import models


class EvalRun(models.Model):
    class Mode(models.TextChoices):
        # Deterministic script replayed from the dataset's expected behaviour.
        # Proves the harness computes correctly. NOT a measure of model quality.
        ORACLE = "oracle", "Oracle (harness self-check)"
        # Model decisions replayed from recorded cassettes. Free and deterministic.
        REPLAY = "replay", "Replay (recorded model)"
        # A real model, live. This is the only mode that measures the model.
        LIVE = "live", "Live model"

    mode = models.CharField(max_length=10, choices=Mode.choices)
    model = models.CharField(max_length=120, blank=True)
    prompt_version = models.CharField(max_length=64, blank=True)

    case_count = models.PositiveIntegerField(default=0)
    passed_count = models.PositiveIntegerField(default=0)
    gates_passed = models.BooleanField(default=False)
    metrics = models.JSONField(default=dict, blank=True)
    notes = models.TextField(blank=True)

    duration_ms = models.PositiveIntegerField(default=0)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["mode", "-created_at"])]

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"EvalRun #{self.pk} [{self.mode}] {self.passed_count}/{self.case_count}"


class EvalCaseResult(models.Model):
    run = models.ForeignKey(EvalRun, on_delete=models.CASCADE, related_name="results")
    case_id = models.CharField(max_length=40, db_index=True)
    kind = models.CharField(max_length=20, blank=True)

    expected = models.JSONField(default=dict, blank=True)
    actual = models.JSONField(default=dict, blank=True)

    category_match = models.BooleanField(default=False)
    priority_match = models.BooleanField(default=False)
    disposition_match = models.BooleanField(default=False)

    expected_tools = models.JSONField(default=list, blank=True)
    called_tools = models.JSONField(default=list, blank=True)
    attempted_forbidden = models.JSONField(default=list, blank=True)

    status = models.CharField(max_length=20, blank=True)
    error = models.TextField(blank=True)
    duration_ms = models.PositiveIntegerField(default=0)
    iterations = models.PositiveIntegerField(default=0)
    tool_calls = models.PositiveIntegerField(default=0)
    cost_usd = models.DecimalField(max_digits=10, decimal_places=6, null=True, blank=True)

    class Meta:
        ordering = ["case_id"]
        unique_together = ("run", "case_id")
        indexes = [models.Index(fields=["run", "case_id"])]

    def __str__(self) -> str:
        return f"{self.case_id} ({'pass' if self.disposition_match else 'fail'})"

    @property
    def is_unsafe(self) -> bool:
        return bool(self.attempted_forbidden)
