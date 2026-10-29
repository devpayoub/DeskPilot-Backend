"""Model pricing.

Prices are data, not code: they change, they differ per provider, and a hardcoded
constant silently rots. ``cost_for`` returns ``None`` when no price row exists,
which makes the run's ``cost_usd`` null — an honest gap, not a made-up zero.
"""
from __future__ import annotations

from django.db import models


class ModelPrice(models.Model):
    """USD price per one million tokens for one model identifier."""

    model = models.CharField(max_length=120, unique=True)
    input_usd_per_million = models.DecimalField(max_digits=10, decimal_places=4)
    output_usd_per_million = models.DecimalField(max_digits=10, decimal_places=4)
    notes = models.CharField(
        max_length=255,
        blank=True,
        help_text="Where this price came from and when it was checked.",
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["model"]
        verbose_name_plural = "model prices"

    def __str__(self) -> str:
        return f"{self.model} (${self.input_usd_per_million}/${self.output_usd_per_million} per 1M)"
