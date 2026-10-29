"""Cost calculation from token usage and a stored price row."""
from __future__ import annotations

import logging
from decimal import ROUND_HALF_UP, Decimal

from django.core.cache import cache

from .models import ModelPrice

logger = logging.getLogger(__name__)

_MICRO = Decimal("0.000001")
_CACHE_TTL = 60


def _price_for(model: str) -> ModelPrice | None:
    key = f"llm:price:{model}"
    cached = cache.get(key, "miss")
    if cached != "miss":
        return cached or None
    row = ModelPrice.objects.filter(model=model).first()
    cache.set(key, row or None, _CACHE_TTL)
    return row


def cost_for(model: str, prompt_tokens: int, completion_tokens: int) -> Decimal | None:
    """Return the USD cost, or None when the model has no price row.

    None is deliberate: a run with an unknown price must not report 0.00, which
    would quietly drag an average cost per run toward zero.
    """
    row = _price_for(model)
    if row is None:
        logger.warning("no ModelPrice row for model=%s; cost will be null", model)
        return None

    million = Decimal(1_000_000)
    cost = (
        Decimal(prompt_tokens) * row.input_usd_per_million / million
        + Decimal(completion_tokens) * row.output_usd_per_million / million
    )
    return cost.quantize(_MICRO, rounding=ROUND_HALF_UP)
