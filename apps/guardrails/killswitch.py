"""Two-level kill switch.

``paused`` blocks writes while leaving diagnostics usable; ``halted`` stops
everything. An unrecognised stored value is treated as ``halted`` — if the switch
state cannot be understood, the safe assumption is that someone pulled it.
"""
from __future__ import annotations

import logging

from django.core.cache import cache

from toolcore.base import KillSwitchState

logger = logging.getLogger(__name__)

CACHE_KEY = "guardrails:killswitch"
# Long TTL: the switch is state, not a cache entry. It survives until changed.
_PERSIST_SECONDS = 60 * 60 * 24 * 365


def get_state() -> KillSwitchState:
    raw = cache.get(CACHE_KEY)
    if not raw:
        return KillSwitchState.OPEN
    try:
        return KillSwitchState(raw)
    except ValueError:
        logger.error("unknown kill switch value %r; treating as HALTED", raw)
        return KillSwitchState.HALTED


def set_state(state: KillSwitchState) -> KillSwitchState:
    cache.set(CACHE_KEY, state.value, _PERSIST_SECONDS)
    logger.warning("kill switch set to %s", state.value)
    return state


def reset() -> KillSwitchState:
    return set_state(KillSwitchState.OPEN)
