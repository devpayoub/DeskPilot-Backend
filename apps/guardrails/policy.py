"""Policy resolution with a short cache.

The chokepoint calls this on every tool invocation, so a cache is required. The
TTL is deliberately short (30s): editing a policy in the console must take effect
promptly, and a stale *permissive* policy is the failure mode that matters.
"""
from __future__ import annotations

import logging

from django.core.cache import cache

from toolcore.base import PolicySnapshot

from .models import ToolPolicy

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 30
_KEY = "guardrails:policy:{tool}"

# Distinguishes "no cache entry" from "cached absence of a policy row".
_MISSING = object()


def _cache_key(tool_name: str) -> str:
    return _KEY.format(tool=tool_name)


def resolve_policy(tool_name: str) -> PolicySnapshot | None:
    """Return the policy for a tool, or None when no row exists.

    Raises if the lookup itself fails — the chokepoint turns that into a denial,
    because a guardrail that silently degrades to "no policy" is not a guardrail.
    """
    key = _cache_key(tool_name)
    cached = cache.get(key, _MISSING)
    if cached is not _MISSING:
        # False is the cached marker for "no row"; anything else is a snapshot.
        return cached if cached else None

    row = ToolPolicy.objects.filter(tool_name=tool_name).first()
    snapshot = row.to_snapshot() if row is not None else False
    cache.set(key, snapshot, CACHE_TTL_SECONDS)
    return snapshot if snapshot else None


def invalidate_policy_cache(tool_name: str | None = None) -> None:
    if tool_name is None:
        # LocMem has no delete_pattern; a full clear is acceptable at this scale.
        cache.clear()
        return
    cache.delete(_cache_key(tool_name))


def seed_policies_from_registry() -> int:
    """Create a policy row for every registered tool that lacks one.

    Returns how many rows were created. Existing rows are never overwritten — the
    console is the source of truth once a row exists.
    """
    from toolcore import registry

    created = 0
    existing = set(ToolPolicy.objects.values_list("tool_name", flat=True))
    for tool in registry.list_tools():
        if tool.name in existing:
            continue
        ToolPolicy.objects.create(
            tool_name=tool.name,
            enabled=True,
            risk_class="",  # defer to the tool declaration
            requires_approval=None,
            allowed_roles=sorted(tool.allowed_roles) if tool.allowed_roles else [],
        )
        created += 1
    return created
