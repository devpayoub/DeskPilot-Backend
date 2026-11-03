"""The capability vocabulary, defined exactly once — on the server.

A capability names a thing a person can do (``member:manage``), not a rank number.
A view asks for the capability it needs and this module answers which roles hold it.

The console used to keep its own copy of that second answer, and the two drifted:
endpoints the map called administrator-only were open to any signed-in user, because
nothing but a TypeScript table was holding them up. So the map lives here and
``/auth/me/`` serves it; the console reads the answer out of the response instead of
maintaining one.

Two rules keep it honest:

* Every capability named here is enforced by at least one view, and the matrix test
  asserts the whole grid, so a capability declared and never gated on cannot rot
  quietly.
* The ladder is cumulative — a technician holds everything the service desk holds, an
  administrator everything a technician holds. Losing that ordering is what the tests
  catch.
"""
from __future__ import annotations

from enum import StrEnum

from apps.accounts.models import Role


class Capability(StrEnum):
    # Tickets and the agent's work.
    TICKET_READ = "ticket:read"
    RUN_TRIGGER = "run:trigger"
    # The tool layer.
    TOOL_READ = "tool:read"
    TOOL_INVOKE = "tool:invoke"
    APPROVAL_READ = "approval:read"
    APPROVAL_DECIDE = "approval:decide"
    AUDIT_READ = "audit:read"
    USAGE_READ = "usage:read"
    EVAL_READ = "eval:read"
    DIRECTORY_READ = "directory:read"
    POLICY_WRITE = "policy:write"
    KILL_SWITCH_WRITE = "killswitch:write"
    # Tenancy. ``org:read`` is "see which account I am in"; the ``:manage`` pair is
    # what a *client administrator* — not a platform operator — may do inside it.
    ORG_READ = "org:read"
    MEMBER_READ = "member:read"
    DEPARTMENT_MANAGE = "department:manage"
    MEMBER_MANAGE = "member:manage"


# Declared walking up the ladder, each one a superset of the last.
_REQUESTER = {
    Capability.TICKET_READ,
    Capability.ORG_READ,
}

# L1 triage: reads the queue and the record, acts on nothing.
_SERVICE_DESK = _REQUESTER | {
    Capability.TOOL_READ,
    Capability.APPROVAL_READ,
    Capability.AUDIT_READ,
    Capability.USAGE_READ,
    Capability.MEMBER_READ,
}

# L2: the role that actually touches things.
_TECHNICIAN = _SERVICE_DESK | {
    Capability.RUN_TRIGGER,
    Capability.TOOL_INVOKE,
    Capability.APPROVAL_DECIDE,
    Capability.DIRECTORY_READ,
}

# Governance of one account: its policies, its switches, its people.
_ADMIN = _TECHNICIAN | {
    Capability.EVAL_READ,
    Capability.POLICY_WRITE,
    Capability.KILL_SWITCH_WRITE,
    Capability.DEPARTMENT_MANAGE,
    Capability.MEMBER_MANAGE,
}

ROLE_CAPABILITIES: dict[str, tuple[Capability, ...]] = {
    # Ordered by the canonical listing rather than set order, so ``/auth/me/`` and
    # the tests see a stable sequence.
    role: tuple(cap for cap in Capability if cap in caps)
    for role, caps in (
        (Role.REQUESTER, _REQUESTER),
        (Role.SERVICE_DESK, _SERVICE_DESK),
        (Role.TECHNICIAN, _TECHNICIAN),
        (Role.ADMIN, _ADMIN),
    )
}


def capabilities_for_role(role: str | None) -> list[str]:
    """Every capability ``role`` holds, in canonical order.

    An unknown or missing role holds nothing. That is the fail-closed direction: a
    role typo, or a membership row with a garbage value, loses access instead of
    gaining it.
    """
    return list(ROLE_CAPABILITIES.get(role or ""))


def role_has_capability(role: str | None, capability: str) -> bool:
    return capability in ROLE_CAPABILITIES.get(role or "")
