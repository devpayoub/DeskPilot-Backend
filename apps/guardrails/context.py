"""Builds a ToolContext wired to the Django guardrails.

This is the seam that keeps ``toolcore`` framework-free: everything Django-shaped
(policy lookup, kill switch, audit persistence, adapters, approval persistence) is
injected here, and the MCP server builds its own equivalent context with the same
tool objects.
"""
from __future__ import annotations

import uuid
from functools import partial
from types import SimpleNamespace
from typing import Any, Callable

from django.conf import settings

from toolcore.adapters import LocalDiagnostics, LdapDirectory, build_remediation_adapter
from toolcore.base import ApprovalContext, ToolContext

from apps.accounts.models import effective_role
from apps.directory.adapters import DatabaseDirectory
from apps.directory.vault import store_password

from . import killswitch, policy
from .audit import record_invocation


def build_directory_adapter(organization=None):
    """LDAP when configured, otherwise the seeded local tenant.

    The default is the fake tenant on purpose: a fresh clone must run with no domain
    controller, and every row it produces is marked ``source=fake``.

    ``organization`` bounds the database-backed adapter to one workspace's identity
    data. The LDAP path ignores it, because a per-tenant base DN is not something this
    deployment can express yet — one directory server currently serves one domain to
    every workspace, and running more than one company against it is not a supported
    configuration rather than an unguarded leak.
    """
    backend = (getattr(settings, "DIRECTORY_BACKEND", "fake") or "fake").lower()
    if backend == "ldap":
        return LdapDirectory(
            server_uri=settings.LDAP_URI,
            base_dn=settings.LDAP_BASE_DN,
            bind_dn=settings.LDAP_BIND_DN,
            bind_password=settings.LDAP_BIND_PASSWORD,
        )
    return DatabaseDirectory(organization)


def default_adapters(organization=None) -> SimpleNamespace:
    """Adapters available to the Django-side agent.

    Diagnostics are read-only, so the real host implementation is used even under
    SAFE_MODE. Remediation is the opposite: ``build_remediation_adapter`` returns a
    simulated host unless real writes were deliberately enabled.
    """
    return SimpleNamespace(
        diagnostics=LocalDiagnostics(),
        remediation=build_remediation_adapter(
            safe_mode=getattr(settings, "SAFE_MODE", True),
            allow_real_writes=getattr(settings, "ALLOW_REAL_WRITES", False),
        ),
        directory=build_directory_adapter(organization),
    )


def build_context(
    user: Any = None,
    *,
    adapters: Any = None,
    approval_token: str | None = None,
    dry_run: bool = False,
    trace_id: str = "",
    transport: str = "internal",
    actor_type: str = "human",
    actor_id: str | None = None,
    actor_role: str | None = None,
    organization: Any = None,
    on_approval_required: Callable[[ApprovalContext], None] | None = None,
    password_sink: Callable[[str, str, bool], str] | None = None,
) -> ToolContext:
    """Build a context for a human caller, or for the agent when ``actor_*`` is given.

    The agent runs as its own actor with an explicit role rather than borrowing a
    user's, so the audit trail distinguishes "the agent did this" from "a person
    did this" — which is exactly the question an incident review asks.

    ``organization`` is not a tool argument and never appears in a prompt: the model
    cannot choose which tenant it is acting in. It reaches three places — the auditor,
    the directory adapter and the password vault — and all three are bound once here,
    so no individual tool call has to remember to scope itself. A caller that does not
    name one gets an adapter that reads nothing and a vault that refuses to store.
    """
    return ToolContext(
        actor_id=actor_id if actor_id is not None else str(getattr(user, "pk", "") or ""),
        # ``effective_role`` is the role for the organisation being acted in, not
        # the legacy field on the user.
        actor_role=actor_role if actor_role is not None else (effective_role(user) or ""),
        actor_type=actor_type,
        adapters=adapters if adapters is not None else default_adapters(organization),
        approval_token=approval_token,
        dry_run=dry_run,
        trace_id=trace_id or uuid.uuid4().hex,
        transport=transport,
        killswitch=killswitch.get_state,
        policy_resolver=policy.resolve_policy,
        auditor=partial(record_invocation, organization=organization),
        on_approval_required=on_approval_required or (lambda _approval: None),
        # Generated passwords go into the vault; the model only ever sees a reference.
        # The tool layer calls the sink with (sam, password, force_change), so the
        # owner is bound in here rather than threaded through ``toolcore``'s contract.
        password_sink=password_sink or partial(store_password, organization),
    )
