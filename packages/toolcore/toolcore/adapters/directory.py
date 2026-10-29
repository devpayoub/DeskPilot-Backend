"""The directory capability interface.

Two implementations must behave identically for everything the agent relies on:

* ``DatabaseDirectory`` (Django) — a seeded fake tenant, so the project runs with no
  domain controller.
* ``LdapDirectory`` — a real LDAP server (OpenLDAP for tests, AD in production).

Where the backends genuinely differ — AD lockout state has no OpenLDAP equivalent
without the ppolicy overlay — the adapter says so with a clear error instead of
pretending. A contract test that documents a real difference is worth more than one
that fakes parity.
"""
from __future__ import annotations

import secrets
import string
from typing import Protocol, runtime_checkable

from ..errors import ToolDenied

# Groups no approval can authorise. A hard deny, not a policy setting.
PRIVILEGED_GROUPS = frozenset(
    {
        "domain admins",
        "enterprise admins",
        "schema admins",
        "administrators",
        "account operators",
        "backup operators",
        "group policy creator owners",
    }
)


def ensure_not_privileged(group: str) -> None:
    """Refuse any operation on a privileged group, before it reaches an adapter."""
    if (group or "").strip().lower() in PRIVILEGED_GROUPS:
        raise ToolDenied(
            f"'{group}' is a privileged group. Group membership changes there are "
            "outside what this agent may do, with or without approval."
        )


def generate_password(length: int = 20) -> str:
    """A random password meeting typical complexity rules, without ambiguous glyphs."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in candidate)
            and any(c.isupper() for c in candidate)
            and any(c.isdigit() for c in candidate)
            and any(c in "!@#$%^&*-_=+" for c in candidate)
        ):
            return candidate


@runtime_checkable
class DirectoryAdapter(Protocol):
    def lookup_user(self, query: str) -> dict | None:
        """Find one user by sAMAccountName, UPN/email, or display name."""

    def get_group_membership(self, group: str, sam: str | None = None) -> dict:
        """List a group's members, or a user's groups when ``sam`` is given."""

    def unlock_account(self, sam: str, *, dry_run: bool) -> dict:
        """Clear a lockout. Backends without lockout state must raise, not pretend."""

    def reset_password(self, sam: str, force_change: bool, *, dry_run: bool) -> dict:
        """Set a new password and return it once, for the caller to store securely."""

    def add_group_member(self, group: str, sam: str, *, dry_run: bool) -> dict:
        """Add a user to a group."""

    def remove_group_member(self, group: str, sam: str, *, dry_run: bool) -> dict:
        """Remove a user from a group."""
