"""Tenant-scoped permissions.

These are *additional* to the rank checks in ``apps.common.permissions``. Rank
answers "how senior is this person"; these answer "in which account, and are they
an admin of it". Both must hold.

A superuser passes the admin check — that is the platform operator's escape hatch
for a client who has locked themselves out. It is deliberately the only bypass.
"""
from __future__ import annotations

from rest_framework.permissions import BasePermission

from apps.accounts.models import Role, effective_role

from .context import resolve_tenant


class HasOrganization(BasePermission):
    """The caller belongs to an active organisation."""

    message = "This account does not belong to an organisation."

    def has_permission(self, request, view) -> bool:
        resolve_tenant(request)
        return getattr(request, "organization", None) is not None


class IsOrganizationAdmin(HasOrganization):
    """Administrator **of this organisation**, not of the installation."""

    message = "Only an administrator of this organisation can do that."

    def has_permission(self, request, view) -> bool:
        if not super().has_permission(request, view):
            return False
        user = request.user
        if getattr(user, "is_superuser", False):
            return True
        return effective_role(user) == Role.ADMIN


class IsOrganizationManager(HasOrganization):
    """Service desk and above — the people who triage, not the ones who govern."""

    message = "Service desk access is required for that."

    def has_permission(self, request, view) -> bool:
        if not super().has_permission(request, view):
            return False
        user = request.user
        if getattr(user, "is_superuser", False):
            return True
        from apps.accounts.models import ROLE_RANK

        return ROLE_RANK.get(effective_role(user), -1) >= ROLE_RANK[Role.SERVICE_DESK]
