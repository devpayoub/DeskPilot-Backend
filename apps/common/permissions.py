"""Role-based permission classes.

The role ladder lives in ``apps.accounts.models`` and the capability map in
``apps.common.capabilities``, so each is defined exactly once. These classes only
translate them into DRF permissions.
"""
from __future__ import annotations

from django.core.exceptions import ImproperlyConfigured
from rest_framework.permissions import BasePermission

from apps.accounts.models import ROLE_RANK, Role, effective_role
from apps.common.capabilities import role_has_capability


def _required_capability(request, view) -> str:
    """The capability this view needs for ``request``.

    A view declares either ``capability`` (one for every method) or ``capabilities``
    (keyed by lowercase HTTP method) when reads and writes diverge — which they do
    constantly: listing the roster is a service-desk thing, editing it is not.
    """
    per_method = getattr(view, "capabilities", None)
    if per_method:
        found = per_method.get(request.method.lower()) or per_method.get(request.method)
        if found:
            return str(found)
    declared = getattr(view, "capability", None)
    if declared:
        return str(declared)
    raise ImproperlyConfigured(
        f"{type(view).__name__} grants HasCapability but declares no `capability` "
        "or `capabilities`, so nothing could be authorised."
    )


class HasCapability(BasePermission):
    """Authorise on a named capability rather than a rank threshold.

    Rank answers "how senior is this person"; a capability answers "may they do
    *this*". They agree today because the ladder is cumulative, but expressing views
    as capabilities is what lets a role hold a wide rank and still be refused one
    thing — and it is the vocabulary the console already renders.

    The role checked is the role **in the organisation this request is acting in**,
    never the legacy field on the user, so the tenant is resolved here before the
    comparison. A platform superuser passes: that is the operator's escape hatch for
    a client who has locked themselves out, and it is the only bypass.
    """

    def has_permission(self, request, view) -> bool:
        user = getattr(request, "user", None)
        if user is None or not user.is_authenticated:
            return False

        required = _required_capability(request, view)

        # Imported here rather than at module scope: the organisations app imports
        # this module for its own permission classes.
        from apps.organizations.context import resolve_tenant

        resolve_tenant(request)

        if getattr(user, "is_superuser", False):
            return True
        if role_has_capability(effective_role(user), required):
            return True

        self.message = f"This action requires the '{required}' capability."
        return False


class MinRole(BasePermission):
    """Allow any authenticated user whose role ranks at or above ``min_role``."""

    min_role: str = Role.REQUESTER

    def has_permission(self, request, view) -> bool:
        user = getattr(request, "user", None)
        if user is None or not user.is_authenticated:
            return False
        if getattr(user, "is_superuser", False):
            return True
        # The role for *this request*: the membership's role when a tenant was
        # resolved, the field on the user otherwise. Reading ``user.role``
        # directly would ignore the organisation the caller is acting in.
        return ROLE_RANK.get(effective_role(user), -1) >= ROLE_RANK[self.min_role]


class IsAdmin(MinRole):
    min_role = Role.ADMIN


class IsServiceDeskOrAbove(MinRole):
    min_role = Role.SERVICE_DESK


class IsTechnicianOrAbove(MinRole):
    min_role = Role.TECHNICIAN
