"""Role-based permission classes.

The role ladder lives in ``apps.accounts.models`` so it is defined exactly once.
These classes only translate it into DRF permissions.
"""
from __future__ import annotations

from rest_framework.permissions import BasePermission

from apps.accounts.models import ROLE_RANK, Role


class MinRole(BasePermission):
    """Allow any authenticated user whose role ranks at or above ``min_role``."""

    min_role: str = Role.REQUESTER

    def has_permission(self, request, view) -> bool:
        user = getattr(request, "user", None)
        if user is None or not user.is_authenticated:
            return False
        if getattr(user, "is_superuser", False):
            return True
        return ROLE_RANK.get(user.role, -1) >= ROLE_RANK[self.min_role]


class IsAdmin(MinRole):
    min_role = Role.ADMIN


class IsServiceDeskOrAbove(MinRole):
    min_role = Role.SERVICE_DESK


class IsTechnicianOrAbove(MinRole):
    min_role = Role.TECHNICIAN
