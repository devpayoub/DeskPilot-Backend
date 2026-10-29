"""Which organisation is this request acting in?

Django middleware runs before DRF authenticates, so at middleware time a
JWT-bearing request still looks anonymous. That is why this is not middleware: it
is called from ``TenantJWTAuthentication`` immediately after the token is
verified, which is the first moment ``request.user`` is real. Same effect,
correct ordering.

Resolution is cached on the request, so calling it twice costs nothing and the
result cannot change mid-request — a permission check and the view that follows it
must never disagree about the tenant.
"""
from __future__ import annotations

from apps.accounts.models import Role

from .models import Membership, Organization

_MEMBERSHIP_ATTR = "_deskpilot_membership"

# The console sends ``x-organization-id`` and stores the value it got back from
# ``/auth/me/``, which is the organisation's primary key. ``x-organization`` is
# accepted too, because a slug is the friendlier thing for a script or a CLI to
# send. Both resolve to the same membership.
_ORGANIZATION_HEADERS = ("HTTP_X_ORGANIZATION_ID", "HTTP_X_ORGANIZATION")


def _requested_organization(request) -> str:
    """Explicit tenant selection, for a person who belongs to several accounts."""
    for header in _ORGANIZATION_HEADERS:
        raw = request.META.get(header)
        if raw is None:
            continue
        value = str(raw).strip()
        if value:
            return value
    return ""


def _organization_by_selector(selector: str) -> Organization | None:
    queryset = Organization.objects.filter(is_active=True)
    if selector.isdigit():
        return queryset.filter(pk=int(selector)).first()
    return queryset.filter(slug=selector).first()


def resolve_tenant(request) -> Membership | None:
    """Attach ``request.organization`` and ``request.membership``, once.

    No membership means no organisation, and every org-scoped permission refuses.
    It does *not* auto-create one: a request that silently provisions a tenant is
    a request that can be used to mint access.

    A selector that names an organisation the caller does not belong to falls back
    to their default membership rather than failing. That is not a privilege
    escalation — the fallback is still one of their own — and it keeps a stale
    cookie (an organisation they were removed from) from bricking the console.

    The one exception is a **platform superuser**: the operator of DeskPilot
    itself, who is not a member of any customer's account. They may name any
    account explicitly and act in it as an administrator. That is the escape hatch
    when a client locks themselves out, so it is deliberately narrow — superuser
    only, explicit header only, never a default, and ``request.membership`` stays
    ``None`` so nothing can mistake them for a real member of the tenant.
    """
    if hasattr(request, _MEMBERSHIP_ATTR):
        return getattr(request, _MEMBERSHIP_ATTR)

    user = getattr(request, "user", None)
    membership = None
    organization = None
    selector = ""

    if user is not None and user.is_authenticated:
        selector = _requested_organization(request)

        candidates = (
            Membership.objects.select_related("organization", "department")
            .filter(
                user=user,
                is_active=True,
                organization__is_active=True,
            )
            .order_by("created_at")
        )

        if selector:
            if selector.isdigit():
                membership = candidates.filter(organization_id=int(selector)).first()
            else:
                membership = candidates.filter(organization__slug=selector).first()
        if membership is None:
            membership = candidates.first()

        if membership is not None:
            # Read by ``accounts.models.effective_role``, which the permission
            # classes use. Never persisted — it is the role for this request only.
            user.active_role = membership.role
            organization = membership.organization

        elif selector and getattr(user, "is_superuser", False):
            organization = _organization_by_selector(selector)
            if organization is not None:
                # Enough for every permission class to let them through, and it is
                # scoped to this request by the same attribute the membership path
                # uses. There is no membership row, and there is not meant to be.
                user.active_role = Role.ADMIN

    setattr(request, _MEMBERSHIP_ATTR, membership)
    request.membership = membership
    request.organization = organization
    return membership


def current_membership(request) -> Membership | None:
    """Alias for readability at call sites that only need the membership."""
    return resolve_tenant(request)
