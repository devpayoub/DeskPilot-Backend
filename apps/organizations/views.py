"""Organisation administration: departments and members.

Two rules shape this module:

* every lookup is scoped to ``request.organization``, so an id from another tenant
  is a 404 rather than a cross-tenant edit. Filtering in the queryset, not after
  the fetch, is the same discipline the ticket endpoints use;
* writes go through ``services``, so the "last admin" and "no role above your own"
  guards cannot be bypassed by a view that forgot to ask.
"""
from __future__ import annotations

from django.db.models import Count, Q
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.models import ROLE_RANK, Role, effective_role

from .models import Department, Membership
from .permissions import HasOrganization, IsOrganizationAdmin
from .services import (
    TenancyError,
    accept_invite,
    create_department,
    create_member,
    delete_department,
    invite_member,
    set_member_password,
    update_department,
    update_member,
)


def _error(code: str, message: str, http_status: int) -> Response:
    return Response({"error": {"code": code, "message": message}}, status=http_status)


def _tenancy_error(exc: TenancyError) -> Response:
    """Map a refused rule onto a status code.

    A rule the caller could not have satisfied is a 409 (the state is the
    problem); a rule about their own authority is a 403; a bad password is the
    caller's input and is a 400.
    """
    if exc.code in {"role_too_high", "last_admin", "cannot_disable_owner"}:
        status_code = status.HTTP_403_FORBIDDEN
    elif exc.code in {"invalid_password", "weak_password", "invalid_email"}:
        status_code = status.HTTP_400_BAD_REQUEST
    else:
        status_code = status.HTTP_409_CONFLICT
    return _error(exc.code, exc.message, status_code)


def serialize_department(department: Department) -> dict:
    return {
        "id": department.pk,
        "name": department.name,
        "code": department.code,
        "parent_id": department.parent_id,
        "is_active": department.is_active,
        # Annotated when listed; counted on demand otherwise.
        "member_count": getattr(department, "member_count", None),
        "created_at": department.created_at.isoformat(),
    }


def serialize_member(membership: Membership) -> dict:
    user = membership.user
    return {
        "id": membership.pk,
        "user_id": str(user.pk),
        "email": user.email,
        "full_name": user.display_name or user.email,
        "role": membership.role,
        "department_id": membership.department_id,
        "department_name": membership.department.name if membership.department_id else None,
        "is_owner": membership.is_owner,
        "is_active": membership.is_active,
        "status": membership.status,
        "created_at": membership.created_at.isoformat(),
        "accepted_at": membership.accepted_at.isoformat() if membership.accepted_at else None,
    }


def _departments(request):
    return Department.objects.filter(organization=request.organization)


def _members(request):
    return Membership.objects.filter(organization=request.organization).select_related(
        "user", "department"
    )


class OrganizationDetailView(APIView):
    """The account the caller is acting in, and what they may do in it."""

    permission_classes = [HasOrganization]

    def get(self, request):
        organization = request.organization
        membership = request.membership
        role = effective_role(request.user)

        return Response(
            {
                "id": str(organization.pk),
                "name": organization.name,
                "slug": organization.slug,
                "is_active": organization.is_active,
                "created_at": organization.created_at.isoformat(),
                "my_role": role,
                "my_department": (
                    serialize_department(membership.department)
                    if membership is not None and membership.department_id
                    else None
                ),
                "member_count": organization.memberships.filter(is_active=True).count(),
                "department_count": organization.departments.count(),
                # What the console should show. Presentation only — the API
                # re-checks every write regardless of what this says.
                "permissions": {
                    "manage_departments": role == Role.ADMIN,
                    "manage_members": role == Role.ADMIN,
                    "view_members": ROLE_RANK.get(role, -1) >= ROLE_RANK[Role.SERVICE_DESK],
                },
            }
        )


class DepartmentListCreateView(APIView):
    """List the operator departments, or add one.

    Only an administrator of this organisation may create one. That is the
    permission the whole feature exists for: a client admin adding departments
    to their own account, without a platform operator in the loop.
    """

    def get_permissions(self):
        if self.request.method == "POST":
            return [IsOrganizationAdmin()]
        return [HasOrganization()]

    def get(self, request):
        queryset = _departments(request).annotate(
            member_count=Count("members", filter=Q(members__is_active=True))
        )
        needle = request.query_params.get("q", "").strip()
        if needle:
            queryset = queryset.filter(Q(name__icontains=needle) | Q(code__icontains=needle))

        include_archived = request.query_params.get("include_archived") == "1"
        if not include_archived:
            queryset = queryset.filter(is_active=True)

        return Response({"results": [serialize_department(d) for d in queryset]})

    def post(self, request):
        data = request.data or {}
        parent = None
        parent_id = data.get("parent_id")
        if parent_id not in (None, "", 0):
            parent = get_object_or_404(_departments(request), pk=parent_id)

        try:
            department = create_department(
                request.organization,
                name=data.get("name", ""),
                code=data.get("code", ""),
                parent=parent,
            )
        except TenancyError as exc:
            return _tenancy_error(exc)

        department.member_count = 0
        return Response(serialize_department(department), status=status.HTTP_201_CREATED)


class DepartmentDetailView(APIView):
    permission_classes = [IsOrganizationAdmin]

    def get_object(self, request, pk) -> Department:
        return get_object_or_404(_departments(request), pk=pk)

    def patch(self, request, pk):
        department = self.get_object(request, pk)
        data = request.data or {}

        parent = None
        if "parent_id" in data:
            parent_id = data.get("parent_id")
            if parent_id in (None, "", 0):
                department.parent = None
            else:
                parent = get_object_or_404(_departments(request), pk=parent_id)

        try:
            department = update_department(
                department,
                name=data.get("name"),
                code=data.get("code"),
                parent=parent,
                is_active=data.get("is_active"),
            )
        except TenancyError as exc:
            return _tenancy_error(exc)

        department.member_count = department.members.filter(is_active=True).count()
        return Response(serialize_department(department))

    def delete(self, request, pk):
        department = self.get_object(request, pk)

        reassign_to = None
        reassign_id = request.query_params.get("reassign_to")
        if reassign_id:
            reassign_to = get_object_or_404(_departments(request), pk=reassign_id)

        try:
            delete_department(department, reassign_to=reassign_to)
        except TenancyError as exc:
            return _tenancy_error(exc)

        return Response(status=status.HTTP_204_NO_CONTENT)


class MemberListCreateView(APIView):
    """The roster, and the invitation that adds to it."""

    def get_permissions(self):
        if self.request.method == "POST":
            return [IsOrganizationAdmin()]
        from .permissions import IsOrganizationManager

        return [IsOrganizationManager()]

    def get(self, request):
        queryset = _members(request)
        needle = request.query_params.get("q", "").strip()
        if needle:
            queryset = queryset.filter(
                Q(user__email__icontains=needle) | Q(user__display_name__icontains=needle)
            )

        department_id = request.query_params.get("department_id")
        if department_id:
            queryset = queryset.filter(department_id=department_id)

        role = request.query_params.get("role")
        if role:
            queryset = queryset.filter(role=role)

        return Response({"results": [serialize_member(m) for m in queryset]})

    def post(self, request):
        data = request.data or {}
        department = None
        if data.get("department_id"):
            department = get_object_or_404(_departments(request), pk=data["department_id"])

        try:
            membership, password = create_member(
                request.organization,
                email=data.get("email", ""),
                role=data.get("role") or Role.REQUESTER,
                password=data.get("password") or None,
                department=department,
                actor_role=effective_role(request.user),
            )
        except TenancyError as exc:
            return _tenancy_error(exc)

        body = serialize_member(membership)
        # Returned once, never stored in the clear and never retrievable again.
        # The person can sign in with it immediately; no invitation step.
        body["initial_password"] = password
        return Response(body, status=status.HTTP_201_CREATED)


class MemberDetailView(APIView):
    permission_classes = [IsOrganizationAdmin]

    def get_object(self, request, pk) -> Membership:
        return get_object_or_404(_members(request), pk=pk)

    def patch(self, request, pk):
        membership = self.get_object(request, pk)
        data = request.data or {}

        department = None
        if data.get("department_id"):
            department = get_object_or_404(_departments(request), pk=data["department_id"])

        try:
            membership = update_member(
                membership,
                role=data.get("role"),
                department=department,
                clear_department="department_id" in data and not data.get("department_id"),
                is_active=data.get("is_active"),
                actor_role=effective_role(request.user),
            )
        except TenancyError as exc:
            return _tenancy_error(exc)

        return Response(serialize_member(membership))

    def delete(self, request, pk):
        """Deactivate, never delete.

        The audit trail, approval decisions and ticket history all point at this
        user. Deleting the row would either cascade that history away or leave
        dangling references — so access is removed and the record is kept.
        """
        membership = self.get_object(request, pk)
        try:
            membership = update_member(
                membership,
                is_active=False,
                actor_role=effective_role(request.user),
            )
        except TenancyError as exc:
            return _tenancy_error(exc)

        return Response(serialize_member(membership))


class MemberPasswordView(APIView):
    """Set or reset one member's password.

    This is the account's only "forgot password" path, because there is no mail
    transport. Both levels of administrator can use it: the company admin for
    their own account, and a platform superuser for any account — the latter is
    the escape hatch when a client has locked themselves out.

    The new password is returned once. It is never stored in the clear, so it
    cannot be read back later; resetting again is the way to recover it.
    """

    permission_classes = [IsOrganizationAdmin]

    def post(self, request, pk):
        membership = get_object_or_404(_members(request), pk=pk)
        data = request.data or {}

        try:
            password = set_member_password(
                membership, password=data.get("password") or None
            )
        except TenancyError as exc:
            return _tenancy_error(exc)

        return Response(
            {
                "id": membership.pk,
                "email": membership.user.email,
                "password": password,
                "message": "Shown once. The member can sign in with it now.",
            }
        )


class AcceptInviteView(APIView):
    """Public: an invited person sets their own password.

    Unauthenticated by necessity — the whole point is that they cannot sign in yet.
    The token is single-use and expires, and the response never says whether an
    address exists, only whether the token was good.
    """

    permission_classes = [AllowAny]
    authentication_classes: list = []

    def post(self, request):
        data = request.data or {}
        try:
            membership = accept_invite(
                str(data.get("token") or ""), str(data.get("password") or "")
            )
        except TenancyError as exc:
            http_status = (
                status.HTTP_400_BAD_REQUEST
                if exc.code == "weak_password"
                else status.HTTP_400_BAD_REQUEST
            )
            return _error(exc.code, exc.message, http_status)

        return Response(
            {
                "email": membership.user.email,
                "organization": membership.organization.name,
                "organization_slug": membership.organization.slug,
                "role": membership.role,
                "message": "Password set. You can sign in now.",
            }
        )
