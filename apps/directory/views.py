from __future__ import annotations

import logging

from django.http import Http404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.common.pagination import DefaultPagination
from apps.common.permissions import IsServiceDeskOrAbove, IsTechnicianOrAbove

from .adapters import DatabaseDirectory
from .models import Device, Employee
from .vault import retrieve_password

logger = logging.getLogger(__name__)


class EmployeeListView(APIView):
    """The directory, for the console's picker. Read-only."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        needle = request.query_params.get("q", "").strip()
        queryset = Employee.objects.prefetch_related("groups", "devices")
        if needle:
            queryset = queryset.filter(sam__icontains=needle) | queryset.filter(
                display_name__icontains=needle
            )
        paginator = DefaultPagination()
        page = paginator.paginate_queryset(queryset, request, view=self)
        rows = [
            {
                "sam": employee.sam,
                "display_name": employee.display_name,
                "email": employee.email,
                "department": employee.department,
                "account_enabled": employee.account_enabled,
                "locked_out": employee.locked_out,
                "groups": sorted(employee.groups.values_list("name", flat=True)),
            }
            for employee in page
        ]
        return paginator.get_paginated_response(rows)


class EmployeeDetailView(APIView):
    permission_classes = [IsServiceDeskOrAbove]

    def get(self, request, sam):
        found = DatabaseDirectory().lookup_user(sam)
        if found is None:
            raise Http404("No such user.")
        return Response(found)


class DeviceListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        paginator = DefaultPagination()
        page = paginator.paginate_queryset(
            Device.objects.select_related("assigned_employee"), request, view=self
        )
        rows = [
            {
                "hostname": device.hostname,
                "model": device.model,
                "assigned_to": device.assigned_employee.sam if device.assigned_employee else None,
                "last_seen": device.last_seen,
                "bitlocker_status": device.bitlocker_status,
            }
            for device in page
        ]
        return paginator.get_paginated_response(rows)


class PasswordResetRetrievalView(APIView):
    """Hand a generated password to an authorised human, once.

    Deliberately separate from the tool layer: the agent only ever sees the
    reference, and this endpoint is the only way to turn it into a secret.
    """

    permission_classes = [IsTechnicianOrAbove]

    def get(self, request, reference):
        try:
            record = retrieve_password(reference)
        except ValueError as exc:
            return Response(
                {"error": {"code": "unavailable", "message": str(exc)}},
                status=status.HTTP_410_GONE,
            )

        logger.info(
            "password retrieved reference=%s sam=%s by=%s",
            record.reference,
            record.sam,
            getattr(request.user, "email", ""),
        )
        return Response(
            {
                "sam": record.sam,
                "password": record.password,
                "force_change": record.force_change,
                "expires_at": record.expires_at,
                "note": "This value is shown once and is not recoverable afterwards.",
            }
        )
