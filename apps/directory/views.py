from __future__ import annotations

import logging

from django.db.models import Q
from django.http import Http404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.common.capabilities import Capability
from apps.common.pagination import DefaultPagination
from apps.common.permissions import HasCapability

from .adapters import DatabaseDirectory
from .crypto import VaultDecryptionError
from .models import Device, Employee
from .vault import retrieve_password

logger = logging.getLogger(__name__)


def _tenant(request):
    """The organisation whose directory this request may read.

    ``None`` means the caller belongs to no workspace — a platform superuser who did
    not name one with an ``X-Organization`` header. Every view below answers as if the
    data simply was not there, rather than falling back to the whole table. That is
    stricter than the ``if organization is not None: filter(...)`` idiom used by the
    audit views, and the difference is deliberate: an audit row is a record about a
    workspace, while a directory is the complete staff list, machine inventory and
    group membership of one company. An operator who genuinely needs a cross-tenant
    read says which workspace they mean.
    """
    return getattr(request, "organization", None)


class EmployeeListView(APIView):
    """The directory, for the console's picker. Read-only."""

    capability = Capability.DIRECTORY_READ
    permission_classes = [HasCapability]

    def get(self, request):
        needle = request.query_params.get("q", "").strip()
        queryset = Employee.objects.filter(organization=_tenant(request)).prefetch_related(
            "groups", "devices"
        )
        if needle:
            # One filter, not two querysets unioned: the previous `|` of two
            # `queryset.filter(...)` calls silently dropped the prefetch and could
            # return the same employee twice.
            queryset = queryset.filter(Q(sam__icontains=needle) | Q(display_name__icontains=needle))
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
    capability = Capability.DIRECTORY_READ
    permission_classes = [HasCapability]

    def get(self, request, sam):
        # The adapter is bound to this request's tenant, so a person who exists in
        # another workspace is simply not found here.
        found = DatabaseDirectory(_tenant(request)).lookup_user(sam)
        if found is None:
            raise Http404("No such user.")
        return Response(found)


class DeviceListView(APIView):
    capability = Capability.DIRECTORY_READ
    permission_classes = [HasCapability]

    def get(self, request):
        paginator = DefaultPagination()
        page = paginator.paginate_queryset(
            Device.objects.filter(organization=_tenant(request)).select_related("assigned_employee"),
            request,
            view=self,
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

    capability = Capability.DIRECTORY_READ
    permission_classes = [HasCapability]

    def get(self, request, reference):
        try:
            record = retrieve_password(reference, _tenant(request))
        except ValueError as exc:
            return Response(
                {"error": {"code": "unavailable", "message": str(exc)}},
                status=status.HTTP_410_GONE,
            )

        try:
            password = record.reveal_password()
        except VaultDecryptionError as exc:
            # The row exists and is live, but the key that wrote it is gone. Say so
            # rather than returning an empty string the operator would paste into a
            # directory.
            logger.error("vault decryption failed reference=%s", record.reference)
            return Response(
                {"error": {"code": "undecryptable", "message": str(exc)}},
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
                "password": password,
                "force_change": record.force_change,
                "expires_at": record.expires_at,
                "note": "This value is shown once and is not recoverable afterwards.",
            }
        )
