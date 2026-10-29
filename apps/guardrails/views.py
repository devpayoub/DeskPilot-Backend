from __future__ import annotations

import logging

from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.common.pagination import DefaultPagination
from apps.common.permissions import IsAdmin, IsServiceDeskOrAbove
from toolcore import registry
from toolcore.base import KillSwitchState
from toolcore.errors import (
    ApprovalRequired,
    ToolDenied,
    ToolExecutionError,
    ToolNotFound,
    ToolValidationError,
)
from toolcore.execute import execute_tool

from . import approvals, killswitch, policy
from .context import build_context
from .models import ApprovalRequest, ToolInvocation, ToolPolicy
from .serializers import (
    ApprovalDecisionSerializer,
    ApprovalRequestSerializer,
    ToolInvocationSerializer,
    ToolPolicySerializer,
)

logger = logging.getLogger(__name__)


def _error(code: str, message: str, http_status: int) -> Response:
    return Response(
        {"error": {"code": code, "message": message}}, status=http_status
    )


@api_view(["GET"])
@permission_classes([AllowAny])
def health(request):
    """Liveness plus how many tools the registry currently exposes."""
    return Response({"status": "ok", "tools": registry.count()})


class ToolListView(APIView):
    """The tool catalog, as the agent and the MCP server see it."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"count": registry.count(), "tools": registry.list_specs()})


class ToolInvokeView(APIView):
    """Invoke one tool through the full guardrail chokepoint.

    Every exception below is mapped to a status code *and* still produces an audit
    row, because the chokepoint audits in a finally block.
    """

    permission_classes = [IsServiceDeskOrAbove]

    def post(self, request, name):
        body = request.data if isinstance(request.data, dict) else {}
        args = body.get("args") or {}
        if not isinstance(args, dict):
            return _error("invalid_arguments", "'args' must be an object.", status.HTTP_400_BAD_REQUEST)

        ctx = build_context(
            request.user,
            dry_run=bool(body.get("dry_run", False)),
            organization=getattr(request, "organization", None),
        )

        try:
            result = execute_tool(name, args, ctx)
        except ApprovalRequired as exc:
            return _error(exc.code, str(exc), status.HTTP_409_CONFLICT)
        except ToolDenied as exc:
            return _error(exc.code, str(exc), status.HTTP_403_FORBIDDEN)
        except ToolNotFound as exc:
            return _error(exc.code, str(exc), status.HTTP_404_NOT_FOUND)
        except ToolValidationError as exc:
            return _error(exc.code, str(exc), status.HTTP_400_BAD_REQUEST)
        except ToolExecutionError as exc:
            logger.warning("tool %s failed: %s", name, exc)
            return _error(exc.code, str(exc), status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"tool": name, "trace_id": ctx.trace_id, "result": result})


class ToolPolicyListView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request):
        return Response(ToolPolicySerializer(ToolPolicy.objects.all(), many=True).data)


class ToolPolicyDetailView(APIView):
    """Edit one tool's policy. Invalidates the cache so the change takes effect now."""

    permission_classes = [IsAdmin]

    def patch(self, request, tool_name):
        # A tool registered after the last seed must still be editable. Requiring a
        # pre-existing row made the toggle 404 for exactly the tools nobody had
        # configured yet — the ones you most want to turn off.
        if registry.try_get_tool(tool_name) is None:
            return _error(
                "tool_not_found",
                f"Tool '{tool_name}' is not in the registry.",
                status.HTTP_404_NOT_FOUND,
            )
        row, _ = ToolPolicy.objects.get_or_create(tool_name=tool_name)
        serializer = ToolPolicySerializer(row, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        policy.invalidate_policy_cache(tool_name)
        return Response(serializer.data)


class KillSwitchView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request):
        return Response({"state": killswitch.get_state().value})

    def post(self, request):
        raw = (request.data or {}).get("state", "")
        try:
            state = KillSwitchState(raw)
        except ValueError:
            return _error(
                "invalid_state",
                "state must be one of: open, paused, halted.",
                status.HTTP_400_BAD_REQUEST,
            )
        killswitch.set_state(state)
        return Response({"state": state.value})


class ToolInvocationListView(APIView):
    """The audit trail, including denied attempts."""

    permission_classes = [IsServiceDeskOrAbove]

    def get(self, request):
        queryset = ToolInvocation.objects.all()
        organization = getattr(request, "organization", None)
        if organization is not None:
            queryset = queryset.filter(organization=organization)
        tool_name = request.query_params.get("tool")
        outcome = request.query_params.get("outcome")
        if tool_name:
            queryset = queryset.filter(tool_name=tool_name)
        if outcome:
            queryset = queryset.filter(outcome=outcome)
        paginator = DefaultPagination()
        page = paginator.paginate_queryset(queryset, request, view=self)
        return paginator.get_paginated_response(ToolInvocationSerializer(page, many=True).data)


class ApprovalListView(APIView):
    """Pending approvals by default; pass ?status= to see decided ones."""

    permission_classes = [IsServiceDeskOrAbove]

    def get(self, request):
        approvals.expire_stale()
        queryset = ApprovalRequest.objects.select_related("decided_by", "run")
        organization = getattr(request, "organization", None)
        if organization is not None:
            queryset = queryset.filter(run__ticket__organization=organization)
        wanted = request.query_params.get("status")
        if wanted:
            queryset = queryset.filter(status=wanted)
        else:
            queryset = queryset.filter(status=ApprovalRequest.Status.PENDING)
        paginator = DefaultPagination()
        page = paginator.paginate_queryset(queryset, request, view=self)
        return paginator.get_paginated_response(ApprovalRequestSerializer(page, many=True).data)


class ApprovalDecisionView(APIView):
    """Approve or reject one request.

    Approving enqueues the resumption on commit, so the worker cannot execute a
    write whose approval row is not yet visible.
    """

    permission_classes = [IsServiceDeskOrAbove]

    def post(self, request, pk, decision):
        if decision not in {"approve", "reject"}:
            return _error(
                "invalid_decision", "decision must be 'approve' or 'reject'.", status.HTTP_400_BAD_REQUEST
            )

        record = get_object_or_404(ApprovalRequest, pk=pk)
        payload = ApprovalDecisionSerializer(data=request.data or {})
        payload.is_valid(raise_exception=True)
        note = payload.validated_data.get("note", "")

        # You may only approve what you could have done yourself: the approver's
        # role must satisfy the tool's own allowlist.
        tool = registry.try_get_tool(record.tool_name)
        if tool is not None and tool.allowed_roles is not None:
            if request.user.role not in tool.allowed_roles:
                return _error(
                    "forbidden",
                    f"Role '{request.user.role}' may not decide on '{record.tool_name}'.",
                    status.HTTP_403_FORBIDDEN,
                )

        try:
            if decision == "approve":
                record = approvals.approve(record, request.user, note)
                run_id, approval_id = record.run_id, record.pk

                def _enqueue() -> None:
                    from apps.agent.enqueue import enqueue_resume

                    enqueue_resume(run_id, approval_id)

                transaction.on_commit(_enqueue)
            else:
                record = approvals.reject(record, request.user, note)
                from apps.agent.services import reject_pending

                reject_pending(
                    record.run,
                    note=note,
                    actor=getattr(request.user, "email", ""),
                )
        except approvals.SelfApprovalDenied as exc:
            return _error("self_approval_denied", str(exc), status.HTTP_403_FORBIDDEN)
        except ValueError as exc:
            return _error("invalid_state", str(exc), status.HTTP_409_CONFLICT)

        return Response(ApprovalRequestSerializer(record).data)
