"""Ticket and agent-run endpoints."""
from __future__ import annotations

import logging

from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.models import Role, effective_role
from apps.common.pagination import DefaultPagination
from apps.common.permissions import IsServiceDeskOrAbove
from apps.helpdesk.models import Ticket
from apps.helpdesk.services import create_ticket

from .models import AgentRun
from .serializers import (
    AgentRunSerializer,
    AgentRunSummarySerializer,
    AgentStepSerializer,
    TicketCreateSerializer,
    TicketDetailSerializer,
    TicketListSerializer,
)
from .enqueue import enqueue_run
from .services import create_run
from .ws_tokens import WS_TICKET_LIFETIME_SECONDS, mint_trace_ticket

logger = logging.getLogger(__name__)


def _tickets_for(request):
    """Tickets this request may see.

    Two filters, and both matter. **Tenant**: only the organisation the caller is
    acting in. **Role**: a requester sees only what they raised; everyone at the
    service desk and above sees the queue.

    Enforced here rather than in each view because list, detail, run and trace all
    route through it — one forgotten ``.filter()`` would leak another account's
    ticket, or its tool output, to anyone who guessed an id.
    """
    queryset = Ticket.objects.filter(is_eval=False)

    organization = getattr(request, "organization", None)
    if organization is not None:
        queryset = queryset.filter(organization=organization)

    user = request.user
    if effective_role(user) == Role.REQUESTER:
        return queryset.filter(requester=user)
    return queryset


def _runs_for(request):
    """Runs follow their ticket: no ticket visibility, no trace visibility."""
    queryset = AgentRun.objects.all()

    organization = getattr(request, "organization", None)
    if organization is not None:
        queryset = queryset.filter(ticket__organization=organization)

    user = request.user
    if effective_role(user) == Role.REQUESTER:
        return queryset.filter(ticket__requester=user)
    return queryset


class TicketListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        queryset = _tickets_for(request)
        paginator = DefaultPagination()
        page = paginator.paginate_queryset(queryset, request, view=self)
        return paginator.get_paginated_response(TicketListSerializer(page, many=True).data)

    def post(self, request):
        serializer = TicketCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = dict(serializer.validated_data)

        # A requester raising a ticket is its requester. A desk user raising one on
        # someone's behalf is not, so the link stays null and the self-approval
        # guard correctly does not fire on the desk user.
        if effective_role(request.user) == Role.REQUESTER:
            data["requester"] = request.user
            if not data.get("requester_email"):
                data["requester_email"] = request.user.email
            if not data.get("requester_name"):
                data["requester_name"] = (
                    request.user.display_name or request.user.email
                )

        # Every ticket is stamped with the account it was raised in, so the
        # tenant filter in `_tickets_for` has something to filter on.
        data["organization"] = getattr(request, "organization", None)

        ticket = create_ticket(**data)
        return Response(
            TicketDetailSerializer(ticket).data, status=status.HTTP_201_CREATED
        )


class TicketDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        ticket = get_object_or_404(_tickets_for(request), pk=pk)
        return Response(TicketDetailSerializer(ticket).data)


class TicketRunView(APIView):
    """Queue an agent run for a ticket.

    Enqueued on commit, so a worker can never pick up a run whose ticket row has
    not been committed yet.
    """

    permission_classes = [IsServiceDeskOrAbove]

    def post(self, request, pk):
        ticket = get_object_or_404(_tickets_for(request), pk=pk)
        client_request_id = request.data.get("client_request_id") if request.data else None

        if client_request_id:
            existing = AgentRun.objects.filter(client_request_id=client_request_id).first()
            if existing is not None:
                # Idempotent replay: return the original run rather than starting a second.
                return Response(AgentRunSummarySerializer(existing).data)

        run = create_run(ticket, client_request_id=client_request_id)
        transaction.on_commit(lambda: enqueue_run(run.pk))
        return Response(
            AgentRunSummarySerializer(run).data, status=status.HTTP_202_ACCEPTED
        )


class RunListView(APIView):
    """Live runs, for the console's active-runs submenu.

    ``?status=active`` is the default because that is the only interesting case for
    an operator: what is happening right now.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        wanted = request.query_params.get("status", "active")
        queryset = _runs_for(request).select_related("ticket")

        if wanted == "active":
            queryset = queryset.filter(
                status__in=[
                    AgentRun.Status.QUEUED,
                    AgentRun.Status.RUNNING,
                    AgentRun.Status.AWAITING_APPROVAL,
                ]
            )
        elif wanted != "all":
            queryset = queryset.filter(status=wanted)

        return Response(
            [
                {
                    "id": run.pk,
                    "ticket_id": run.ticket_id,
                    "ticket_number": run.ticket.number,
                    "ticket_subject": run.ticket.subject,
                    "status": run.status,
                    "iterations": run.iterations,
                    "tool_calls": run.tool_calls,
                    "created_at": run.created_at,
                }
                for run in queryset[:25]
            ]
        )


class RunDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        run = get_object_or_404(_runs_for(request).prefetch_related("steps"), pk=pk)
        return Response(AgentRunSerializer(run).data)


class RunStepsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        run = get_object_or_404(_runs_for(request), pk=pk)
        return Response(AgentStepSerializer(run.steps.all(), many=True).data)


class RunWsTicketView(APIView):
    """Mint a short-lived ticket for this run's trace socket.

    The console cannot read its own access token — it lives in an httpOnly
    cookie — and a browser cannot send headers on a WebSocket handshake. Rather
    than expose the session token to JavaScript, this hands back one that is
    valid for 60 seconds against this single run and nothing else.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        run = get_object_or_404(_runs_for(request), pk=pk)
        return Response(
            {
                "ticket": mint_trace_ticket(request.user, run.pk),
                "run": run.pk,
                "expires_in": WS_TICKET_LIFETIME_SECONDS,
            }
        )
