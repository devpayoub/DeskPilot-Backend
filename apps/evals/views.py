"""Console-facing read endpoints: KPIs and eval history.

Kept deliberately thin — the console should not be doing arithmetic that the
backend can do once, correctly.
"""
from __future__ import annotations

from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.agent.models import AgentRun
from apps.common.pagination import DefaultPagination
from apps.guardrails.models import ApprovalRequest, ToolInvocation
from apps.helpdesk.models import Ticket

from .models import EvalRun


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))], 1)


class StatsView(APIView):
    """The numbers on the dashboard cards."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        tickets = Ticket.objects.filter(is_eval=False)
        touched = tickets.exclude(ai_disposition="")
        resolved = touched.filter(ai_disposition=Ticket.Disposition.AUTO_RESOLVED)

        durations = [
            (run.finished_at - run.started_at).total_seconds() * 1000
            for run in AgentRun.objects.exclude(started_at=None).exclude(finished_at=None)
        ]
        costs = [
            float(run.cost_usd)
            for run in AgentRun.objects.exclude(cost_usd=None)
        ]

        return Response(
            {
                "tickets_total": tickets.count(),
                "tickets_open": tickets.exclude(
                    status__in=[Ticket.Status.RESOLVED, Ticket.Status.CLOSED]
                ).count(),
                "agent_touched": touched.count(),
                "auto_resolved": resolved.count(),
                "auto_resolution_rate": round(resolved.count() / touched.count(), 3)
                if touched.count()
                else None,
                "pending_approvals": ApprovalRequest.objects.filter(
                    status=ApprovalRequest.Status.PENDING
                ).count(),
                # Denied attempts: the evidence that the guardrails are doing work.
                "blocked_actions": ToolInvocation.objects.filter(
                    outcome="denied"
                ).count(),
                "runs_total": AgentRun.objects.count(),
                "runs_failed": AgentRun.objects.filter(status=AgentRun.Status.FAILED).count(),
                "p95_latency_ms": _percentile(durations, 0.95),
                "mean_cost_usd": round(sum(costs) / len(costs), 6) if costs else None,
                "priced_runs": len(costs),
            }
        )


class EvalRunListView(APIView):
    """Recent eval runs, for the eval dashboard."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        paginator = DefaultPagination()
        runs = paginator.paginate_queryset(EvalRun.objects.order_by("-created_at"), request, view=self)
        return paginator.get_paginated_response(
            [
                {
                    "id": run.pk,
                    "mode": run.mode,
                    "model": run.model,
                    "case_count": run.case_count,
                    "passed_count": run.passed_count,
                    "gates_passed": run.gates_passed,
                    "metrics": run.metrics,
                    "notes": run.notes,
                    "duration_ms": run.duration_ms,
                    "created_at": run.created_at,
                }
                for run in runs
            ]
        )
