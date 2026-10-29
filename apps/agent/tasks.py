"""Celery entry point for an agent run."""
from __future__ import annotations

import logging

from celery import shared_task

from .models import AgentRun

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=0, name="agent.run_agent_for_ticket")
def run_agent_for_ticket(self, run_id: int) -> dict:
    """Execute one queued run. Never retries: a failed run is a visible failure."""
    from .services import execute_run

    run = AgentRun.objects.filter(pk=run_id).first()
    if run is None:
        logger.warning("agent run %s no longer exists", run_id)
        return {"ok": False, "reason": "run_not_found"}

    execute_run(run)
    return {"ok": run.status == AgentRun.Status.FINISHED, "status": run.status}


@shared_task(bind=True, max_retries=0, name="agent.resume_agent_run")
def resume_agent_run(self, run_id: int, approval_id: int) -> dict:
    """Resume a paused run after a human approved one specific step."""
    from apps.guardrails.models import ApprovalRequest

    from .services import resume_run

    run = AgentRun.objects.filter(pk=run_id).first()
    approval = ApprovalRequest.objects.filter(pk=approval_id).first()
    if run is None or approval is None:
        logger.warning("cannot resume run=%s approval=%s (missing)", run_id, approval_id)
        return {"ok": False, "reason": "not_found"}

    resume_run(run, approval)
    return {"ok": run.status == AgentRun.Status.FINISHED, "status": run.status}
