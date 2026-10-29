"""Background execution for agent runs.

The browser must be able to navigate away and come back to a run that kept going.
Two paths:

* **A broker is configured** (Redis/RabbitMQ) — hand off to Celery, which is the
  production answer and survives a process restart.
* **No broker** (the usual local setup) — run in a plain background thread. It still
  outlives the HTTP request and the browser tab, which is what an operator expects
  from a button labelled "Run agent". It does *not* survive a server restart; that
  needs the broker path.

Either way the request returns immediately and the UI polls.
"""
from __future__ import annotations

import logging
import threading

from django.conf import settings
from django.db import connections

logger = logging.getLogger(__name__)


def _broker_is_real() -> bool:
    url = str(getattr(settings, "CELERY_BROKER_URL", "") or "")
    return url.startswith(("redis://", "rediss://", "amqp://", "sqs://"))


def _use_task_queue() -> bool:
    """Eager mode keeps Celery in the path so tests can intercept the enqueue."""
    return getattr(settings, "CELERY_TASK_ALWAYS_EAGER", False) or _broker_is_real()


def _spawn(target, *args) -> None:
    def _wrapper() -> None:
        try:
            target(*args)
        except Exception:  # a background failure must never take the server down
            logger.exception("background agent task failed")
        finally:
            # Threads get their own DB connections; close them or the pool leaks.
            connections.close_all()

    threading.Thread(target=_wrapper, name="deskpilot-agent", daemon=False).start()


def enqueue_run(run_id: int) -> None:
    """Start an agent run without blocking the request."""
    from .tasks import run_agent_for_ticket

    if _use_task_queue():
        run_agent_for_ticket.delay(run_id)
    else:
        _spawn(lambda: run_agent_for_ticket.apply(args=[run_id]))


def enqueue_resume(run_id: int, approval_id: int) -> None:
    """Resume a paused run after an approval, same background rules."""
    from .tasks import resume_agent_run

    if _use_task_queue():
        resume_agent_run.delay(run_id, approval_id)
    else:
        _spawn(lambda: resume_agent_run.apply(args=[run_id, approval_id]))
