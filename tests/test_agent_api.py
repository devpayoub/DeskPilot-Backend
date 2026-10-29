"""Ticket and run endpoints."""
from __future__ import annotations

import pytest
from django.test import override_settings

from apps.agent.models import AgentRun
from apps.agent.tasks import run_agent_for_ticket
from apps.helpdesk.models import Ticket

pytestmark = pytest.mark.django_db


@pytest.fixture
def ticket() -> Ticket:
    from apps.helpdesk.services import create_ticket

    return create_ticket(
        subject="Printer offline",
        body="The office printer shows offline on my laptop.",
        requester_email="user@example.com",
        requester_name="Sam User",
        device_hostname="DESK-01",
    )


@pytest.fixture
def inline_celery(monkeypatch):
    """Run the enqueued task inline instead of relying on broker config."""
    monkeypatch.setattr(
        run_agent_for_ticket,
        "delay",
        lambda run_id: run_agent_for_ticket.apply(args=[run_id]),
    )


# ---------------------------------------------------------------------------
# Tickets
# ---------------------------------------------------------------------------
def test_creating_a_ticket_assigns_a_number_and_first_message(desk_client):
    response = desk_client.post(
        "/api/v1/tickets/",
        {
            "subject": "VPN keeps dropping",
            "body": "It disconnects every few minutes.",
            "requester_email": "user@example.com",
            "requester_name": "Sam User",
            "device_hostname": "DESK-02",
        },
        format="json",
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["number"].startswith("T-")
    assert len(payload["messages"]) == 1
    assert payload["messages"][0]["author_type"] == "requester"


def test_ticket_list_and_detail(desk_client, ticket):
    listing = desk_client.get("/api/v1/tickets/")
    assert listing.status_code == 200
    assert len(listing.json()["results"]) == 1

    detail = desk_client.get(f"/api/v1/tickets/{ticket.pk}/")
    assert detail.status_code == 200
    assert detail.json()["subject"] == "Printer offline"
    assert detail.json()["latest_run_id"] is None


def test_ticket_endpoints_require_authentication(api_client, ticket):
    assert api_client.get("/api/v1/tickets/").status_code == 401
    assert api_client.get(f"/api/v1/tickets/{ticket.pk}/").status_code == 401


# ---------------------------------------------------------------------------
# Triggering a run
# ---------------------------------------------------------------------------
def test_requester_may_not_trigger_the_agent(requester_client, ticket):
    response = requester_client.post(f"/api/v1/tickets/{ticket.pk}/run/", {}, format="json")

    assert response.status_code == 403
    assert AgentRun.objects.count() == 0


@override_settings(LLM_API_KEY="")
def test_triggering_a_run_queues_it_and_fails_cleanly_without_an_api_key(
    desk_client, ticket, inline_celery, django_capture_on_commit_callbacks
):
    # The key is overridden rather than assumed absent: a test that only passes on
    # a machine without credentials silently starts calling a paid API the moment
    # someone configures one — which is exactly what happened here.
    with django_capture_on_commit_callbacks(execute=True):
        response = desk_client.post(f"/api/v1/tickets/{ticket.pk}/run/", {}, format="json")

    assert response.status_code == 202
    run = AgentRun.objects.get(pk=response.json()["id"])

    # No key: the run must fail loudly and visibly, not hang in "running" forever.
    assert run.status == AgentRun.Status.FAILED
    assert "LLM not configured" in run.error
    assert run.finished_at is not None

    ticket.refresh_from_db()
    assert ticket.status == Ticket.Status.NEW, "a failed run hands the ticket back"


def test_client_request_id_makes_triggering_idempotent(
    desk_client, ticket, inline_celery, django_capture_on_commit_callbacks
):
    payload = {"client_request_id": "req-abc-123"}

    with django_capture_on_commit_callbacks(execute=True):
        first = desk_client.post(f"/api/v1/tickets/{ticket.pk}/run/", payload, format="json")
        second = desk_client.post(f"/api/v1/tickets/{ticket.pk}/run/", payload, format="json")

    assert first.status_code == 202
    assert first.json()["id"] == second.json()["id"]
    assert AgentRun.objects.count() == 1, "a retried request must not start a second run"


def test_run_detail_includes_the_trace(desk_client, ticket):
    run = AgentRun.objects.create(
        ticket=ticket,
        objective="OBJECTIVE: test",
        status=AgentRun.Status.FINISHED,
        iterations=2,
        tool_calls=1,
        prompt_tokens=100,
        completion_tokens=20,
    )
    run.steps.create(
        step_no=1,
        thought="check disk",
        tool_name="get_disk_health",
        tool_risk="READ",
        validated_args={},
        result={"ok": True},
        status="ok",
        latency_ms=12,
    )

    response = desk_client.get(f"/api/v1/runs/{run.pk}/")

    assert response.status_code == 200
    payload = response.json()
    assert payload["iterations"] == 2
    assert len(payload["steps"]) == 1
    assert payload["steps"][0]["tool_name"] == "get_disk_health"


def test_run_steps_endpoint(desk_client, ticket):
    run = AgentRun.objects.create(ticket=ticket, objective="o", status=AgentRun.Status.QUEUED)
    run.steps.create(step_no=1, tool_name="get_system_health", status="ok")

    response = desk_client.get(f"/api/v1/runs/{run.pk}/steps/")

    assert response.status_code == 200
    assert response.json()[0]["tool_name"] == "get_system_health"


# ---------------------------------------------------------------------------
# Visibility: a requester sees their own ticket, and nothing else
# ---------------------------------------------------------------------------
def test_a_requester_sees_only_the_tickets_they_raised(requester_client, requester_user):
    """`tickets/` used to return every ticket in the system to any caller."""
    from apps.helpdesk.services import create_ticket

    mine = create_ticket(subject="Mine", body="b", requester=requester_user)
    create_ticket(subject="Someone else's", body="b")

    response = requester_client.get("/api/v1/tickets/")

    assert response.status_code == 200
    assert [row["id"] for row in response.json()["results"]] == [mine.pk]


def test_a_requester_cannot_open_someone_elses_ticket(requester_client, requester_user):
    from apps.helpdesk.services import create_ticket

    create_ticket(subject="Mine", body="b", requester=requester_user)
    theirs = create_ticket(subject="Theirs", body="b")

    assert requester_client.get(f"/api/v1/tickets/{theirs.pk}/").status_code == 404


def test_a_requester_cannot_read_someone_elses_trace(requester_client, requester_user):
    """A trace carries the ticket body and tool output — it follows the ticket."""
    from apps.helpdesk.services import create_ticket

    create_ticket(subject="Mine", body="b", requester=requester_user)
    theirs = create_ticket(subject="Theirs", body="b")
    run = AgentRun.objects.create(ticket=theirs, objective="o", status=AgentRun.Status.RUNNING)

    assert requester_client.get(f"/api/v1/runs/{run.pk}/").status_code == 404
    assert requester_client.get(f"/api/v1/runs/{run.pk}/steps/").status_code == 404
    assert requester_client.post(f"/api/v1/runs/{run.pk}/ws-ticket/").status_code == 404


def test_the_service_desk_still_sees_the_whole_queue(desk_client, requester_user):
    from apps.helpdesk.services import create_ticket

    create_ticket(subject="Mine", body="b", requester=requester_user)
    create_ticket(subject="Theirs", body="b")

    response = desk_client.get("/api/v1/tickets/")

    assert response.status_code == 200
    assert len(response.json()["results"]) == 2
