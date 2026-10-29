"""The live trace socket: authentication, authorisation and step delivery."""
from __future__ import annotations

import asyncio

import pytest
from channels.layers import get_channel_layer
from channels.testing import WebsocketCommunicator
from rest_framework_simplejwt.tokens import RefreshToken

from apps.agent.models import AgentRun
from apps.agent.ws_tokens import mint_trace_ticket
from config.asgi import application

pytestmark = pytest.mark.django_db

ORIGIN = [(b"origin", b"http://testserver")]


@pytest.fixture
def run(ticket_for_trace) -> AgentRun:
    return AgentRun.objects.create(
        ticket=ticket_for_trace, objective="o", status=AgentRun.Status.RUNNING
    )


@pytest.fixture
def ticket_for_trace(db):
    from apps.helpdesk.services import create_ticket

    return create_ticket(subject="Trace test", body="body")


def _connect(path: str) -> bool:
    async def scenario():
        communicator = WebsocketCommunicator(application, path, headers=ORIGIN)
        connected, _ = await communicator.connect()
        await communicator.disconnect()
        return connected

    return asyncio.run(scenario())


def test_socket_without_a_token_is_rejected(run):
    assert _connect(f"/ws/runs/{run.pk}/") is False


def test_socket_with_an_invalid_token_is_rejected(run):
    assert _connect(f"/ws/runs/{run.pk}/?token=not-a-jwt") is False


def test_a_session_access_token_is_not_enough(run, desk_user):
    """A general-purpose token must not open a trace.

    The token travels in the query string, so accepting the session token here
    would put a long-lived, whole-API credential into proxy logs.
    """
    access = str(RefreshToken.for_user(desk_user).access_token)

    assert _connect(f"/ws/runs/{run.pk}/?token={access}") is False


def test_a_ticket_for_another_run_is_rejected(run, desk_user):
    """Without the run check, anyone could subscribe to anyone's trace."""
    other_ticket = mint_trace_ticket(desk_user, run.pk + 1)

    assert _connect(f"/ws/runs/{run.pk}/?token={other_ticket}") is False


def test_a_valid_ticket_connects_and_receives_steps(run, desk_user):
    ticket = mint_trace_ticket(desk_user, run.pk)

    async def scenario():
        communicator = WebsocketCommunicator(
            application, f"/ws/runs/{run.pk}/?token={ticket}", headers=ORIGIN
        )
        connected, _ = await communicator.connect()
        assert connected is True

        hello = await communicator.receive_json_from()
        assert hello["type"] == "connected"

        # Send to the group the consumer joined, exactly as the run does.
        layer = get_channel_layer()
        await layer.group_send(
            f"run.{run.pk}",
            {
                "type": "run.step",
                "payload": {
                    "type": "run.step",
                    "step_no": 1,
                    "tool": "get_disk_health",
                    "status": "ok",
                },
            },
        )

        message = await communicator.receive_json_from()
        await communicator.disconnect()
        return message

    message = asyncio.run(scenario())
    assert message["type"] == "run.step"
    assert message["step_no"] == 1
    assert message["tool"] == "get_disk_health"


# ---------------------------------------------------------------------------
# The ticket endpoint
# ---------------------------------------------------------------------------
def test_minting_a_ticket_requires_authentication(api_client, run):
    assert api_client.post(f"/api/v1/runs/{run.pk}/ws-ticket/").status_code == 401


def test_the_ticket_endpoint_binds_the_token_to_the_run(run, technician_client):
    response = technician_client.post(f"/api/v1/runs/{run.pk}/ws-ticket/")

    assert response.status_code == 200
    body = response.json()
    assert body["run"] == run.pk
    assert body["expires_in"] == 60

    # And the token it returns actually works.
    assert _connect(f"/ws/runs/{run.pk}/?token={body['ticket']}") is True
