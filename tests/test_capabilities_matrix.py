"""The permission grid, asserted end to end instead of one incident at a time.

Three things are pinned here, and each exists because it was once untrue:

1. **Every endpoint is annotated.** Before this, a new view inheriting DRF's
   default ``IsAuthenticated`` was an open door — which is how ``/evals/runs/`` and
   the directory ended up readable by a *requester*, while the console's own map
   called them administrator-only. The only defence was a reviewer noticing. Now a
   test notices.
2. **Every capability in the vocabulary is enforced by something.** A capability
   declared and never gated on is a promise the API does not keep.
3. **The HTTP outcome agrees with the map for every role.** The map is what the
   console renders; if the two disagree, the UI is lying about what a person may do.

The grid's expectation is read out of the same map the server serves, so the test
fails when the *enforcement* drifts from it rather than when either is edited — the
comparison is against the vocabulary, not against a second copy of the answers.
"""
from __future__ import annotations

import pytest
from django.urls import get_resolver
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import Role
from apps.common.capabilities import ROLE_CAPABILITIES, Capability, role_has_capability
from apps.helpdesk.services import create_ticket
from apps.organizations.models import Membership, Organization
from tests.factories import make_user

pytestmark = pytest.mark.django_db

# Endpoints that are *meant* to be reachable without a capability: the public
# liveness probe, the auth round-trip, and the invitation page an invitee opens
# before they have a session. Adding to this list is a security decision.
PUBLIC_ENDPOINTS = {
    "health",
    "auth-login",
    "auth-logout",
    "auth-me",
    "token-obtain",
    "token-refresh",
    "invite-accept",
    "schema",
    "docs",
    # The generated API reference. Renders the schema; every endpoint inside it
    # still has to authorise the caller on its own.
    "swagger-ui",
}

ALL_ROLES = [Role.REQUESTER, Role.SERVICE_DESK, Role.TECHNICIAN, Role.ADMIN]


def _client_for(user) -> APIClient:
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(user).access_token}")
    return client


def _api_views() -> dict[str, type[APIView]]:
    """Every class-based view the URLconf actually routes to.

    Walked from the resolver rather than a hardcoded list on purpose: an endpoint
    nobody remembered to list is exactly the hole this test exists to catch.
    """
    found: dict[str, type[APIView]] = {}

    def walk(patterns):
        for pattern in patterns:
            if hasattr(pattern, "url_patterns"):
                walk(pattern.url_patterns)
                continue
            callback = getattr(pattern, "callback", None)
            cls = getattr(callback, "cls", None)
            if cls is not None and isinstance(cls, type) and issubclass(cls, APIView):
                found[pattern.name or str(pattern.pattern)] = cls

    walk(get_resolver().url_patterns)
    return found


def _declared_capabilities(cls) -> set[str]:
    declared: set[str] = set()
    single = getattr(cls, "capability", None)
    if single:
        declared.add(str(single))
    for value in (getattr(cls, "capabilities", None) or {}).values():
        declared.add(str(value))
    return declared


# ---------------------------------------------------------------------------
# Structure: no forgotten doors
# ---------------------------------------------------------------------------


def test_every_endpoint_declares_a_capability_or_is_publicly_listed():
    unguarded = sorted(
        name
        for name, cls in _api_views().items()
        if name not in PUBLIC_ENDPOINTS and not _declared_capabilities(cls)
    )

    assert not unguarded, (
        f"{unguarded} inherit DRF's default IsAuthenticated, so any signed-in user "
        "of any role can reach them. Declare a `capability` (or `capabilities` per "
        "method), or — if it truly must be public — add it to PUBLIC_ENDPOINTS."
    )


def test_every_capability_in_the_vocabulary_is_enforced():
    enforced: set[str] = set()
    for cls in _api_views().values():
        enforced |= _declared_capabilities(cls)

    named = {str(capability) for capability in Capability}
    unused = sorted(named - enforced)

    assert not unused, f"declared but never gated on: {unused}"


def test_the_ladder_is_cumulative():
    """Nobody loses a power by being promoted."""
    for lower, higher in zip(ALL_ROLES, ALL_ROLES[1:]):
        held = set(ROLE_CAPABILITIES[lower])
        assert held <= set(ROLE_CAPABILITIES[higher]), f"{higher} lost {held - set(ROLE_CAPABILITIES[higher])}"


# ---------------------------------------------------------------------------
# The grid: role x endpoint
# ---------------------------------------------------------------------------

GRID = [
    ("get", "/api/v1/tickets/", Capability.TICKET_READ),
    ("get", "/api/v1/stats/", Capability.USAGE_READ),
    ("get", "/api/v1/evals/runs/", Capability.EVAL_READ),
    ("get", "/api/v1/tools/", Capability.TOOL_READ),
    ("post", "/api/v1/tools/get_disk_health/invoke/", Capability.TOOL_INVOKE),
    ("get", "/api/v1/directory/employees/", Capability.DIRECTORY_READ),
    ("get", "/api/v1/directory/devices/", Capability.DIRECTORY_READ),
    ("get", "/api/v1/guardrails/approvals/", Capability.APPROVAL_READ),
    ("get", "/api/v1/guardrails/invocations/", Capability.AUDIT_READ),
    ("get", "/api/v1/guardrails/policies/", Capability.POLICY_WRITE),
    ("get", "/api/v1/guardrails/killswitch/", Capability.USAGE_READ),
    ("post", "/api/v1/guardrails/killswitch/", Capability.KILL_SWITCH_WRITE),
]


def _call(client: APIClient, method: str, path: str):
    body = None
    if method == "post":
        body = {"state": "open"} if path.endswith("killswitch/") else {"args": {}}
    if body is None:
        return getattr(client, method)(path)
    return getattr(client, method)(path, body, format="json")


@pytest.mark.parametrize("role", ALL_ROLES)
@pytest.mark.parametrize("method,path,capability", GRID)
def test_http_outcome_agrees_with_the_capability_map(method, path, capability, role, api_fake_adapters):
    response = _call(_client_for(make_user(f"{role.lower()}@grid.test", role)), method, path)
    allowed = role_has_capability(role, capability)

    if allowed:
        assert response.status_code != 403, (
            f"{role} holds '{capability}' but was refused {method.upper()} {path}: "
            f"{response.data if hasattr(response, 'data') else ''}"
        )
    else:
        assert response.status_code == 403, f"{method.upper()} {path} is open to {role}"
        assert response.json()["error"]["code"] == "permission_denied"
        assert capability in response.json()["error"]["message"]


def test_a_requester_can_still_raise_their_own_ticket():
    """The product's front door, kept open on purpose.

    A requester posting one is how a ticket exists at all, so the endpoint cannot
    gate on a capability. What it does instead is refuse to believe the body about
    *who* the ticket belongs to: the requester is forced to the caller, so a requester
    cannot file one as somebody else. Raising a ticket on another person's behalf is
    a service-desk act, and the view only honours a supplied identity at that rank.
    """
    requester = make_user("me@grid.test", Role.REQUESTER)
    client = _client_for(requester)

    response = client.post(
        "/api/v1/tickets/",
        {"subject": "No wifi", "body": "Cannot connect", "requester_email": "someone.else@acme.test"},
        format="json",
    )

    assert response.status_code == 201
    assert response.json()["requester_email"] == "me@grid.test", (
        "a requester must not be able to file a ticket as another person"
    )


def test_triggering_a_run_starts_at_the_technician():
    ticket = create_ticket(subject="Laptop won't boot", body="Black screen")

    for role in ALL_ROLES:
        response = _client_for(make_user(f"run-{role.lower()}@grid.test", role)).post(
            f"/api/v1/tickets/{ticket.pk}/run/", {}, format="json"
        )
        expected = 202 if role_has_capability(role, Capability.RUN_TRIGGER) else 403
        assert response.status_code == expected, f"{role} triggering a run"


def test_deciding_an_approval_starts_at_the_technician(monkeypatch):
    """Reading the queue is not the same as signing off on it."""
    from datetime import timedelta

    from django.utils import timezone

    from apps.agent.models import AgentRun
    from apps.guardrails import approvals
    from apps.guardrails.models import ApprovalRequest

    # The state machine and the self-approval guard have their own suite; this test
    # is about who may reach the door at all.
    monkeypatch.setattr(approvals, "approve", lambda record, user, note="": record)

    run = AgentRun.objects.create(
        ticket=create_ticket(subject="Reset a password", body="Please reset it"),
        objective="OBJECTIVE: reset it",
    )
    record = ApprovalRequest.objects.create(
        run=run,
        # Not a registered tool: the per-tool allowlist is that suite's business,
        # this grid is about who may reach the endpoint.
        tool_name="grid_unregistered_tool",
        risk_class="WRITE",
        args_hash="sha256:abc",
        expires_at=timezone.now() + timedelta(minutes=10),
    )

    for role in ALL_ROLES:
        response = _client_for(make_user(f"decide-{role.lower()}@grid.test", role)).post(
            f"/api/v1/guardrails/approvals/{record.pk}/approve/", {"note": "ok"}, format="json"
        )
        if role_has_capability(role, Capability.APPROVAL_DECIDE):
            assert response.status_code == 200, role
        else:
            assert response.status_code == 403, f"{role} must not decide approvals"


# ---------------------------------------------------------------------------
# The map the console renders
# ---------------------------------------------------------------------------


def test_me_serves_the_map_the_api_enforces(desk_client):
    """One source of truth.

    The console used to keep its own copy of this table in TypeScript, and the two
    drifted until endpoints the table called admin-only were wide open. Now the
    client is handed the answer the server is enforcing.
    """
    body = desk_client.get("/api/v1/auth/me/").json()
    served = body["role_capabilities"]

    assert set(served) == {str(role) for role in Role}
    for role, capabilities in ROLE_CAPABILITIES.items():
        assert served[str(role)] == [str(capability) for capability in capabilities]

    desk = set(served[str(Role.SERVICE_DESK)])
    assert "member:read" in desk, "triage needs to know who is in the account"
    assert "member:manage" not in desk, "adding people is not a service-desk power"


# ---------------------------------------------------------------------------
# Inside a real account: departments and members
# ---------------------------------------------------------------------------


def _join(user, organization, role):
    return Membership.objects.create(
        user=user, organization=organization, role=role, accepted_at=timezone.now()
    )


@pytest.fixture
def matrix_org(db) -> Organization:
    return Organization.objects.create(name="Matrix Support", slug="matrix")


@pytest.mark.parametrize("role", ALL_ROLES)
def test_roster_reads_start_at_the_service_desk_and_writes_at_the_admin(matrix_org, role):
    user = make_user(f"{role.lower()}@matrix.test", role)
    _join(user, matrix_org, role)
    client = _client_for(user)

    reads_members = role_has_capability(role, Capability.MEMBER_READ)
    response = client.get("/api/v1/org/members/")
    assert response.status_code == (200 if reads_members else 403), f"{role} reading the roster"

    reads_departments = role_has_capability(role, Capability.ORG_READ)
    response = client.get("/api/v1/org/departments/")
    assert response.status_code == (200 if reads_departments else 403), f"{role} reading departments"

    writes = role_has_capability(role, Capability.MEMBER_MANAGE)
    response = client.post(
        "/api/v1/org/members/",
        {"email": f"new-{role.lower()}@matrix.test", "role": Role.REQUESTER},
        format="json",
    )
    assert response.status_code == (201 if writes else 403), f"{role} adding a member"

    response = client.post(
        "/api/v1/org/departments/", {"name": f"Desk {role}", "code": f"D{role[:3]}"}, format="json"
    )
    assert response.status_code == (201 if role_has_capability(role, Capability.DEPARTMENT_MANAGE) else 403)


def test_a_technician_cannot_approve_another_account_s_write(matrix_org):
    """Capability says *what* you may do; tenancy still says *where*.

    Approval ids are sequential integers, so the unscoped lookup was reachable by
    guessing: a technician in one account could approve a write queued in another.
    """
    from datetime import timedelta

    from django.utils import timezone

    from apps.agent.models import AgentRun
    from apps.guardrails.models import ApprovalRequest

    elsewhere = Organization.objects.create(name="Globex Desk", slug="globex-desk")
    tech = make_user("tech@matrix.test", Role.TECHNICIAN)
    _join(tech, matrix_org, Role.TECHNICIAN)

    foreign_run = AgentRun.objects.create(
        ticket=create_ticket(subject="Globex laptop", body="Broken", organization=elsewhere),
        objective="OBJECTIVE: fix it",
    )
    record = ApprovalRequest.objects.create(
        run=foreign_run,
        tool_name="grid_unregistered_tool",
        risk_class="WRITE",
        args_hash="sha256:def",
        expires_at=timezone.now() + timedelta(minutes=10),
    )

    response = _client_for(tech).post(
        f"/api/v1/guardrails/approvals/{record.pk}/approve/", {"note": "sure"}, format="json"
    )

    assert response.status_code == 404
    record.refresh_from_db()
    assert record.status == ApprovalRequest.Status.PENDING, "not silently decided by another account"
