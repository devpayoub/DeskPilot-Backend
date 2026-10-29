"""HTTP surface: the catalog, the invoke endpoint, and the audit read-back."""
from __future__ import annotations

import pytest

from apps.guardrails.models import ToolInvocation, ToolPolicy

pytestmark = pytest.mark.django_db

INVOKE = "/api/v1/tools/{name}/invoke/"


def test_health_is_public(api_client):
    response = api_client.get("/api/v1/health/")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["tools"] >= 3


def test_tool_list_requires_authentication(api_client):
    assert api_client.get("/api/v1/tools/").status_code == 401


def test_tool_list_exposes_the_catalog(desk_client):
    response = desk_client.get("/api/v1/tools/")

    assert response.status_code == 200
    names = {tool["name"] for tool in response.json()["tools"]}
    assert {"get_system_health", "get_disk_health", "list_services"} <= names

    disk = next(t for t in response.json()["tools"] if t["name"] == "get_disk_health")
    assert disk["risk_class"] == "READ"
    assert disk["requires_approval"] is False


def test_requester_may_not_invoke_tools(requester_client, api_fake_adapters):
    response = requester_client.post(INVOKE.format(name="get_disk_health"), {"args": {}}, format="json")

    assert response.status_code == 403
    assert ToolInvocation.objects.count() == 0, "rejected before the chokepoint runs"


def test_service_desk_can_invoke_a_read_tool(desk_client, api_fake_adapters):
    response = desk_client.post(INVOKE.format(name="get_disk_health"), {"args": {}}, format="json")

    assert response.status_code == 200
    body = response.json()
    assert body["tool"] == "get_disk_health"
    assert body["result"]["any_low_space"] is True
    assert body["trace_id"]


def test_unknown_tool_returns_404(desk_client, api_fake_adapters):
    response = desk_client.post(INVOKE.format(name="ghost_tool"), {"args": {}}, format="json")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "tool_not_found"


def test_bad_arguments_return_400(desk_client, api_fake_adapters):
    response = desk_client.post(
        INVOKE.format(name="list_services"), {"args": {"state": "exploded"}}, format="json"
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_arguments"


def test_non_object_args_return_400(desk_client, api_fake_adapters):
    response = desk_client.post(
        INVOKE.format(name="get_disk_health"), {"args": ["nope"]}, format="json"
    )

    assert response.status_code == 400


def test_audit_endpoint_reads_back_the_invocation(desk_client, api_fake_adapters):
    desk_client.post(INVOKE.format(name="get_disk_health"), {"args": {}}, format="json")

    response = desk_client.get("/api/v1/guardrails/invocations/")

    assert response.status_code == 200
    rows = response.json()["results"]
    assert len(rows) == 1
    assert rows[0]["tool_name"] == "get_disk_health"
    assert rows[0]["outcome"] == "ok"
    assert rows[0]["is_denial"] is False


def test_kill_switch_requires_admin(desk_client):
    response = desk_client.post(
        "/api/v1/guardrails/killswitch/", {"state": "halted"}, format="json"
    )
    assert response.status_code == 403


def test_admin_halts_and_invocations_are_then_denied(admin_client, desk_client, api_fake_adapters):
    halt = admin_client.post(
        "/api/v1/guardrails/killswitch/", {"state": "halted"}, format="json"
    )
    assert halt.status_code == 200
    assert halt.json()["state"] == "halted"

    denied = desk_client.post(INVOKE.format(name="get_disk_health"), {"args": {}}, format="json")
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "denied"

    # The refusal itself is auditable — that is the point of the trail.
    assert ToolInvocation.objects.filter(outcome="denied").count() == 1


def test_invalid_kill_switch_state_is_rejected(admin_client):
    response = admin_client.post(
        "/api/v1/guardrails/killswitch/", {"state": "banana"}, format="json"
    )
    assert response.status_code == 400


def test_admin_can_read_and_edit_policies(admin_client):
    # Build the row here rather than relying on the seed command having run.
    ToolPolicy.objects.create(tool_name="get_disk_health")

    listing = admin_client.get("/api/v1/guardrails/policies/")
    assert listing.status_code == 200
    assert len(listing.json()) == 1

    updated = admin_client.patch(
        "/api/v1/guardrails/policies/get_disk_health/", {"enabled": False}, format="json"
    )
    assert updated.status_code == 200
    assert updated.json()["enabled"] is False


def test_policy_for_an_unknown_row_returns_404(admin_client):
    response = admin_client.patch(
        "/api/v1/guardrails/policies/never_seeded/", {"enabled": False}, format="json"
    )
    assert response.status_code == 404


def test_a_tool_with_no_policy_row_can_still_be_disabled(admin_client):
    """The row is created on demand.

    Before this, toggling a tool that had never been seeded returned 404 — which
    is precisely the tool you would be trying to switch off.
    """
    from apps.guardrails.models import ToolPolicy

    ToolPolicy.objects.filter(tool_name="list_services").delete()

    response = admin_client.patch(
        "/api/v1/guardrails/policies/list_services/", {"enabled": False}, format="json"
    )

    assert response.status_code == 200
    assert response.json()["enabled"] is False
    assert ToolPolicy.objects.filter(tool_name="list_services", enabled=False).exists()


def test_an_unknown_tool_cannot_have_a_policy(admin_client):
    response = admin_client.patch(
        "/api/v1/guardrails/policies/not_a_tool/", {"enabled": False}, format="json"
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "tool_not_found"


def test_the_invocation_list_returns_the_console_envelope(desk_client):
    """The console's `Paginated<T>` needs page and page_size, not just count.

    DRF's default envelope omits them, and deriving them client-side from the URL
    is exactly the kind of duplicated logic that drifts.
    """
    response = desk_client.get("/api/v1/guardrails/invocations/?page_size=5")

    assert response.status_code == 200
    body = response.json()
    assert set(body) >= {"count", "next", "previous", "page", "page_size", "results"}
    assert body["page"] == 1
    assert body["page_size"] == 5
    assert isinstance(body["results"], list)
