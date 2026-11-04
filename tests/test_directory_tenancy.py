"""Two workspaces, one table: nothing in the directory may cross the line.

Every test here is a pair — one row in organisation A, one in organisation B, and a
caller who belongs to A. The assertion is always the same shape: A sees its own and
cannot see, find or spend B's. With only one tenant in the fixture, a query that
silently dropped its tenant filter would still pass, which is exactly how the leak
went unnoticed.
"""
from __future__ import annotations

import pytest
from django.db.utils import IntegrityError
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import CustomUser, Role
from apps.directory.adapters import DatabaseDirectory
from apps.directory.models import Device, DirectoryGroup, Employee, PasswordReset
from apps.directory.vault import retrieve_password, store_password
from apps.guardrails.context import build_context
from toolcore.errors import ToolExecutionError
from toolcore.execute import execute_tool

pytestmark = pytest.mark.django_db


def _client_for(user) -> APIClient:
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(user).access_token}")
    return client


def _employee(organization, sam: str, **overrides) -> Employee:
    fields = {
        "external_id": f"fake-{sam}",
        "sam": sam,
        "upn": f"{sam}@example.test",
        "display_name": sam.replace(".", " ").title(),
        "email": f"{sam}@example.test",
        "department": "IT",
        "title": "Technician",
        "locked_out": True,
        "bad_password_count": 4,
    }
    fields.update(overrides)
    return Employee.objects.create(organization=organization, **fields)


@pytest.fixture
def two_tenants(organization, other_organization):
    """Two employees per side plus a group name both tenants use."""
    insa = _employee(organization, "a.insaf", display_name="Ines Saf")
    bob = _employee(other_organization, "b.obrien", display_name="Bob Obrien")
    _employee(organization, "c.chen")
    Device.objects.create(organization=organization, hostname="DESK-A1", assigned_employee=insa)
    Device.objects.create(organization=other_organization, hostname="DESK-B1", assigned_employee=bob)
    DirectoryGroup.objects.create(organization=organization, name="VPN Users")
    DirectoryGroup.objects.create(organization=other_organization, name="VPN Users")
    return {"insa": insa, "bob": bob, "a": organization, "b": other_organization}


@pytest.fixture
def tech_in_a(technician_user, organization, join):
    join(technician_user, organization, Role.TECHNICIAN)
    return technician_user


# ---------------------------------------------------------------------------
# The adapter itself
# ---------------------------------------------------------------------------


def test_an_unbound_adapter_reads_nothing(two_tenants):
    """An adapter built without a tenant is empty rather than global.

    The fail-closed direction: forgetting to thread the organisation through has to
    lose data, not gain it.
    """
    assert DatabaseDirectory().lookup_user("a.insaf") is None
    assert DatabaseDirectory().lookup_user("b.obrien") is None


def test_the_adapter_only_resolves_people_in_its_own_tenant(two_tenants):
    directory = DatabaseDirectory(two_tenants["a"])

    assert directory.lookup_user("a.insaf")["sam"] == "a.insaf"
    assert directory.lookup_user("b.obrien") is None


def test_a_group_name_in_use_elsewhere_is_not_the_same_group(two_tenants):
    """Both tenants call their group "VPN Users"; the names must not merge."""
    a_members = {
        member["sam"] for member in DatabaseDirectory(two_tenants["a"]).get_group_membership("VPN Users")["members"]
    }
    b_members = {
        member["sam"] for member in DatabaseDirectory(two_tenants["b"]).get_group_membership("VPN Users")["members"]
    }

    assert DatabaseDirectory(two_tenants["a"]).get_group_membership("VPN Users")["group"] == "VPN Users"
    assert a_members.isdisjoint(b_members)


def test_another_tenants_account_cannot_be_written_to(two_tenants):
    directory = DatabaseDirectory(two_tenants["a"])

    with pytest.raises(ToolExecutionError):
        directory.unlock_account("b.obrien", dry_run=False)

    two_tenants["bob"].refresh_from_db()
    assert two_tenants["bob"].locked_out is True, "the other tenant's lockout must survive"


# ---------------------------------------------------------------------------
# Uniqueness moved inside the tenant
# ---------------------------------------------------------------------------


def test_two_organisations_may_share_a_sam(two_tenants):
    """`sam` is a corporate identifier, not a platform one."""
    _employee(two_tenants["b"], "a.insaf", display_name="Another Ines")

    assert Employee.objects.filter(sam="a.insaf").count() == 2


def test_a_duplicate_sam_inside_one_organisation_is_refused(two_tenants):
    with pytest.raises(IntegrityError):
        _employee(two_tenants["a"], "a.insaf")


def test_two_organisations_may_share_a_hostname(two_tenants):
    Device.objects.create(organization=two_tenants["a"], hostname="DESK-B1")

    assert Device.objects.filter(hostname="DESK-B1").count() == 2


# ---------------------------------------------------------------------------
# The HTTP surface
# ---------------------------------------------------------------------------


def test_the_employee_list_returns_only_the_callers_tenant(tech_in_a, technician_client, two_tenants):
    response = technician_client.get("/api/v1/directory/employees/")

    assert response.status_code == 200
    assert {row["sam"] for row in response.json()["results"]} == {"a.insaf", "c.chen"}


def test_a_search_cannot_reach_another_tenant_by_name(tech_in_a, technician_client, two_tenants):
    response = technician_client.get("/api/v1/directory/employees/", {"q": "obrien"})

    assert response.status_code == 200
    assert response.json()["results"] == []


def test_the_device_list_returns_only_the_callers_tenant(tech_in_a, technician_client, two_tenants):
    response = technician_client.get("/api/v1/directory/devices/")

    assert {row["hostname"] for row in response.json()["results"]} == {"DESK-A1"}


def test_an_employee_detail_of_another_tenant_is_not_found(tech_in_a, technician_client, two_tenants):
    response = technician_client.get("/api/v1/directory/employees/b.obrien/")

    assert response.status_code == 404, "a foreign row must look absent, not forbidden"


def test_a_request_with_no_tenant_sees_an_empty_directory(admin_user, two_tenants):
    """Authenticated and capability-holding, but a member of nowhere.

    The `filter only when an organisation exists` idiom used elsewhere would hand
    this caller every workspace's staff list. That fallback is what is being closed.
    """
    admin_user.role = Role.ADMIN
    admin_user.save(update_fields=["role"])

    client = _client_for(admin_user)

    assert client.get("/api/v1/directory/employees/").json()["results"] == []
    assert client.get("/api/v1/directory/devices/").json()["results"] == []


# ---------------------------------------------------------------------------
# The vault
# ---------------------------------------------------------------------------


def test_a_reference_from_another_tenant_is_not_spendable(two_tenants):
    """The worst case: a uuid that leaked into a log, plus any directory:read."""
    reference = store_password(two_tenants["b"], "b.obrien", "N0tF0rY0uP@ssw0rd")

    with pytest.raises(ValueError, match="No password reset with that reference."):
        retrieve_password(reference, two_tenants["a"])

    # The owning tenant still gets it, so the refusal above is tenancy, not expiry.
    assert retrieve_password(reference, two_tenants["b"]).sam == "b.obrien"


def test_a_foreign_reference_answers_exactly_like_a_bogus_one(two_tenants):
    reference = store_password(two_tenants["b"], "b.obrien", "N0tF0rY0uP@ssw0rd")
    bogus = "00000000-0000-0000-0000-000000000000"

    answers = []
    for value in (reference, bogus):
        try:
            retrieve_password(value, two_tenants["a"])
        except ValueError as exc:
            answers.append(str(exc))

    assert answers[0] == answers[1], "the difference between these two is an oracle"


def test_a_vaulted_password_remembers_who_owns_it(two_tenants):
    reference = store_password(two_tenants["a"], "a.insaf", "Own3rOnclyP@ss")

    record = PasswordReset.objects.get(reference=reference)
    assert record.organization_id == two_tenants["a"].pk


def test_the_vault_refuses_to_store_without_an_owner():
    with pytest.raises(ValueError, match="no owning organisation"):
        store_password(None, "a.insaf", "OrphanP@ssw0rd")


def test_the_retrieval_endpoint_refuses_a_foreign_reference(tech_in_a, technician_client, two_tenants):
    reference = store_password(two_tenants["b"], "b.obrien", "N0tF0rY0uP@ssw0rd")

    response = technician_client.get(f"/api/v1/directory/password-resets/{reference}/")

    assert response.status_code == 410
    assert "N0tF0rY0uP@ssw0rd" not in response.content.decode()


# ---------------------------------------------------------------------------
# The agent and tool path
# ---------------------------------------------------------------------------


def test_a_tool_cannot_act_on_another_tenants_account(tech_in_a, two_tenants):
    """The tool layer takes no organisation argument, so it cannot be talked into one."""
    context = build_context(tech_in_a, organization=two_tenants["a"])

    assert execute_tool("lookup_user", {"query": "b.obrien"}, context)["found"] is False


def test_a_generated_password_lands_in_the_callers_tenant(tech_in_a, two_tenants):
    context = build_context(tech_in_a, organization=two_tenants["a"])

    reference = context.password_sink("a.insaf", "H0tF0rMe0nly@x", True)

    assert PasswordReset.objects.get(reference=reference).organization_id == two_tenants["a"].pk


def test_holding_the_capability_in_one_workspace_opens_nothing_in_another(two_tenants, join):
    outsider = CustomUser.objects.create(email="outsider@example.test")
    outsider.role = Role.TECHNICIAN
    outsider.save(update_fields=["role"])
    join(outsider, two_tenants["b"], Role.TECHNICIAN)

    client = _client_for(outsider)
    results = client.get("/api/v1/directory/employees/").json()["results"]

    assert {row["sam"] for row in results} == {"b.obrien"}
