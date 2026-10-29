"""Tenancy: organisations, departments, members and their permissions.

The tests that matter most here are the negative ones. A multi-tenant product fails
not because an admin cannot add a department, but because a *different* admin can.
"""
from __future__ import annotations

import pytest
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import Role
from apps.helpdesk.services import create_ticket
from apps.organizations.models import Department, Membership, Organization
from apps.organizations.services import TenancyError, invite_member, update_member
from tests.factories import make_user

pytestmark = pytest.mark.django_db

ORG = "/api/v1/org/"
DEPARTMENTS = "/api/v1/org/departments/"
MEMBERS = "/api/v1/org/members/"
ACCEPT = "/api/v1/org/invites/accept/"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _client_for(user) -> APIClient:
    client = APIClient()
    token = RefreshToken.for_user(user).access_token
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    return client


def _join(user, organization, role=Role.ADMIN, **extra) -> Membership:
    extra.setdefault("accepted_at", timezone.now())
    return Membership.objects.create(
        user=user, organization=organization, role=role, **extra
    )


@pytest.fixture
def acme(db) -> Organization:
    return Organization.objects.create(name="Acme Support", slug="acme")


@pytest.fixture
def globex(db) -> Organization:
    return Organization.objects.create(name="Globex", slug="globex")


@pytest.fixture
def acme_admin(acme):
    user = make_user("owner@acme.test", Role.ADMIN)
    _join(user, acme, Role.ADMIN, is_owner=True)
    return user


@pytest.fixture
def acme_client(acme_admin) -> APIClient:
    return _client_for(acme_admin)


@pytest.fixture
def acme_tech(acme):
    user = make_user("tech@acme.test", Role.TECHNICIAN)
    _join(user, acme, Role.TECHNICIAN)
    return user


@pytest.fixture
def tech_client(acme_tech) -> APIClient:
    return _client_for(acme_tech)


# ---------------------------------------------------------------------------
# Departments
# ---------------------------------------------------------------------------


def test_an_admin_can_add_a_department_to_their_own_account(acme_client, acme):
    """The feature this whole layer exists for."""
    response = acme_client.post(
        DEPARTMENTS, {"name": "Field technicians", "code": "FLD"}, format="json"
    )

    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "Field technicians"
    assert body["code"] == "FLD"
    assert body["member_count"] == 0
    assert Department.objects.filter(organization=acme, name="Field technicians").exists()


def test_a_technician_cannot_add_a_department(tech_client):
    response = tech_client.post(DEPARTMENTS, {"name": "Shadow IT"}, format="json")

    assert response.status_code == 403


def test_a_requester_cannot_even_list_departments(acme):
    user = make_user("someone@acme.test", Role.REQUESTER)
    _join(user, acme, Role.REQUESTER)

    response = _client_for(user).get(DEPARTMENTS)

    # Reading the roster is a service-desk capability; departments follow it.
    assert response.status_code == 200, "listing departments is open to every member"
    assert response.json()["results"] == []


def test_a_department_name_is_unique_within_an_organisation(acme_client):
    acme_client.post(DEPARTMENTS, {"name": "Service desk"}, format="json")

    duplicate = acme_client.post(DEPARTMENTS, {"name": "service desk"}, format="json")

    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "duplicate_department"


def test_the_same_department_name_is_allowed_in_another_organisation(
    acme_client, globex
):
    acme_client.post(DEPARTMENTS, {"name": "Service desk"}, format="json")
    Department.objects.create(organization=globex, name="Service desk")

    again = acme_client.post(DEPARTMENTS, {"name": "Service desk"}, format="json")

    assert again.status_code == 409, "still a duplicate inside Acme"
    assert Department.objects.filter(name="Service desk").count() == 2


def test_a_department_from_another_tenant_is_a_404(acme_client, globex):
    """Ids are guessable. Scoping is what makes guessing useless."""
    foreign = Department.objects.create(organization=globex, name="Their desk")

    read = acme_client.patch(f"{DEPARTMENTS}{foreign.pk}/", {"name": "Hijacked"}, format="json")
    delete = acme_client.delete(f"{DEPARTMENTS}{foreign.pk}/")

    assert read.status_code == 404
    assert delete.status_code == 404
    foreign.refresh_from_db()
    assert foreign.name == "Their desk"


def test_a_parent_department_must_be_in_the_same_organisation(acme_client, globex):
    foreign = Department.objects.create(organization=globex, name="Foreign")

    response = acme_client.post(
        DEPARTMENTS, {"name": "Nested", "parent_id": foreign.pk}, format="json"
    )

    assert response.status_code == 404


def test_deleting_a_staffed_department_is_refused_until_the_members_move(
    acme_client, acme, acme_tech
):
    department = Department.objects.create(organization=acme, name="L1")
    membership = Membership.objects.get(user=acme_tech)
    membership.department = department
    membership.save(update_fields=["department"])

    refused = acme_client.delete(f"{DEPARTMENTS}{department.pk}/")
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "department_has_members"

    target = Department.objects.create(organization=acme, name="L2")
    moved = acme_client.delete(f"{DEPARTMENTS}{department.pk}/?reassign_to={target.pk}")

    assert moved.status_code == 204
    membership.refresh_from_db()
    assert membership.department == target


# ---------------------------------------------------------------------------
# Members
# ---------------------------------------------------------------------------


def test_an_admin_adds_a_member_with_a_password_that_works_immediately(
    api_client, acme_client, acme
):
    """The whole point: a credential, not a link the person has to redeem."""
    department = Department.objects.create(organization=acme, name="L1")

    response = acme_client.post(
        MEMBERS,
        {
            "email": "New.Person@Acme.test",
            "role": Role.TECHNICIAN,
            "department_id": department.pk,
            "password": "a-real-password",
        },
        format="json",
    )

    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "new.person@acme.test", "addresses are normalised"
    assert body["role"] == Role.TECHNICIAN
    assert body["department_id"] == department.pk
    assert body["status"] == "active", "no invitation step — they can sign in now"
    assert body["initial_password"] == "a-real-password"

    login = api_client.post(
        "/api/v1/auth/login/",
        {"email": "new.person@acme.test", "password": "a-real-password"},
        format="json",
    )
    assert login.status_code == 200


def test_the_server_generates_a_password_when_none_is_supplied(api_client, acme_client):
    body = acme_client.post(MEMBERS, {"email": "gen@acme.test"}, format="json").json()

    assert len(body["initial_password"]) >= 12
    login = api_client.post(
        "/api/v1/auth/login/",
        {"email": "gen@acme.test", "password": body["initial_password"]},
        format="json",
    )
    assert login.status_code == 200


def test_a_weak_password_is_refused_when_adding_a_member(acme_client):
    response = acme_client.post(
        MEMBERS, {"email": "weak@acme.test", "password": "abc"}, format="json"
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "weak_password"
    assert not Membership.objects.filter(user__email="weak@acme.test").exists()


def test_an_admin_can_reset_a_members_password(api_client, acme_client):
    """The only "forgot password" path, since there is no mail transport."""
    created = acme_client.post(
        MEMBERS, {"email": "reset@acme.test", "password": "original-password"}, format="json"
    ).json()

    response = acme_client.post(
        f"{MEMBERS}{created['id']}/password/",
        {"password": "brand-new-password"},
        format="json",
    )

    assert response.status_code == 200
    assert response.json()["password"] == "brand-new-password"

    old = api_client.post(
        "/api/v1/auth/login/",
        {"email": "reset@acme.test", "password": "original-password"},
        format="json",
    )
    new = api_client.post(
        "/api/v1/auth/login/",
        {"email": "reset@acme.test", "password": "brand-new-password"},
        format="json",
    )
    assert old.status_code == 401, "the previous password must stop working"
    assert new.status_code == 200


def test_a_password_reset_cannot_cross_tenants(acme_client, globex):
    outsider = make_user("theirs@globex.test", Role.ADMIN)
    foreign = _join(outsider, globex, Role.ADMIN, is_owner=True)

    response = acme_client.post(
        f"{MEMBERS}{foreign.pk}/password/",
        {"password": "hijacked-password"},
        format="json",
    )

    assert response.status_code == 404


def test_a_password_reset_does_not_reactivate_a_suspended_member(
    acme_client, acme, acme_tech
):
    membership = Membership.objects.get(user=acme_tech)
    update_member(membership, is_active=False, actor_role=Role.ADMIN)

    acme_client.post(f"{MEMBERS}{membership.pk}/password/", {}, format="json")

    membership.refresh_from_db()
    assert membership.is_active is False, "a reset must not undo a suspension"


def test_an_invitation_token_still_works_through_the_api(api_client, acme):
    """The console issues passwords now; the API still supports invitations."""
    _membership, token = invite_member(acme, email="invited@acme.test", actor_role=Role.ADMIN)

    accepted = api_client.post(
        ACCEPT, {"token": token, "password": "a-real-password"}, format="json"
    )
    assert accepted.status_code == 200
    assert (
        api_client.post(
            "/api/v1/auth/login/",
            {"email": "invited@acme.test", "password": "a-real-password"},
            format="json",
        ).status_code
        == 200
    )

    replay = api_client.post(
        ACCEPT, {"token": token, "password": "another-password"}, format="json"
    )
    assert replay.status_code == 400
    assert replay.json()["error"]["code"] == "invalid_invite"


def test_a_short_password_is_refused_at_acceptance(api_client, acme):
    _membership, token = invite_member(acme, email="short@acme.test", actor_role=Role.ADMIN)

    response = api_client.post(ACCEPT, {"token": token, "password": "abc"}, format="json")

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "weak_password"


def test_the_same_person_cannot_be_added_twice(acme_client):
    acme_client.post(MEMBERS, {"email": "dup@acme.test"}, format="json")

    again = acme_client.post(MEMBERS, {"email": "dup@acme.test"}, format="json")

    assert again.status_code == 409
    assert again.json()["error"]["code"] == "already_a_member"


def test_a_technician_cannot_add_anyone(tech_client):
    response = tech_client.post(MEMBERS, {"email": "sneaky@acme.test"}, format="json")

    assert response.status_code == 403


def test_nobody_can_grant_a_role_above_their_own(acme):
    """Checked in the service layer, so no future view can forget it."""
    actor = make_user("desk@acme.test", Role.SERVICE_DESK)
    _join(actor, acme, Role.SERVICE_DESK)

    with pytest.raises(TenancyError) as refused:
        invite_member(acme, email="boss@acme.test", role=Role.ADMIN, actor_role=Role.SERVICE_DESK)

    assert refused.value.code == "role_too_high"
    assert not Membership.objects.filter(user__email="boss@acme.test").exists()


def test_the_last_admin_cannot_deactivate_themselves(acme):
    """Otherwise the account is unreachable, with no platform superadmin to undo it."""
    user = make_user("solo@acme.test", Role.ADMIN)
    membership = _join(user, acme, Role.ADMIN)  # deliberately not the owner

    with pytest.raises(TenancyError) as refused:
        update_member(membership, is_active=False, actor_role=Role.ADMIN)

    assert refused.value.code == "last_admin"
    membership.refresh_from_db()
    assert membership.is_active is True


def test_the_last_admin_cannot_be_demoted(acme):
    user = make_user("solo2@acme.test", Role.ADMIN)
    membership = _join(user, acme, Role.ADMIN)

    with pytest.raises(TenancyError) as refused:
        update_member(membership, role=Role.TECHNICIAN, actor_role=Role.ADMIN)

    assert refused.value.code == "last_admin"


def test_an_admin_may_be_demoted_once_another_exists(acme):
    first = make_user("a1@acme.test", Role.ADMIN)
    second = make_user("a2@acme.test", Role.ADMIN)
    membership = _join(first, acme, Role.ADMIN)
    _join(second, acme, Role.ADMIN)

    update_member(membership, role=Role.TECHNICIAN, actor_role=Role.ADMIN)

    membership.refresh_from_db()
    assert membership.role == Role.TECHNICIAN


def test_the_owner_cannot_be_deactivated(acme):
    owner = make_user("owner@acme.test", Role.ADMIN)
    membership = _join(owner, acme, Role.ADMIN, is_owner=True)
    other = make_user("a2@acme.test", Role.ADMIN)
    _join(other, acme, Role.ADMIN)

    with pytest.raises(TenancyError) as refused:
        update_member(membership, is_active=False, actor_role=Role.ADMIN)

    assert refused.value.code == "cannot_disable_owner"


def test_deleting_a_member_deactivates_rather_than_erases(acme_client, acme, acme_tech):
    membership = Membership.objects.get(user=acme_tech)

    response = acme_client.delete(f"{MEMBERS}{membership.pk}/")

    assert response.status_code == 200
    assert response.json()["status"] == "disabled"
    assert Membership.objects.filter(pk=membership.pk).exists(), "history must survive"


def test_the_roster_only_shows_this_organisation(acme_client, globex):
    outsider = make_user("theirs@globex.test", Role.ADMIN)
    _join(outsider, globex, Role.ADMIN, is_owner=True)

    response = acme_client.get(MEMBERS)

    assert response.status_code == 200
    emails = [row["email"] for row in response.json()["results"]]
    assert "owner@acme.test" in emails
    assert "theirs@globex.test" not in emails


# ---------------------------------------------------------------------------
# Tenant resolution
# ---------------------------------------------------------------------------


def test_the_organisation_header_picks_the_tenant_and_its_role(acme, globex):
    """One human, two accounts, two different roles — the point of memberships."""
    user = make_user("consultant@example.test", Role.ADMIN)
    _join(user, acme, Role.ADMIN)
    _join(user, globex, Role.REQUESTER)

    client = _client_for(user)
    in_acme = client.get(ORG).json()
    in_globex = client.get(ORG, HTTP_X_ORGANIZATION="globex").json()

    assert in_acme["slug"] == "acme"
    assert in_acme["my_role"] == Role.ADMIN
    assert in_acme["permissions"]["manage_departments"] is True

    assert in_globex["slug"] == "globex"
    assert in_globex["my_role"] == Role.REQUESTER
    assert in_globex["permissions"]["manage_departments"] is False


def test_an_admin_of_one_org_cannot_administer_another(acme, globex):
    user = make_user("admin@acme.test", Role.ADMIN)
    _join(user, acme, Role.ADMIN, is_owner=True)
    _join(user, globex, Role.REQUESTER)

    response = _client_for(user).post(
        DEPARTMENTS,
        {"name": "Not mine"},
        format="json",
        HTTP_X_ORGANIZATION="globex",
    )

    assert response.status_code == 403


def test_the_console_selects_the_tenant_by_primary_key(acme, globex):
    """`/auth/me/` hands the console a pk, and the BFF sends it back verbatim."""
    user = make_user("console@example.test", Role.ADMIN)
    _join(user, acme, Role.ADMIN)
    _join(user, globex, Role.REQUESTER)

    body = _client_for(user).get(ORG, HTTP_X_ORGANIZATION_ID=str(globex.pk)).json()

    assert body["slug"] == "globex"
    assert body["my_role"] == Role.REQUESTER


def test_a_stale_organization_cookie_falls_back_to_a_real_membership(acme):
    """A cookie naming an account they left must not brick the console."""
    user = make_user("stale@acme.test", Role.ADMIN)
    _join(user, acme, Role.ADMIN, is_owner=True)

    body = _client_for(user).get(ORG, HTTP_X_ORGANIZATION_ID="999999").json()

    assert body["slug"] == "acme", "falls back to one of their own, never to someone else's"


def test_a_platform_admin_can_act_in_any_account(acme, globex):
    """The project admin is not a member of the client's account, by design."""
    operator = make_user("ops@deskpilot.test", Role.ADMIN, is_superuser=True, is_staff=True)

    body = _client_for(operator).get(ORG, HTTP_X_ORGANIZATION_ID=str(globex.pk)).json()

    assert body["slug"] == "globex"
    assert body["my_role"] == Role.ADMIN
    assert body["permissions"]["manage_members"] is True


def test_a_platform_admin_must_name_the_account(acme):
    """No default tenant for someone who belongs to none — otherwise it is a guess."""
    operator = make_user("ops2@deskpilot.test", Role.ADMIN, is_superuser=True, is_staff=True)

    response = _client_for(operator).get(ORG)

    assert response.status_code == 403


def test_a_platform_admin_can_rescue_a_client_who_locked_themselves_out(api_client, globex):
    operator = make_user("ops3@deskpilot.test", Role.ADMIN, is_superuser=True, is_staff=True)
    stranded = make_user("stranded@globex.test", Role.ADMIN)
    membership = _join(stranded, globex, Role.ADMIN, is_owner=True)

    response = _client_for(operator).post(
        f"{MEMBERS}{membership.pk}/password/",
        {"password": "rescued-password"},
        format="json",
        HTTP_X_ORGANIZATION_ID=str(globex.pk),
    )

    assert response.status_code == 200
    assert (
        api_client.post(
            "/api/v1/auth/login/",
            {"email": "stranded@globex.test", "password": "rescued-password"},
            format="json",
        ).status_code
        == 200
    )


def test_a_regular_admin_cannot_reach_an_account_they_are_not_in(acme, globex):
    """The escape hatch is superuser-only; naming a foreign tenant does nothing."""
    admin = make_user("admin@acme.test", Role.ADMIN)
    _join(admin, acme, Role.ADMIN, is_owner=True)

    body = _client_for(admin).get(ORG, HTTP_X_ORGANIZATION_ID=str(globex.pk)).json()

    assert body["slug"] == "acme", "the header cannot move you into a tenant you are not in"


def test_a_user_with_no_membership_cannot_use_the_org_api():
    user = make_user("nobody@nowhere.test", Role.ADMIN)

    response = _client_for(user).get(ORG)

    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Data isolation
# ---------------------------------------------------------------------------


def test_a_ticket_belongs_to_the_tenant_that_raised_it(acme, globex):
    ticket = create_ticket(
        subject="Acme laptop", body="It is broken", organization=acme
    )

    outsider = make_user("spy@globex.test", Role.ADMIN)
    _join(outsider, globex, Role.ADMIN, is_owner=True)

    response = _client_for(outsider).get(f"/api/v1/tickets/{ticket.pk}/")

    assert response.status_code == 404, "another tenant's ticket must not resolve at all"


def test_a_ticket_is_visible_inside_its_own_tenant(acme, acme_client):
    ticket = create_ticket(subject="Acme laptop", body="Broken", organization=acme)

    response = acme_client.get(f"/api/v1/tickets/{ticket.pk}/")

    assert response.status_code == 200


def test_the_dashboard_counts_only_this_tenant(acme, globex, acme_client):
    create_ticket(subject="Mine", body="b", organization=acme)
    create_ticket(subject="Theirs", body="b", organization=globex)

    body = acme_client.get("/api/v1/stats/").json()

    assert body["tickets_total"] == 1
