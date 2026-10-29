"""Console auth: `/auth/login/` and `/auth/me/`.

These two endpoints exist because the web console's BFF expects them. They are
tested here rather than in the console, because the contract is the backend's.
"""
from __future__ import annotations

import pytest

from apps.accounts.models import Role
from tests.factories import PASSWORD, make_user

pytestmark = pytest.mark.django_db

LOGIN = "/api/v1/auth/login/"
ME = "/api/v1/auth/me/"


def test_login_returns_tokens_and_the_user(api_client, technician_user):
    response = api_client.post(
        LOGIN, {"email": technician_user.email, "password": PASSWORD}, format="json"
    )

    assert response.status_code == 200
    body = response.json()
    assert body["access"]
    assert body["refresh"]
    assert body["user"]["email"] == technician_user.email
    assert body["user"]["full_name"], "the console renders this in the sidebar"
    assert body["user"]["id"] == str(technician_user.pk)


def test_login_is_case_insensitive_on_email(api_client, desk_user):
    response = api_client.post(
        LOGIN, {"email": desk_user.email.upper(), "password": PASSWORD}, format="json"
    )

    assert response.status_code == 200


def test_a_wrong_password_and_an_unknown_email_look_identical(api_client, desk_user):
    """Distinguishing them would be a free account-enumeration oracle."""
    wrong_password = api_client.post(
        LOGIN, {"email": desk_user.email, "password": "not-the-password"}, format="json"
    )
    unknown_email = api_client.post(
        LOGIN, {"email": "nobody@deskpilot.test", "password": PASSWORD}, format="json"
    )

    assert wrong_password.status_code == unknown_email.status_code == 401
    assert (
        wrong_password.json()["error"]["code"]
        == unknown_email.json()["error"]["code"]
        == "invalid_credentials"
    )
    assert wrong_password.json()["error"]["message"] == unknown_email.json()["error"]["message"]


def test_missing_fields_are_a_400(api_client):
    response = api_client.post(LOGIN, {"email": "a@b.test"}, format="json")

    assert response.status_code == 400


def test_a_deactivated_account_cannot_sign_in(api_client, desk_user):
    desk_user.is_active = False
    desk_user.save(update_fields=["is_active"])

    response = api_client.post(
        LOGIN, {"email": desk_user.email, "password": PASSWORD}, format="json"
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "account_inactive"


def test_me_requires_a_token(api_client):
    assert api_client.get(ME).status_code == 401


@pytest.mark.parametrize(
    "role",
    [Role.ADMIN, Role.TECHNICIAN, Role.SERVICE_DESK, Role.REQUESTER],
)
def test_me_reports_the_real_role_from_a_real_membership(api_client, role):
    """The console gates its entire UI on this.

    The role used to be one global field reported inside a synthetic workspace.
    It now comes from a membership row, which is what lets the same person hold a
    different role in a different account.
    """
    user = make_user(f"{role.lower()}@deskpilot.test", role)
    login = api_client.post(LOGIN, {"email": user.email, "password": PASSWORD}, format="json")
    token = login.json()["access"]

    response = api_client.get(ME, HTTP_AUTHORIZATION=f"Bearer {token}")

    assert response.status_code == 200
    body = response.json()
    assert body["user"]["email"] == user.email
    assert len(body["memberships"]) == 1

    membership = body["memberships"][0]
    assert membership["role"] == role, "the console gates the UI on this"
    assert membership["organization_slug"] == "deskpilot"
    assert body["active_organization"]["organization_slug"] == "deskpilot"
    assert membership["organization_id"], "the console keys the org switcher on this"


# ---------------------------------------------------------------------------
# Logout / revocation
# ---------------------------------------------------------------------------
LOGOUT = "/api/v1/auth/logout/"
REFRESH = "/api/v1/auth/refresh/"


def test_logout_blacklists_the_refresh_token(api_client, technician_user):
    """Clearing a cookie only forgets the token locally.

    Without a server-side blacklist a stolen refresh token stays valid for its
    whole lifetime no matter what the user does, which makes "log out everywhere"
    and incident response impossible.
    """
    login = api_client.post(
        LOGIN, {"email": technician_user.email, "password": PASSWORD}, format="json"
    ).json()
    access, refresh = login["access"], login["refresh"]

    assert api_client.post(
        LOGOUT, {"refresh": refresh}, format="json", HTTP_AUTHORIZATION=f"Bearer {access}"
    ).status_code == 204

    reused = api_client.post(REFRESH, {"refresh": refresh}, format="json")
    assert reused.status_code == 401, "a logged-out refresh token must not mint a new access token"


def test_logout_requires_authentication(api_client):
    assert api_client.post(LOGOUT, {"refresh": "whatever"}, format="json").status_code == 401


def test_logout_without_a_refresh_token_is_still_a_success(api_client, technician_user):
    """Ending a session must not fail because the client had nothing to revoke."""
    login = api_client.post(
        LOGIN, {"email": technician_user.email, "password": PASSWORD}, format="json"
    ).json()

    response = api_client.post(
        LOGOUT, {}, format="json", HTTP_AUTHORIZATION=f"Bearer {login['access']}"
    )

    assert response.status_code == 204


def test_refresh_rotates_and_blacklists_the_previous_token(api_client, technician_user):
    """Rotation means a leaked refresh token is single-use."""
    login = api_client.post(
        LOGIN, {"email": technician_user.email, "password": PASSWORD}, format="json"
    ).json()

    first = api_client.post(REFRESH, {"refresh": login["refresh"]}, format="json")
    assert first.status_code == 200
    assert first.json().get("refresh"), "rotation must hand back a new refresh token"

    replay = api_client.post(REFRESH, {"refresh": login["refresh"]}, format="json")
    assert replay.status_code == 401, "the old refresh token must be dead after rotation"
