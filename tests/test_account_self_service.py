"""Account self-service: the name on your profile, your password, your sign-ins.

Three endpoints, and the interesting assertions are all about *reach*: what one
person's session may touch is exactly one person. These are the only views in the
API with no capability on them, so everything that keeps them honest is here —
the current password before a new one, the caller's own rows before a revoke, and
no field beyond the display name on a profile write.

The session ledger is SimpleJWT's ``OutstandingToken`` table rather than a table of
ours, which is why one test is about a token rotation: rotation is the ordinary
thing the console does every fifteen minutes, and if the ledger loses track of a
browser mid-rotation, both the list on the security page and "every other sign-in
ended" become fiction.
"""

from __future__ import annotations

import base64
import json
import re
from datetime import timedelta

import pytest
from django.core import mail
from django.utils import timezone
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.test import APIClient
from rest_framework_simplejwt.token_blacklist.models import (
    BlacklistedToken,
    OutstandingToken,
)
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts import password_reset
from apps.accounts.models import CustomUser, Role
from apps.organizations.services import MIN_PASSWORD_LENGTH
from tests.factories import PASSWORD, make_user

pytestmark = pytest.mark.django_db

ME = "/api/v1/auth/me/"
CHANGE = "/api/v1/auth/change-password/"
SESSIONS = "/api/v1/auth/sessions/"
LOGIN = "/api/v1/auth/login/"
REFRESH = "/api/v1/auth/refresh/"
RESET = "/api/v1/auth/reset-password/"

EMAIL = "nadia.haddad@northwind.test"
NEW_PASSWORD = "a-brand-new-starter-2026"


@pytest.fixture(autouse=True)
def no_change_rate_limit(monkeypatch):
    """``password_change`` is 10/hour in production.

    A suite that hits the endpoint twice per test would trip its own throttle, so
    the rate is pinned high everywhere and restored by the one test that asserts it.
    """
    monkeypatch.setattr(
        ScopedRateThrottle,
        "THROTTLE_RATES",
        {**ScopedRateThrottle.THROTTLE_RATES, "password_change": "1000/hour"},
    )


@pytest.fixture
def user(db) -> CustomUser:
    return make_user(EMAIL, Role.TECHNICIAN)


def _client_with(refresh_token: str) -> APIClient:
    """A browser holding one session, as a client that can be pointed at an endpoint."""
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {RefreshToken(refresh_token).access_token}")
    return client


def _signed_in_client(user) -> APIClient:
    return _client_with(str(RefreshToken.for_user(user)))


def _jti(refresh_token: str) -> str:
    """Read the ledger id without verifying the token.

    A revoked token is precisely the one this suite asks about, and constructing a
    ``RefreshToken`` from it raises — the id is a label, not a credential, so the
    signature adds nothing to an assertion about it.
    """
    payload = refresh_token.split(".")[1]
    padding = "=" * (-len(payload) % 4)
    return str(json.loads(base64.urlsafe_b64decode(payload + padding))["jti"])


def _can_renew(api_client: APIClient, refresh_token: str) -> bool:
    """Whether that browser can still get a new access token — i.e. whether it is
    still signed in. An access token riding out its fifteen minutes is not a session.
    """
    return (
        api_client.post(REFRESH, {"refresh": refresh_token}, format="json").status_code == 200
    )


def _sessions(client: APIClient) -> list[dict]:
    response = client.get(SESSIONS)
    assert response.status_code == 200, response.content
    return response.json()["sessions"]


def _rows(client: APIClient) -> set[str]:
    return {row["jti"] for row in _sessions(client)}


def _change(client: APIClient, current: str, password: str):
    return client.post(
        CHANGE, {"current_password": current, "password": password}, format="json"
    )


def _reset_token_in_mailbox(user) -> str:
    """The plaintext token from the newest message to this address.

    Read out of the mail rather than recomputed: the table stores a digest, and a
    test that hashed its way to the answer would be checking the implementation
    instead of the flow.
    """
    for message in reversed(mail.outbox):
        if message.to != [user.email]:
            continue
        match = re.search(r"/auth/reset-password/([^/]+)/", message.body)
        if match:
            return match.group(1)
    raise AssertionError(f"no reset mail for {user.email}")


# ---------------------------------------------------------------------------
# PATCH /auth/me/ — the display name, and nothing else
# ---------------------------------------------------------------------------


def test_the_display_name_round_trips(user):
    client = _signed_in_client(user)

    response = client.patch(ME, {"display_name": "Nadia Haddad"}, format="json")

    assert response.status_code == 200
    body = response.json()["user"]
    assert body["display_name"] == "Nadia Haddad"
    # ``full_name`` is what a header shows; it must follow the edit rather than stay
    # on whatever the session was built with.
    assert body["full_name"] == "Nadia Haddad"
    user.refresh_from_db()
    assert user.display_name == "Nadia Haddad"


def test_the_email_address_is_not_yours_to_change(user):
    """It is the username, and the address reset links are mailed to.

    Refusing is the point; naming the field in the message is what stops the console
    from looking like it saved a change it threw away.
    """
    client = _signed_in_client(user)

    response = client.patch(ME, {"email": "someone.else@northwind.test"}, format="json")

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "immutable_field"
    assert "email" in response.json()["error"]["message"]
    user.refresh_from_db()
    assert user.email == EMAIL


def test_someone_elses_profile_cannot_be_reached_by_id(user):
    """No id in the route, so there is no door to test — and that is the assertion.

    An "administrator edits a profile" endpoint has to be a different view with a
    capability, not this one with an id parameter bolted on.
    """
    outsider = make_user("outsider@northwind.test", Role.REQUESTER)
    client = _signed_in_client(user)

    response = client.patch(
        ME, {"id": str(outsider.pk), "display_name": "Hijacked"}, format="json"
    )

    assert response.status_code == 400
    outsider.refresh_from_db()
    assert outsider.display_name != "Hijacked"


def test_an_empty_display_name_is_an_answer_not_a_bug(user):
    client = _signed_in_client(user)

    response = client.patch(ME, {"display_name": "   "}, format="json")

    assert response.status_code == 200
    body = response.json()["user"]
    assert body["display_name"] == ""
    # The header still has to show something, so the fallback lives in the response.
    assert body["full_name"] == EMAIL


def test_an_overlong_name_is_refused_not_truncated(user):
    client = _signed_in_client(user)

    response = client.patch(ME, {"display_name": "x" * 151}, format="json")

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "name_too_long"
    user.refresh_from_db()
    assert user.display_name != "x" * 151


def test_patch_needs_a_session(api_client):
    assert (
        api_client.patch(ME, {"display_name": "Anonymous"}, format="json").status_code == 401
    )


def test_me_still_serves_the_capability_map(user):
    """The console's session bootstrap reads this body; PATCH must not have changed it."""
    body = _signed_in_client(user).get(ME).json()

    assert set(body) == {
        "user",
        "memberships",
        "active_organization",
        "role_capabilities",
    }


# ---------------------------------------------------------------------------
# POST /auth/change-password/
# ---------------------------------------------------------------------------


def test_the_current_password_is_required_and_checked(user):
    client = _signed_in_client(user)

    response = _change(client, "not-your-password", NEW_PASSWORD)

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_credentials"
    user.refresh_from_db()
    assert user.check_password(PASSWORD), "a refusal must not have written anything"


def test_a_missing_current_password_is_not_a_free_change(user):
    assert _change(_signed_in_client(user), "", NEW_PASSWORD).status_code == 401


def test_a_weak_new_password_is_refused_before_anything_changes(user):
    client = _signed_in_client(user)
    weak = "x" * (MIN_PASSWORD_LENGTH - 1)

    response = _change(client, PASSWORD, weak)

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "weak_password"
    user.refresh_from_db()
    assert user.check_password(PASSWORD)
    assert BlacklistedToken.objects.count() == 0, "a refused change evicts nobody"


def test_a_common_password_is_refused(user):
    """Length is not the only rule, and this one comes from Django's validators."""
    response = _change(_signed_in_client(user), PASSWORD, "password1234")

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "weak_password"


def test_changing_it_to_the_same_password_is_refused(user):
    """Otherwise every other device is signed out in exchange for no change."""
    client = _signed_in_client(user)

    response = _change(client, PASSWORD, PASSWORD)

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "password_unchanged"
    assert BlacklistedToken.objects.count() == 0


def test_the_new_password_signs_in_and_the_old_one_is_refused(api_client, user):
    assert _change(_signed_in_client(user), PASSWORD, NEW_PASSWORD).status_code == 200

    assert (
        api_client.post(LOGIN, {"email": EMAIL, "password": PASSWORD}, format="json").status_code
        == 401
    )
    assert (
        api_client.post(
            LOGIN, {"email": EMAIL, "password": NEW_PASSWORD}, format="json"
        ).status_code
        == 200
    )


def test_this_tab_stays_signed_in_and_the_others_do_not(api_client, user):
    """The bargain of the endpoint: evict everyone else, keep the person asking.

    A bare "done" would make the console's own next refresh fail, which reads
    exactly like the password change broke the account.
    """
    home = str(RefreshToken.for_user(user))
    holiday_laptop = str(RefreshToken.for_user(user))
    client = _client_with(home)
    assert _can_renew(api_client, home)

    body = _change(client, PASSWORD, NEW_PASSWORD).json()

    assert _can_renew(api_client, body["refresh"]), "the tab that asked stays signed in"
    assert not _can_renew(api_client, holiday_laptop), "every other sign-in ended"


def test_it_says_how_many_sign_ins_it_ended(user):
    for _ in range(3):
        RefreshToken.for_user(user)
    mine = str(RefreshToken.for_user(user))

    body = _change(_client_with(mine), PASSWORD, NEW_PASSWORD).json()

    # The caller's own row is in that count: it was ended, then replaced.
    assert body["revoked_sessions"] == 4
    assert OutstandingToken.objects.filter(user=user, blacklistedtoken__isnull=True).count() == 1


def test_a_sign_in_that_already_died_is_not_counted(user):
    """The change-password answer counts the same set the security page lists.

    SimpleJWT leaves expired rows in the ledger until ``flushexpiredtokens`` runs.
    Blacklisting one ends no sign-in, so counting it would tell somebody who just
    changed a stolen password that thirty places were locked out when three were.
    """
    stale = str(RefreshToken.for_user(user))
    OutstandingToken.objects.filter(jti=_jti(stale)).update(
        expires_at=timezone.now() - timedelta(hours=1)
    )
    mine = str(RefreshToken.for_user(user))

    body = _change(_client_with(mine), PASSWORD, NEW_PASSWORD).json()

    assert body["revoked_sessions"] == 1, "only the caller's own live sign-in"


def test_a_session_that_rotated_is_still_evicted(api_client, user):
    """The hole this closes: rotation mints a refresh token the library never records.

    With no ledger row, that browser is invisible to the security page *and* survives
    ``revoke_sessions`` — so an attacker who signed in, waited fifteen minutes, and
    then had the account reset would still be holding the account.
    """
    login = api_client.post(
        LOGIN, {"email": EMAIL, "password": PASSWORD}, format="json"
    ).json()
    rotated = api_client.post(REFRESH, {"refresh": login["refresh"]}, format="json")
    assert rotated.status_code == 200, rotated.content
    rotated = rotated.json()["refresh"]

    assert _change(_client_with(rotated), PASSWORD, NEW_PASSWORD).status_code == 200

    assert not _can_renew(api_client, rotated), "a rotated session outlived a password change"


def test_rotation_records_the_new_session(api_client, user):
    """Through the real endpoint, because a serializer the settings never point at
    would fix the bug in this test file and nowhere else.
    """
    login = api_client.post(
        LOGIN, {"email": EMAIL, "password": PASSWORD}, format="json"
    ).json()

    rotated = api_client.post(REFRESH, {"refresh": login["refresh"]}, format="json").json()

    listed = _rows(_client_with(rotated["refresh"]))
    assert {_jti(rotated["refresh"])} <= listed
    assert _jti(login["refresh"]) not in listed, "the old one is ended when it is replaced"
    assert OutstandingToken.objects.filter(jti=_jti(login["refresh"])).exists(), (
        "blacklisting needs the row to still be in the table, or the ledger forgets "
        "a session that was revoked"
    )


def test_the_change_is_stamped(user):
    """``set_password`` is the one place every credential passes, so the stamp cannot
    be skipped by a path that forgot to set it — including account creation, which is
    why a fresh row is already dated.
    """
    client = _signed_in_client(user)
    user.refresh_from_db()
    at_creation = user.password_updated_at
    assert at_creation is not None

    body = _change(client, PASSWORD, NEW_PASSWORD).json()

    assert body["user"]["password_updated_at"] is not None
    user.refresh_from_db()
    assert user.password_updated_at > at_creation
    assert timezone.now() - user.password_updated_at < timedelta(minutes=1)


def test_a_reset_stamps_it_too(api_client, user):
    """One timestamp, whichever path the password took.

    If only the self-service endpoint stamped it, an account saved by a reset would
    go on saying "never recorded" — on the page whose whole job is saying whether the
    credential is recent.
    """
    password_reset.issue_reset(EMAIL)

    response = api_client.post(
        RESET, {"token": _reset_token_in_mailbox(user), "password": NEW_PASSWORD}, format="json"
    )

    assert response.status_code == 200, response.content
    user.refresh_from_db()
    assert user.password_updated_at is not None


def test_an_administrator_setting_a_password_stamps_it(organization):
    """The paths that are not self-service are still password changes.

    ``create_member`` writes a working credential, so the row has to be stamped like
    any other: an account whose "last changed" stays null forever reads as an audit
    gap on the security page.
    """
    from apps.organizations.services import create_member

    _membership, issued = create_member(
        organization, email="newcomer@northwind.test", role=Role.SERVICE_DESK
    )

    newcomer = CustomUser.objects.get(email="newcomer@northwind.test")
    assert newcomer.check_password(issued)
    assert newcomer.password_updated_at is not None


def test_change_password_needs_a_session(api_client):
    assert api_client.post(
        CHANGE, {"current_password": "whatever", "password": "whatever"}, format="json"
    ).status_code == 401


def test_the_change_rate_limit_is_real(user, monkeypatch):
    """Pinned at a low rate to prove the shipped one is wired up.

    The endpoint hands back a fresh refresh token, so an unlimited one would turn a
    guessed password into a permanent session.
    """
    monkeypatch.setattr(
        ScopedRateThrottle,
        "THROTTLE_RATES",
        {**ScopedRateThrottle.THROTTLE_RATES, "password_change": "2/hour"},
    )
    client = _signed_in_client(user)

    for _ in range(2):
        assert _change(client, "wrong", NEW_PASSWORD).status_code == 401

    assert _change(client, "wrong", NEW_PASSWORD).status_code == 429


# ---------------------------------------------------------------------------
# GET /auth/sessions/  and  DELETE /auth/sessions/<jti>/
# ---------------------------------------------------------------------------


def test_a_sign_in_appears_once(user):
    mine = str(RefreshToken.for_user(user))

    sessions = _sessions(_client_with(mine))

    assert len(sessions) == 1
    row = sessions[0]
    assert row["jti"] == _jti(mine)
    assert row["signed_in_at"] is not None
    assert row["expires_at"] is not None
    assert set(row) == {"jti", "signed_in_at", "expires_at", "current"}


def test_the_refresh_token_itself_is_never_shown(user):
    """``OutstandingToken.token`` holds the credential.

    The jti is a label and safe to display; the token is the thing that renews a
    session, and the security page is rendered in a browser.
    """
    mine = str(RefreshToken.for_user(user))

    body = _client_with(mine).get(SESSIONS).content.decode()

    assert mine not in body
    assert _jti(mine) in body, "the row is listed, just not by its secret"


def test_ended_and_expired_sign_ins_are_not_listed(user):
    mine = str(RefreshToken.for_user(user))
    ended = str(RefreshToken.for_user(user))
    RefreshToken(ended).blacklist()
    stale = str(RefreshToken.for_user(user))
    OutstandingToken.objects.filter(jti=_jti(stale)).update(
        expires_at=timezone.now() - timedelta(hours=1)
    )

    assert _rows(_client_with(mine)) == {_jti(mine)}


def test_the_list_is_newest_first(user):
    tokens = [str(RefreshToken.for_user(user)) for _ in range(3)]
    for position, token in enumerate(tokens):
        OutstandingToken.objects.filter(jti=_jti(token)).update(
            created_at=timezone.now() - timedelta(minutes=position)
        )

    sessions = _sessions(_client_with(tokens[0]))

    # tokens[0] was given the newest timestamp, so it leads; a list ordered by the
    # database's own id would put the oldest sign-in first.
    assert [row["jti"] for row in sessions] == [_jti(t) for t in tokens]


def test_the_current_one_is_labelled(user):
    mine = str(RefreshToken.for_user(user))
    other = str(RefreshToken.for_user(user))
    client = _client_with(mine)

    sessions = client.get(SESSIONS, {"current_jti": _jti(mine)}).json()["sessions"]

    assert [row["current"] for row in sessions if row["jti"] == _jti(mine)] == [True]
    assert [row["current"] for row in sessions if row["jti"] == _jti(other)] == [False]
    # Without the hint nothing is claimed: guessing which row is this browser is
    # worse than leaving the badge off.
    assert all(row["current"] is False for row in _sessions(client))


def test_revoking_ends_one_session_and_leaves_the_rest(api_client, user):
    mine = str(RefreshToken.for_user(user))
    holiday_laptop = str(RefreshToken.for_user(user))
    client = _client_with(mine)

    response = client.delete(f"{SESSIONS}{_jti(holiday_laptop)}/")

    assert response.status_code == 204
    assert not _can_renew(api_client, holiday_laptop)
    assert _rows(client) == {_jti(mine)}
    assert _can_renew(api_client, mine)


def test_another_accounts_session_is_not_found(api_client, user):
    stranger = make_user("karim.opara@brightloop.test", Role.ADMIN)
    theirs = str(RefreshToken.for_user(stranger))
    client = _signed_in_client(user)

    response = client.delete(f"{SESSIONS}{_jti(theirs)}/")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "session_not_found"
    assert _can_renew(api_client, theirs), "refused, not performed"


def test_revoking_an_already_ended_session_is_404(user):
    mine = str(RefreshToken.for_user(user))
    client = _client_with(mine)

    assert client.delete(f"{SESSIONS}{_jti(mine)}/").status_code == 204
    assert client.delete(f"{SESSIONS}{_jti(mine)}/").status_code == 404


def test_revoking_an_unknown_jti_is_404(user):
    client = _signed_in_client(user)

    assert (
        client.delete(f"{SESSIONS}0192f6c3-7d2c-7a11-9f1e-000000000000/").status_code == 404
    )


def test_revoking_your_own_session_is_allowed(user):
    """Deliberate: "this is not my phone" and "sign me out of everything" are both
    reasons to reach for the row you are standing in."""
    mine = str(RefreshToken.for_user(user))
    client = _client_with(mine)

    assert client.delete(f"{SESSIONS}{_jti(mine)}/").status_code == 204
    assert _sessions(client) == []


def test_one_persons_list_is_not_another_s(user):
    stranger = make_user("karim.opara@brightloop.test", Role.ADMIN)
    theirs = {str(RefreshToken.for_user(stranger)) for _ in range(2)}
    mine = str(RefreshToken.for_user(user))

    assert _rows(_client_with(mine)) == {_jti(mine)}
    assert not {_jti(t) for t in theirs} & _rows(_client_with(mine))


def test_the_list_needs_a_sign_in(api_client):
    assert api_client.get(SESSIONS).status_code == 401
    assert api_client.delete(f"{SESSIONS}anything/").status_code == 401


def test_the_security_page_reports_when_the_password_last_changed(user):
    client = _signed_in_client(user)

    _change(client, PASSWORD, NEW_PASSWORD)
    assert client.get(SESSIONS).json()["password_updated_at"] is not None

    # A row written before the column existed stays null, and the page is told so
    # rather than being handed date_joined as a change nobody observed.
    CustomUser.objects.filter(pk=user.pk).update(password_updated_at=None)
    assert client.get(SESSIONS).json()["password_updated_at"] is None
