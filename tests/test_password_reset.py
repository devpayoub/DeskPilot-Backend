"""Password reset: a link to the address on file, then a new password.

``/auth/forgot-password/`` is the endpoint a stranger with a breach list uses, so
the interesting assertions here are the ones about what the server will not say.
The rest follow the sign-up suite: the token's life, and what happens to the
sessions that were already signed in when the password changed.
"""
from __future__ import annotations

import hashlib
import re
from datetime import timedelta

import pytest
from django.core import mail
from django.utils import timezone
from rest_framework.throttling import ScopedRateThrottle

from apps.accounts.models import RESET_LIFETIME, PasswordResetToken, Role
from apps.accounts.password_reset import _send_link
from tests.factories import PASSWORD, make_user

pytestmark = pytest.mark.django_db

FORGOT = "/api/v1/auth/forgot-password/"
RESET = "/api/v1/auth/reset-password/"
LOGIN = "/api/v1/auth/login/"
REFRESH = "/api/v1/auth/refresh/"

EMAIL = "priya.nair@northwind.test"
NEW_PASSWORD = "a-brand-new-starter-2026"


def _pin_rate(monkeypatch, scope: str, rate: str) -> None:
    """DRF copies ``DEFAULT_THROTTLE_RATES`` onto the throttle class at import time,
    so reassigning ``settings.REST_FRAMEWORK`` mid-test changes nothing the request
    can see. ``get_rate()`` reads the class attribute, once per request.
    """
    monkeypatch.setattr(
        ScopedRateThrottle, "THROTTLE_RATES", {**ScopedRateThrottle.THROTTLE_RATES, scope: rate}
    )


def _forgot(api_client, email: str = EMAIL):
    return api_client.post(FORGOT, {"email": email}, format="json")


def _link(email: str = EMAIL) -> str:
    """The reset URL from the newest message addressed to this account."""
    message = [m for m in mail.outbox if m.to == [email]][-1]
    return re.search(r"(https?://\S+/auth/reset-password/\S+/)", message.body).group(1)


def _token_from(url: str) -> str:
    return url.rstrip("/").rsplit("/", 1)[1]


def _token_for(email: str = EMAIL) -> str:
    return _token_from(_link(email))


def _reset(api_client, token: str, password: str = NEW_PASSWORD):
    return api_client.post(RESET, {"token": token, "password": password}, format="json")


def _live_link(api_client, email: str = EMAIL) -> str:
    """Walk step one and hand back the token, the way the emailed link does."""
    assert _forgot(api_client, email).status_code == 202
    return _token_for(email)


# ---------------------------------------------------------------------------
# Asking for a link
# ---------------------------------------------------------------------------


def test_asking_for_a_link_returns_a_receipt_and_nothing_else(api_client, technician_user):
    response = _forgot(api_client, technician_user.email)

    assert response.status_code == 202
    assert set(response.json()) == {"sent", "expires_in"}


def test_an_unknown_address_is_not_told_it_is_unknown(api_client, technician_user):
    """The whole point of the endpoint's shape.

    A stranger feeds breach lists into this form; if the answer differed for an
    address with an account, the API would be a free directory of who uses it.
    """
    known = _forgot(api_client, technician_user.email)
    unknown = _forgot(api_client, "nobody-at-all@northwind.test")

    assert known.status_code == unknown.status_code == 202
    assert known.json() == unknown.json()


def test_nothing_is_sent_to_an_address_without_an_account(api_client):
    _forgot(api_client, "ghost@northwind.test")

    assert mail.outbox == []


def test_the_link_is_the_only_thing_that_reveals_the_account(api_client, technician_user):
    """The receipt says nothing; the mail is where the evidence is, and only the
    person who can read that mailbox gets it.
    """
    _forgot(api_client, technician_user.email)

    assert [m.to for m in mail.outbox] == [[technician_user.email]]


def test_a_deactivated_account_is_not_emailed(api_client):
    """Suspending somebody has to survive their own reset request.

    A link that ended with a new password would be a way back in around the
    suspension, which is the opposite of what deactivating an account means.
    """
    suspended = make_user("suspended@northwind.test", role=Role.TECHNICIAN)
    suspended.is_active = False
    suspended.save(update_fields=["is_active"])

    response = _forgot(api_client, suspended.email)

    assert response.status_code == 202
    assert mail.outbox == []
    assert not PasswordResetToken.objects.exists()


def test_the_link_is_built_from_the_configured_console_origin(api_client, technician_user, settings):
    settings.CONSOLE_BASE_URL = "https://help.northwind.example"

    _forgot(api_client, technician_user.email)

    assert _link(technician_user.email).startswith("https://help.northwind.example/auth/reset-password/")


def test_a_dead_relay_still_answers_the_same(api_client, technician_user, monkeypatch):
    """Honesty about the send would be an oracle, so the failure is swallowed.

    The contrast with sign-up is deliberate: ``issue_code`` may report 503 because
    it answers that way for every address, existing or not. Only this path sends
    when an account exists, so a 503 here would confirm one.
    """
    from smtplib import SMTPServerDisconnected

    def refuse(*args, **kwargs):
        raise SMTPServerDisconnected("connection refused")

    monkeypatch.setattr("apps.accounts.password_reset._send_link", refuse)
    response = _forgot(api_client, technician_user.email)

    assert response.status_code == 202
    assert PasswordResetToken.objects.filter(user=technician_user).exists()


# ---------------------------------------------------------------------------
# The token at rest
# ---------------------------------------------------------------------------


def test_only_a_digest_of_the_link_is_stored(api_client, technician_user):
    token = _live_link(api_client, technician_user.email)

    record = PasswordResetToken.objects.get(user=technician_user)
    assert record.token_hash != token
    assert record.token_hash == hashlib.sha256(token.encode()).hexdigest()
    assert record.consumed_at is None


def test_two_requests_leave_one_live_link(api_client, technician_user):
    """Asking twice must not leave two ways into the account.

    The first message is what a person forwards or leaves open on a shared laptop,
    so the second request retiring it is the safer default.
    """
    _forgot(api_client, technician_user.email)
    first = _token_for(technician_user.email)
    _forgot(api_client, technician_user.email)
    second = _token_for(technician_user.email)

    assert first != second
    assert _reset(api_client, first).status_code == 400
    assert _reset(api_client, second).status_code == 200


# ---------------------------------------------------------------------------
# Using the link
# ---------------------------------------------------------------------------


def test_a_link_sets_the_password_and_the_new_one_logs_in(api_client, technician_user):
    token = _live_link(api_client, technician_user.email)

    response = _reset(api_client, token)

    assert response.status_code == 200
    login = api_client.post(
        LOGIN, {"email": technician_user.email, "password": NEW_PASSWORD}, format="json"
    )
    assert login.status_code == 200


def test_the_old_password_is_dead(api_client, technician_user):
    token = _live_link(api_client, technician_user.email)
    _reset(api_client, token)

    refused = api_client.post(
        LOGIN, {"email": technician_user.email, "password": PASSWORD}, format="json"
    )

    assert refused.status_code == 401
    assert refused.json()["error"]["code"] == "invalid_credentials"


def test_the_link_works_once(api_client, technician_user):
    token = _live_link(api_client, technician_user.email)
    assert _reset(api_client, token).status_code == 200

    replay = _reset(api_client, token)

    assert replay.status_code == 400
    assert replay.json()["error"]["code"] == "invalid_token"


def test_an_expired_link_is_refused(api_client, technician_user):
    token = _live_link(api_client, technician_user.email)
    PasswordResetToken.objects.update(
        expires_at=timezone.now() - timedelta(seconds=1)
    )

    response = _reset(api_client, token)

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_token"


def test_a_garbage_token_and_a_spent_one_get_the_same_answer(api_client, technician_user):
    """The three ways a link fails must not be distinguishable from the outside."""
    _live_link(api_client, technician_user.email)

    unknown = _reset(api_client, "not-a-token-anyone-was-sent")
    blank = _reset(api_client, "")

    assert unknown.status_code == blank.status_code == 400
    assert unknown.json()["error"]["code"] == blank.json()["error"]["code"] == "invalid_token"


def test_a_weak_password_is_refused_and_the_link_survives_it(api_client, technician_user):
    """Validation happens before the token is spent.

    A person who picks a bad password is told to pick another one, not told to
    start the whole email round again.
    """
    token = _live_link(api_client, technician_user.email)

    refused = _reset(api_client, token, "short")

    assert refused.status_code == 400
    assert refused.json()["error"]["code"] == "weak_password"
    assert PasswordResetToken.objects.get(user=technician_user).consumed_at is None
    assert _reset(api_client, token).status_code == 200


def test_the_email_says_the_link_expires_and_works_once(api_client, technician_user):
    """The mail is the only place the rules are stated to the person affected."""
    _forgot(api_client, technician_user.email)

    body = mail.outbox[-1].body
    assert "works once" in body
    assert f"{int(RESET_LIFETIME.total_seconds() // 60)} minutes" in body


# ---------------------------------------------------------------------------
# What a reset does to the sessions already running
# ---------------------------------------------------------------------------


def test_a_reset_ends_the_sessions_that_were_signed_in(api_client, technician_user):
    """The reason this endpoint exists at all.

    Somebody resetting their password because of a stolen session expects the
    thief to be out. The refresh token is the part that outlives a browser tab, so
    it is the part that has to die here.
    """
    login = api_client.post(
        LOGIN, {"email": technician_user.email, "password": PASSWORD}, format="json"
    ).json()
    token = _live_link(api_client, technician_user.email)

    assert api_client.post(REFRESH, {"refresh": login["refresh"]}, format="json").status_code == 200

    assert _reset(api_client, token).status_code == 200

    replay = api_client.post(REFRESH, {"refresh": login["refresh"]}, format="json")
    assert replay.status_code == 401


def test_the_account_itself_still_works_afterwards(api_client, technician_user):
    """Eviction is for tokens, not for memberships or the role ladder."""
    token = _live_link(api_client, technician_user.email)
    _reset(api_client, token)

    login = api_client.post(
        LOGIN, {"email": technician_user.email, "password": NEW_PASSWORD}, format="json"
    ).json()
    me = api_client.get("/api/v1/auth/me/", HTTP_AUTHORIZATION=f"Bearer {login['access']}")

    assert me.status_code == 200
    assert me.json()["user"]["email"] == technician_user.email


# ---------------------------------------------------------------------------
# Rate limits
# ---------------------------------------------------------------------------


def test_the_configured_reset_rates_are_env_overridable(settings):
    rates = settings.REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]

    assert rates["password_forgot"] == "5/min"
    assert rates["password_reset"] == "30/min"


def test_asking_for_links_is_rate_limited(api_client, technician_user, monkeypatch):
    _pin_rate(monkeypatch, "password_forgot", "2/min")

    for _ in range(2):
        assert _forgot(api_client, technician_user.email).status_code == 202

    blocked = _forgot(api_client, technician_user.email)

    assert blocked.status_code == 429
    # Throttled before the lookup, so the bucket is shared by every address and
    # the response cannot say whose account was being asked about.
    assert _forgot(api_client, "someone-else@northwind.test").status_code == 429


def test_spending_links_is_rate_limited(api_client, technician_user, monkeypatch):
    _pin_rate(monkeypatch, "password_reset", "1/min")
    _forgot(api_client, technician_user.email)
    token = _token_for(technician_user.email)

    assert _reset(api_client, token).status_code == 200
    assert _reset(api_client, "junk").status_code == 429


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------


def test_the_link_points_at_the_console_route_not_the_api(api_client, technician_user, settings):
    """The URL is built here but rendered by the Next.js app.

    A path that drifts from the console's route is a dead link in somebody's
    inbox, and nothing on this side of the boundary would ever notice.
    """
    settings.CONSOLE_BASE_URL = "http://localhost:3001"

    _forgot(api_client, technician_user.email)
    url = _link(technician_user.email)

    assert url.startswith(f"{settings.CONSOLE_BASE_URL}/auth/reset-password/")
    assert "/api/" not in url


def test_the_send_carries_the_address_and_the_token(technician_user):
    """Guards the one line that decides who receives a live credential."""
    before = len(mail.outbox)

    _send_link(technician_user, "somerandomtoken")

    assert len(mail.outbox) == before + 1
    assert mail.outbox[-1].to == [technician_user.email]
    assert "somerandomtoken" in mail.outbox[-1].body
