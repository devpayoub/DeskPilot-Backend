"""Self-service sign-up: address → code → company name and password.

These three endpoints are the only unauthenticated write surface this API has, so
most of what is asserted here is about what a stranger can *learn* from them:
that an address is registered, that a code is close, that a guess is left.
"""
from __future__ import annotations

import re
from datetime import timedelta

import pytest
from django.core import mail
from django.utils import timezone
from rest_framework.throttling import ScopedRateThrottle

from apps.accounts.models import MAX_CODE_ATTEMPTS, RegistrationCode, Role
from apps.organizations.models import Membership, Organization
from tests.factories import PASSWORD, make_user

pytestmark = pytest.mark.django_db

ISSUE = "/api/v1/auth/register-code/"
VERIFY = "/api/v1/auth/register-code-verify/"
REGISTER = "/api/v1/auth/register/"
LOGIN = "/api/v1/auth/login/"
ME = "/api/v1/auth/me/"

NEW_EMAIL = "priya.nair@northwind.test"
COMPANY = "Northwind IT"


def _issue(api_client, email: str = NEW_EMAIL):
    return api_client.post(ISSUE, {"email": email}, format="json")


def _sent_code(email: str = NEW_EMAIL) -> str:
    """Read the newest code for an address out of its email."""
    message = [m for m in mail.outbox if m.to == [email]][-1]
    return re.search(r"code is (\d{6})", message.body).group(1)


def _wrong_code(email: str = NEW_EMAIL) -> str:
    correct = _sent_code(email)
    return next(c for c in ("999999", "888888", "777777") if c != correct)


def _verify(api_client, email: str, code: str):
    return api_client.post(VERIFY, {"email": email, "code": code}, format="json")


def _verified(api_client, email: str = NEW_EMAIL) -> str:
    """Walk the first two steps and hand back the verification token."""
    assert _issue(api_client, email).status_code == 202
    response = _verify(api_client, email, _sent_code(email))
    assert response.status_code == 200, response.json()
    return response.json()["verification"]


def _signup(api_client, email: str = NEW_EMAIL, name: str = COMPANY, password: str = PASSWORD):
    return api_client.post(
        REGISTER,
        {"verification": _verified(api_client, email), "company_name": name, "password": password},
        format="json",
    )


# ---------------------------------------------------------------------------
# Step one: send the code
# ---------------------------------------------------------------------------


def test_issuing_a_code_returns_a_receipt_and_nothing_else(api_client):
    response = _issue(api_client)

    assert response.status_code == 202
    assert set(response.json()) == {"sent", "expires_in"}
    assert response.json()["expires_in"] == 600


def test_the_code_is_emailed_and_never_stored_readable(api_client):
    _issue(api_client)
    code = _sent_code()

    assert len(code) == 6 and code.isdigit()
    record = RegistrationCode.objects.get(email=NEW_EMAIL)
    assert code not in record.code_hash, "the row must not carry the code"
    assert record.code_hash != code
    assert "$" in record.code_hash, "a password hasher, not a bare digest"


def test_a_second_send_replaces_the_first_code(api_client):
    _issue(api_client)
    _issue(api_client)

    assert RegistrationCode.objects.filter(email=NEW_EMAIL).count() == 1
    assert len([m for m in mail.outbox if m.to == [NEW_EMAIL]]) == 2


def test_an_unknown_address_is_not_told_it_is_unknown(api_client):
    """The response cannot be an enumeration oracle, so it is character-identical."""
    fresh = _issue(api_client, NEW_EMAIL)
    make_user(NEW_EMAIL)
    taken = _issue(api_client, "someone-else@northwind.test")

    assert fresh.status_code == taken.status_code == 202
    assert fresh.json() == taken.json()


def test_a_malformed_address_is_refused(api_client):
    response = _issue(api_client, "not-an-email")

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_email"


def test_a_dead_relay_is_reported_and_leaves_no_code(api_client, monkeypatch):
    """The one failure the first step can have once ``EMAIL_HOST`` is real.

    A code that was never mailed is a guessable secret sitting in the table, and a
    202 would send the person at the page to an inbox that will never arrive.
    """
    from smtplib import SMTPServerDisconnected

    def refuse(*args, **kwargs):
        raise SMTPServerDisconnected("connection refused")

    monkeypatch.setattr("apps.accounts.registration._send_code", refuse)
    response = _issue(api_client)

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "email_not_sent"
    assert not RegistrationCode.objects.exists()


def test_a_dead_relay_leaves_the_sign_up_resumable(api_client, monkeypatch):
    """Nothing is remembered from the failed attempt, so the next send is clean."""
    from smtplib import SMTPServerDisconnected

    def refuse(*args, **kwargs):
        raise SMTPServerDisconnected("connection refused")

    monkeypatch.setattr("apps.accounts.registration._send_code", refuse)
    assert _issue(api_client).status_code == 503

    monkeypatch.undo()
    assert _issue(api_client).status_code == 202
    assert _verify(api_client, NEW_EMAIL, _sent_code()).status_code == 200


# ---------------------------------------------------------------------------
# Step two: check the code
# ---------------------------------------------------------------------------


def test_a_correct_code_hands_back_a_single_use_token(api_client):
    _issue(api_client)

    response = _verify(api_client, NEW_EMAIL, _sent_code())

    assert response.status_code == 200
    body = response.json()
    assert body["verified"] is True
    assert len(body["verification"]) >= 32
    assert body["expires_in"] == 900
    record = RegistrationCode.objects.get(email=NEW_EMAIL)
    assert body["verification"] not in record.verification_hash, "only a digest is stored"


def test_a_wrong_code_is_refused_and_counted(api_client):
    _issue(api_client)

    response = _verify(api_client, NEW_EMAIL, _wrong_code())

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_code"
    assert RegistrationCode.objects.get(email=NEW_EMAIL).attempts == 1


def test_five_wrong_guesses_burn_the_code(api_client):
    _issue(api_client)
    correct = _sent_code()
    guesses = [f"{n:06d}" for n in range(111111, 111111 + MAX_CODE_ATTEMPTS + 1)]
    guesses = [g for g in guesses if g != correct][:MAX_CODE_ATTEMPTS]

    for guess in guesses[:-1]:
        assert _verify(api_client, NEW_EMAIL, guess).status_code == 400

    exhausted = _verify(api_client, NEW_EMAIL, guesses[-1])

    assert exhausted.status_code == 429
    assert exhausted.json()["error"]["code"] == "too_many_attempts"
    assert RegistrationCode.objects.get(email=NEW_EMAIL).consumed_at is not None
    # Even the right code no longer works: the row is dead, not merely tired.
    assert _verify(api_client, NEW_EMAIL, correct).status_code == 400


def test_an_expired_code_is_refused(api_client):
    _issue(api_client)
    code = _sent_code()
    RegistrationCode.objects.filter(email=NEW_EMAIL).update(
        expires_at=timezone.now() - timedelta(seconds=1)
    )

    response = _verify(api_client, NEW_EMAIL, code)

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_code"


def test_a_correct_code_works_once(api_client):
    _issue(api_client)
    code = _sent_code()
    assert _verify(api_client, NEW_EMAIL, code).status_code == 200

    again = _verify(api_client, NEW_EMAIL, code)

    assert again.status_code == 400
    assert again.json()["error"]["code"] == "invalid_code"


def test_a_registered_address_is_only_revealed_after_the_correct_code(api_client):
    """Knowing the address is not enough — the caller has to receive mail at it."""
    make_user(NEW_EMAIL)
    assert _issue(api_client).status_code == 202

    response = _verify(api_client, NEW_EMAIL, _sent_code())

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "email_taken"


# ---------------------------------------------------------------------------
# Step three: open the account
# ---------------------------------------------------------------------------


def test_sign_up_creates_an_account_the_registrant_owns(api_client):
    response = _signup(api_client)

    assert response.status_code == 201, response.json()
    body = response.json()
    assert body["access"] and body["refresh"]
    assert body["user"]["email"] == NEW_EMAIL
    assert body["user"]["full_name"], "the console renders this in the sidebar"
    assert body["organization"]["organization_name"] == COMPANY
    assert body["organization"]["role"] == Role.ADMIN
    assert body["organization"]["is_owner"] is True

    organization = Organization.objects.get(slug="northwind-it")
    assert organization.is_active
    assert Membership.objects.filter(organization=organization).count() == 1


def test_the_new_session_sees_its_own_account(api_client):
    signed_in = _signup(api_client).json()
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {signed_in['access']}")

    me = api_client.get(ME).json()

    assert me["user"]["email"] == NEW_EMAIL
    assert me["active_organization"]["organization_slug"] == "northwind-it"
    assert len(me["memberships"]) == 1, "a sign-up joins nobody else's workspace"
    assert set(me["role_capabilities"][Role.ADMIN]) >= {"member:manage", "killswitch:write"}


def test_the_password_works_for_login_afterwards(api_client):
    _signup(api_client)

    response = api_client.post(LOGIN, {"email": NEW_EMAIL, "password": PASSWORD}, format="json")

    assert response.status_code == 200, "sign-up must produce a usable credential"


def test_a_weak_password_is_refused_and_can_be_retried(api_client):
    verification = _verified(api_client)

    response = api_client.post(
        REGISTER,
        {"verification": verification, "company_name": COMPANY, "password": "short"},
        format="json",
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "weak_password"
    assert not Organization.objects.filter(slug="northwind-it").exists()

    retry = api_client.post(
        REGISTER,
        {"verification": verification, "company_name": COMPANY, "password": PASSWORD},
        format="json",
    )

    assert retry.status_code == 201, "a refusal must not spend the verification"


def test_a_common_password_is_refused(api_client):
    verification = _verified(api_client)

    response = api_client.post(
        REGISTER,
        {"verification": verification, "company_name": COMPANY, "password": "password"},
        format="json",
    )

    assert response.status_code == 400
    assert "common" in response.json()["error"]["message"].lower()


def test_the_verification_token_works_once(api_client):
    verification = _verified(api_client)
    assert api_client.post(
        REGISTER,
        {"verification": verification, "company_name": COMPANY, "password": PASSWORD},
        format="json",
    ).status_code == 201

    replay = api_client.post(
        REGISTER,
        {"verification": verification, "company_name": "Second Attempt", "password": PASSWORD},
        format="json",
    )

    assert replay.status_code == 400
    assert replay.json()["error"]["code"] == "invalid_verification"
    assert not Organization.objects.filter(name="Second Attempt").exists()


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"company_name": COMPANY, "password": PASSWORD},
        {"verification": "not-a-token", "company_name": COMPANY, "password": PASSWORD},
    ],
)
def test_the_last_step_cannot_be_reached_without_verifying(api_client, body):
    response = api_client.post(REGISTER, body, format="json")

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_verification"


def test_a_blank_company_name_is_refused(api_client):
    verification = _verified(api_client)

    response = api_client.post(
        REGISTER,
        {"verification": verification, "company_name": "   ", "password": PASSWORD},
        format="json",
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_organization_name"
    assert not RegistrationCode.objects.get(email=NEW_EMAIL).consumed_at, (
        "the refusal rolled the whole thing back, code row included"
    )


def test_two_accounts_can_share_a_company_name(api_client):
    """Slugs collide; people must not be told their business already exists."""
    assert _signup(api_client, NEW_EMAIL, COMPANY).status_code == 201
    assert _signup(api_client, "sam@northwind.test", COMPANY).status_code == 201

    slugs = sorted(
        Organization.objects.filter(name=COMPANY).values_list("slug", flat=True)
    )
    assert slugs == ["northwind-it", "northwind-it-2"]


def test_a_new_send_invalidates_a_verification_in_flight(api_client):
    verification = _verified(api_client)

    _issue(api_client)

    response = api_client.post(
        REGISTER,
        {"verification": verification, "company_name": COMPANY, "password": PASSWORD},
        format="json",
    )

    assert response.status_code == 400
    assert not Organization.objects.filter(slug="northwind-it").exists()


# ---------------------------------------------------------------------------
# Rate limits
# ---------------------------------------------------------------------------


def test_the_configured_sign_up_rates_are_env_overridable(settings):
    rates = settings.REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]
    assert rates["register_issue"] == "5/min"
    assert rates["register_verify"] == "10/min"
    assert rates["register_finalize"] == "20/hour"


def _pin_rate(monkeypatch, scope: str, rate: str) -> None:
    """Pin one scope's rate for a test.

    DRF copies ``DEFAULT_THROTTLE_RATES`` onto the throttle class at import time, so
    reassigning ``settings.REST_FRAMEWORK`` mid-test changes nothing the request can
    see. ``get_rate()`` reads the class attribute, once per request.
    """
    monkeypatch.setattr(
        ScopedRateThrottle, "THROTTLE_RATES", {**ScopedRateThrottle.THROTTLE_RATES, scope: rate}
    )


def test_issuing_codes_is_rate_limited(api_client, monkeypatch):
    _pin_rate(monkeypatch, "register_issue", "2/min")

    for address in ("a@northwind.test", "b@northwind.test", "c@northwind.test"):
        response = _issue(api_client, address)

    assert response.status_code == 429
    assert response.json()["error"]["code"] == "throttled"


def test_guessing_codes_is_rate_limited(api_client, monkeypatch):
    _issue(api_client)
    wrong = _wrong_code()
    _pin_rate(monkeypatch, "register_verify", "2/min")

    for _ in range(3):
        response = _verify(api_client, NEW_EMAIL, wrong)

    assert response.status_code == 429


def test_finishing_sign_up_is_rate_limited(api_client, monkeypatch):
    first = _verified(api_client, "a@northwind.test")
    second = _verified(api_client, "b@northwind.test")
    _pin_rate(monkeypatch, "register_finalize", "1/min")

    for verification, name in ((first, "First Co"), (second, "Second Co")):
        response = api_client.post(
            REGISTER,
            {"verification": verification, "company_name": name, "password": PASSWORD},
            format="json",
        )

    assert response.status_code == 429
    assert not Organization.objects.filter(name="Second Co").exists()
