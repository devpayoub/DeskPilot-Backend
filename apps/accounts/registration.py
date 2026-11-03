"""Self-service sign-up: prove the address first, then open the account.

Three calls because that is the flow the console asks for — an address, a code
sent to it, then a company name and a password — and each step only reveals what
the previous one earned. The ordering matters for more than tidiness:

* **No enumeration oracle.** ``issue_code`` answers the same way whether or not an
  account already uses the address, and ``email_taken`` is only ever raised
  *after* a correct code, so learning that an email is registered requires
  receiving mail at it. ``LoginView`` makes the same bargain for passwords.
* **The code is a password, so it is hashed like one.** Six digits is twenty bits;
  a plain digest of that is reversible offline from a leaked row. See
  ``RegistrationCode``.
* **The code is not the credential for the last step.** Verification hands back a
  single-use high-entropy token, so the password is submitted without sending the
  code over the wire a second time, and a spent code cannot be replayed.

There is no mail transport configured by default: ``dev.py`` falls back to the
console backend, which prints the message — and therefore the code — to the
server's terminal, and nothing sensitive is ever returned in a response body.
Point ``EMAIL_BACKEND`` and ``EMAIL_HOST`` at a real relay in ``.env`` to send for
a deploy. If that relay fails, ``issue_code`` reports it and leaves no row behind:
a stored code that was never mailed is a guessable secret nobody can retrieve.
"""

from __future__ import annotations

import hashlib
import secrets
from smtplib import SMTPException

from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.mail import send_mail
from django.core.validators import validate_email
from django.db import transaction
from django.utils import timezone

from apps.organizations.services import MIN_PASSWORD_LENGTH, TenancyError, create_organization

from .models import (
    CODE_LIFETIME,
    MAX_CODE_ATTEMPTS,
    VERIFICATION_LIFETIME,
    CustomUser,
    RegistrationCode,
)


class RegistrationError(Exception):
    """A sign-up refusal with a machine-readable code.

    Same contract as ``TenancyError``: the view translates it into the project's
    ``{"error": {"code", "message"}}`` envelope and never has to guess.
    """

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _clean_email(raw: object) -> str:
    email = str(raw or "").strip().lower()
    if not email:
        raise RegistrationError("invalid_email", "An email address is required.")
    try:
        validate_email(email)
    except DjangoValidationError as exc:
        raise RegistrationError("invalid_email", "That is not a valid email address.") from exc
    return email


def _display_name_for(email: str) -> str:
    """Same derivation ``create_member`` uses — the local part, prettified.

    Sign-up does not ask for a name, so the address is all there is to go on.
    """
    return email.split("@")[0].replace(".", " ").replace("_", " ").title()


def _send_code(email: str, code: str) -> None:
    body = (
        f"Your DeskPilot sign-up code is {code}.\n\n"
        f"It expires in {int(CODE_LIFETIME.total_seconds() // 60)} minutes and works once.\n"
        "If you did not ask to create an account, you can ignore this.\n"
    )
    send_mail(
        subject="Your DeskPilot sign-up code",
        message=body,
        from_email=None,
        recipient_list=[email],
        fail_silently=False,
    )


def issue_code(raw_email: object) -> RegistrationCode:
    """Start sign-up: put a fresh six-digit code on an address.

    The return value deliberately does not carry the code — it exists only inside
    this function and inside the email. The caller cannot read it back out of the
    row either, because only a password hash of it is stored.
    """
    email = _clean_email(raw_email)

    with transaction.atomic():
        # One live code per address. Dropping the earlier rows keeps a stale code
        # from being a second thing to guess at, and clears out expired rows on the
        # way through instead of needing a scheduled purge.
        RegistrationCode.objects.filter(email=email).delete()
        code = f"{secrets.randbelow(1_000_000):06d}"
        record = RegistrationCode.objects.create(
            email=email,
            code_hash=make_password(code),
            expires_at=timezone.now() + CODE_LIFETIME,
        )

    try:
        _send_code(email, code)
    except (SMTPException, OSError) as exc:
        # A relay that is down or wrongly configured is the one failure this step
        # can honestly report. The row goes with it: a code nobody was mailed is a
        # guessable secret sitting in the table, and the person at the page would
        # otherwise be told to check an inbox that will never arrive.
        record.delete()
        raise RegistrationError(
            "email_not_sent",
            "We could not send the code right now. Try again in a moment.",
        ) from exc
    return record


def verify_code(raw_email: object, raw_code: object) -> str:
    """Check a code and trade it for a single-use verification token."""
    email = _clean_email(raw_email)
    code = str(raw_code or "").strip()
    if not code:
        raise RegistrationError("invalid_code", "Enter the code from your email.")

    record = (
        RegistrationCode.objects.filter(email=email, consumed_at__isnull=True)
        .order_by("-created_at")
        .first()
    )
    if record is None or not record.is_live:
        # Covers "never requested", "expired" and "guessed too often" with one
        # answer: all three mean the same thing to the person at the keyboard.
        raise RegistrationError("invalid_code", "That code is not valid. Ask for a new one.")

    if record.verification_hash:
        # The code has already been traded for a token, so it is spent even though
        # the row is not consumed yet — otherwise every re-submission of a correct
        # code would mint a second token and the code would be a standing credential
        # for the fifteen minutes the token lives. Checking this before the hash
        # comparison also keeps a replay from costing a PBKDF2 round.
        raise RegistrationError(
            "invalid_code", "That code has already been used. Ask for a new one."
        )

    if not check_password(code, record.code_hash):
        record.attempts += 1
        if record.attempts >= MAX_CODE_ATTEMPTS:
            # Burn it rather than leave it live: a spent row can only be replaced
            # by a new send, which is also the throttle's cue to slow down.
            record.consumed_at = timezone.now()
            record.save(update_fields=["attempts", "consumed_at"])
            raise RegistrationError(
                "too_many_attempts", "Too many wrong tries. Request a new code and start again."
            )
        record.save(update_fields=["attempts"])
        raise RegistrationError("invalid_code", "That code is not valid.")

    if CustomUser.objects.filter(email=email).exists():
        # Only reachable with the code in hand, so this is not an enumeration oracle.
        raise RegistrationError("email_taken", "An account already uses this address.")

    token = secrets.token_urlsafe(32)
    record.verification_hash = _digest(token)
    # The row's clock now runs for the last step, not for the code — the code has
    # been spent, and this is the window in which the password can be submitted.
    record.expires_at = timezone.now() + VERIFICATION_LIFETIME
    record.save(update_fields=["verification_hash", "expires_at"])
    return token


def finalize_registration(raw_token: object, raw_name: object, raw_password: object):
    """Create the account, its organisation and its first administrator.

    Returns ``(user, organization, membership)``.
    """
    token = str(raw_token or "").strip()
    if not token:
        raise RegistrationError("invalid_verification", "Verify your email address first.")

    record = RegistrationCode.objects.filter(verification_hash=_digest(token)).first()
    if record is None or not record.verification_is_live or record.expires_at <= timezone.now():
        raise RegistrationError(
            "invalid_verification", "That verification has expired. Start sign-up again."
        )

    email = record.email
    password = str(raw_password or "")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise RegistrationError(
            "weak_password", f"Choose a password of at least {MIN_PASSWORD_LENGTH} characters."
        )

    user = CustomUser(email=email, display_name=_display_name_for(email), role="REQUESTER")
    try:
        validate_password(password, user)
    except DjangoValidationError as exc:
        raise RegistrationError("weak_password", " ".join(exc.messages)) from exc

    with transaction.atomic():
        # Re-checked inside the transaction: two tabs can finish the same verified
        # address at once, and the unique email constraint is the real guard.
        if CustomUser.objects.filter(email=email).exists():
            raise RegistrationError("email_taken", "An account already uses this address.")

        user.set_password(password)
        user.is_active = True
        user.save()

        try:
            organization, membership = create_organization(str(raw_name or ""), owner=user)
        except TenancyError as exc:
            raise RegistrationError(exc.code, exc.message) from exc

        record.consumed_at = timezone.now()
        record.verification_hash = ""
        record.save(update_fields=["consumed_at", "verification_hash"])

    return user, organization, membership
