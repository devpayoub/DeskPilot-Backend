"""Password reset: prove the mailbox, then let its owner pick a new password.

The link goes to the address on the account, which is the only proof this project
has that the person asking is the person who owns it. The shape follows
``registration.py`` because the threat is the same — a public endpoint that hands
out a secret and eventually writes a password — with one difference worth the
whole file: a reset token is 256 bits, so it is stored as a SHA-256 digest rather
than with Django's password hashers. A six-digit sign-up code has to be hashed
like a password because twenty bits is guessable offline; nothing about this token
is guessable at all.

Two rules hold the rest of the design up:

* **No enumeration oracle.** ``issue_reset`` answers the same way for an address
  with an account and one without, so "forgot password" cannot be used to list
  who is registered. Only the mail says anything, and only the person who can
  read that mailbox sees it.
* **The token dies with the password.** It is spent inside the same transaction
  that writes the new hash, and every other live token for the account goes with
  it — an old link in an inbox must not be able to undo a reset.
"""

from __future__ import annotations

import hashlib
import secrets
from smtplib import SMTPException

from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.mail import send_mail
from django.db import transaction
from django.utils import timezone

from apps.organizations.services import MIN_PASSWORD_LENGTH

from .models import RESET_LIFETIME, CustomUser, PasswordResetToken


class ResetError(Exception):
    """A refusal with a machine-readable code, same contract as ``TenancyError``."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _reset_url(token: str) -> str:
    base = str(getattr(settings, "CONSOLE_BASE_URL", "") or "").rstrip("/")
    return f"{base}/auth/reset-password/{token}/"


def _send_link(user, token: str) -> None:
    link = _reset_url(token)
    minutes = int(RESET_LIFETIME.total_seconds() // 60)
    body = (
        f"Somebody asked to reset the password for {user.email} on DeskPilot.\n\n"
        f"Set a new password here: {link}\n\n"
        f"The link works once and expires in {minutes} minutes.\n"
        "If you did not ask for this, nothing needs doing — your password is "
        "unchanged until a link is used.\n"
    )
    send_mail(
        subject="Reset your DeskPilot password",
        message=body,
        from_email=None,
        recipient_list=[user.email],
        fail_silently=False,
    )


def issue_reset(raw_email: object) -> bool:
    """Mail a reset link if an active account uses this address.

    The return value is for logs and tests only — no view may show it. Telling the
    caller "no account here" is exactly the enumeration answer this endpoint is
    not allowed to give.

    A mail transport that is down is swallowed rather than reported, for the same
    reason: the send only happens for a real account, so a 503 on one address and a
    202 on another would answer the question the endpoint exists to keep secret.
    Sign-up can afford to be honest about a failed send because it answers the same
    way whichever address it is given.
    """
    email = str(raw_email or "").strip().lower()
    if not email:
        return False

    user = CustomUser.objects.filter(email=email, is_active=True).first()
    if user is None:
        return False

    token = secrets.token_urlsafe(32)
    with transaction.atomic():
        # Newest link wins. An earlier row stays readable for the audit trail but
        # stops working the moment a second request is made, so a person who asks
        # twice is never holding two live ways into the same account.
        PasswordResetToken.objects.filter(user=user, consumed_at__isnull=True).update(
            consumed_at=timezone.now()
        )
        PasswordResetToken.objects.create(
            user=user,
            token_hash=_digest(token),
            expires_at=timezone.now() + RESET_LIFETIME,
        )

    try:
        _send_link(user, token)
    except (SMTPException, OSError):
        return False
    return True


def check_password_strength(password: str, user) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ResetError(
            "weak_password", f"Choose a password of at least {MIN_PASSWORD_LENGTH} characters."
        )
    try:
        validate_password(password, user)
    except DjangoValidationError as exc:
        raise ResetError("weak_password", " ".join(exc.messages)) from exc


def finalize_reset(raw_token: object, raw_password: object) -> CustomUser:
    """Spend the link and write the new password, evicting every old session."""
    token = str(raw_token or "").strip()
    if not token:
        raise ResetError("invalid_token", "This reset link is not valid. Ask for a new one.")

    record = (
        PasswordResetToken.objects.select_related("user")
        .filter(token_hash=_digest(token))
        .first()
    )
    # One message for "never existed", "expired" and "already used". They differ on
    # the server, where the rows say which, and must not differ in the answer.
    if record is None or not record.is_live:
        raise ResetError("invalid_token", "This reset link has expired or was already used.")

    user = record.user
    if not user.is_active:
        # A reset must not walk a deactivated account back in. Suspending someone
        # is a decision an administrator made for a reason, and the only path out
        # of it is them deciding otherwise.
        raise ResetError("account_inactive", "This account has been deactivated.")

    password = str(raw_password or "")
    check_password_strength(password, user)

    with transaction.atomic():
        # Re-read inside the transaction: two tabs can open the same link at once
        # and only the first may take the account.
        locked = (
            PasswordResetToken.objects.select_for_update()
            .filter(pk=record.pk)
            .first()
        )
        if locked is None or locked.consumed_at is not None or locked.expires_at <= timezone.now():
            raise ResetError("invalid_token", "This reset link has expired or was already used.")

        user.set_password(password)
        # Django's own update_last_login is off in this project, so nothing else
        # records the event; the token row below is the timestamp that matters.
        user.save(update_fields=["password", "password_updated_at"])

        locked.consumed_at = timezone.now()
        locked.save(update_fields=["consumed_at"])

        # Every other link for this account dies too, spent or not.
        PasswordResetToken.objects.filter(user=user, consumed_at__isnull=True).update(
            consumed_at=timezone.now()
        )
        revoke_sessions(user)

    return user


def revoke_sessions(user) -> int:
    """Blacklist the account's outstanding refresh tokens, and say how many.

    Somebody who resets their password because of a stolen session expects that
    session to end. The access token still rides out its fifteen minutes — this API
    has no per-request revocation list for those, and adding one would cost a
    database read on every call — but a refresh is the part that outlives the tab,
    and it dies here.

    The count is returned because the change-password endpoint tells the person how
    many sign-ins it just ended. That number is the difference between "your
    password changed" and "you are the only one left holding the account" — which is
    why it counts the same set the security page lists. SimpleJWT keeps expired rows
    in the ledger until ``flushexpiredtokens`` runs; blacklisting one ends no
    sign-in, and reporting it inflates the number a frightened person is reading.
    """
    from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken

    from apps.accounts.sessions import live_sessions

    outstanding = live_sessions(user)
    BlacklistedToken.objects.bulk_create(
        [BlacklistedToken(token=row) for row in outstanding]
    )
    return len(outstanding)
