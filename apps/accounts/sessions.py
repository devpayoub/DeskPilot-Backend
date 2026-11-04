"""The sign-ins a person can see and end.

``OutstandingToken`` is SimpleJWT's own ledger: one row per refresh token handed
out, and a ``BlacklistedToken`` child once that session has been ended. It is the
only place this API records that a sign-in exists, so it is what the security page
reads. A parallel session table would be a second truth, and the first thing it
would drift away from is the thing that actually authorises a request.

What the ledger does *not* hold is a device name, an IP or a user agent — the
token is a signed claim, not a browser fingerprint. So the console shows when a
sign-in started and when it dies, and nothing else. Inventing "Chrome on Windows"
here would be a decoration people trust when deciding whether a session is theirs.

A refresh token is the part that outlives the tab, so this is all revocation
meaning: the sign-in cannot be renewed. The access token already in that client's
hand still rides out its fifteen minutes; there is no per-request revocation list
and adding one would cost a database read on every call.
"""

from __future__ import annotations

from django.utils import timezone
from rest_framework_simplejwt.token_blacklist.models import (
    BlacklistedToken,
    OutstandingToken,
)


def live_sessions(user) -> list[OutstandingToken]:
    """Sessions that can still be renewed, newest first.

    Expired rows are excluded on purpose. SimpleJWT leaves them in the table until
    ``flushexpiredtokens`` runs, and a list of "active sign-ins" that includes
    tokens which stopped working days ago would have people revoking nothing and
    wondering why the count never drops.
    """
    return list(
        OutstandingToken.objects.filter(
            user=user,
            blacklistedtoken__isnull=True,
            expires_at__gt=timezone.now(),
        ).order_by("-created_at", "-id")
    )


def serialize_session(row: OutstandingToken, current_jti: str | None) -> dict:
    """One row, in the shape the console renders.

    ``row.token`` is the refresh token itself and must never leave this function.
    A session identifier is safe to show; the credential is not.
    """
    return {
        "jti": row.jti,
        "signed_in_at": row.created_at.isoformat() if row.created_at else None,
        "expires_at": row.expires_at.isoformat(),
        "current": bool(current_jti) and row.jti == current_jti,
    }


def revoke_session(user, jti: str) -> bool:
    """End one sign-in. ``False`` when there was no live session by that id.

    Filtered by ``user`` before anything else, so a guessed jti from another
    account's session is simply not found — the same 404 as one that never existed.
    """
    row = OutstandingToken.objects.filter(
        user=user, jti=jti, blacklistedtoken__isnull=True
    ).first()
    if row is None:
        return False

    BlacklistedToken.objects.create(token=row)
    return True
