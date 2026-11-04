"""Password vault: holds a generated credential for a human, never for the model."""
from __future__ import annotations

import logging
from datetime import timedelta

from django.utils import timezone

from .crypto import encrypt
from .models import PasswordReset

logger = logging.getLogger(__name__)

TTL_MINUTES = 15


def purge_expired() -> int:
    """Delete expired credentials. Returns the number removed.

    ``expires_at`` alone only blocks *retrieval*; without this the plaintext row
    survives forever, so a database dump would still yield every password the
    agent ever generated — including ones still valid somewhere else. Expiry has
    to mean deletion, not just a closed door.

    Deliberately not tenant-scoped: this is the one query that should cross every
    organisation, because an expired secret in someone else's workspace is still a
    secret that failed to die.
    """
    removed, _ = PasswordReset.objects.filter(expires_at__lte=timezone.now()).delete()
    if removed:
        logger.info("purged %d expired password reset record(s)", removed)
    return removed


def store_password(organization, sam: str, password: str, force_change: bool = True) -> str:
    """Persist a generated password and return the opaque reference the agent sees.

    The caller's organisation is recorded on the row so that retrieval can be checked
    against it. Without that, a reference that leaked into a log line would be
    spendable by anyone holding ``directory:read`` anywhere on the platform.
    """
    if organization is None:
        raise ValueError(
            "Refusing to vault a password with no owning organisation — it could "
            "not be scoped on the way back out."
        )
    purge_expired()
    record = PasswordReset.objects.create(
        organization=organization,
        sam=sam,
        password_ciphertext=encrypt(password),
        force_change=force_change,
        expires_at=timezone.now() + timedelta(minutes=TTL_MINUTES),
    )
    logger.info("stored password reset reference=%s sam=%s", record.reference, sam)
    return str(record.reference)


def retrieve_password(reference, organization) -> PasswordReset:
    """Fetch a stored password. Raises ValueError when unusable.

    An unknown reference and a reference owned by another workspace answer the same
    way on purpose: "no password reset with that reference" tells an attacker that
    the uuid they found in a log is real without handing them the secret.
    """
    if organization is None:
        raise ValueError("No password reset with that reference.")
    record = PasswordReset.objects.filter(reference=reference, organization=organization).first()
    if record is None:
        raise ValueError("No password reset with that reference.")
    if record.is_expired:
        raise ValueError("This password has expired and must be reset again.")
    if record.retrieved_at is not None:
        raise ValueError("This password has already been retrieved.")

    record.retrieved_at = timezone.now()
    record.save(update_fields=["retrieved_at"])
    return record
