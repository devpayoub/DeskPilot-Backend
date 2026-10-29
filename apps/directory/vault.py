"""Password vault: holds a generated credential for a human, never for the model."""
from __future__ import annotations

import logging
from datetime import timedelta

from django.utils import timezone

from .models import PasswordReset

logger = logging.getLogger(__name__)

TTL_MINUTES = 15


def store_password(sam: str, password: str, force_change: bool = True) -> str:
    """Persist a generated password and return the opaque reference the agent sees."""
    record = PasswordReset.objects.create(
        sam=sam,
        password=password,
        force_change=force_change,
        expires_at=timezone.now() + timedelta(minutes=TTL_MINUTES),
    )
    logger.info("stored password reset reference=%s sam=%s", record.reference, sam)
    return str(record.reference)


def retrieve_password(reference) -> PasswordReset:
    """Fetch a stored password. Raises ValueError when unusable."""
    record = PasswordReset.objects.filter(reference=reference).first()
    if record is None:
        raise ValueError("No password reset with that reference.")
    if record.is_expired:
        raise ValueError("This password has expired and must be reset again.")
    if record.retrieved_at is not None:
        raise ValueError("This password has already been retrieved.")

    record.retrieved_at = timezone.now()
    record.save(update_fields=["retrieved_at"])
    return record
