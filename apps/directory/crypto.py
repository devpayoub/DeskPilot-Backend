"""Encryption for credentials the vault holds at rest.

The vault already keeps generated passwords away from the *model* — it only ever
sees an opaque reference. That solves the prompt-injection problem and does
nothing for the database: a dump, a backup, or a stray `.sqlite3` copied for
debugging still yields working credentials for real accounts.

So the column is encrypted. The key is a passphrase in ``VAULT_ENCRYPTION_KEY``,
stretched with SHA-256 into a Fernet key. When that variable is absent the key is
derived from ``SECRET_KEY``, which keeps a fresh clone working with no extra setup;
``prod.py`` refuses to start without an explicit value, so the convenience cannot
follow you into a deployment.

Note the consequence, stated plainly: **changing `SECRET_KEY` (or the passphrase)
makes existing rows unreadable.** That is the correct behaviour for a 15-minute
credential — they expire long before this matters — but it is not silent, because
``decrypt`` raises ``VaultDecryptionError`` rather than returning garbage.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings


class VaultDecryptionError(RuntimeError):
    """The stored ciphertext cannot be read with the configured key."""


def _fernet() -> Fernet:
    secret = (getattr(settings, "VAULT_ENCRYPTION_KEY", "") or "").strip()
    if not secret:
        secret = f"deskpilot-vault:{settings.SECRET_KEY}"
    # Fernet wants 32 raw bytes, urlsafe-base64 encoded. SHA-256 gives exactly 32
    # bytes for any passphrase length, so the operator can paste any long random
    # string instead of having to produce a correctly-shaped key.
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt(plaintext: str) -> str:
    """Return an opaque token safe to store in a text column."""
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(token: str) -> str:
    """Reverse :func:`encrypt`, or raise :class:`VaultDecryptionError`."""
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeDecodeError) as exc:
        raise VaultDecryptionError(
            "This credential cannot be decrypted with the current key. "
            "VAULT_ENCRYPTION_KEY (or SECRET_KEY) has changed since it was stored."
        ) from exc
