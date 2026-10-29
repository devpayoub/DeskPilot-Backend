"""HMAC request signing for the host agent.

The implementation lives in ``toolcore.adapters.signing`` so the client and the
server share one definition; this module is the host agent's import surface.
"""
from __future__ import annotations

from toolcore.adapters.signing import (  # noqa: F401
    NONCE_HEADER,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    WINDOW_SECONDS,
    NonceCache,
    sign,
    verify,
)

__all__ = [
    "NONCE_HEADER",
    "SIGNATURE_HEADER",
    "TIMESTAMP_HEADER",
    "WINDOW_SECONDS",
    "NonceCache",
    "sign",
    "verify",
]
