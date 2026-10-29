"""HMAC request signing shared by the host agent and its client.

Defined once here (in the framework-free package) so the signer and the verifier
can never drift apart — a mismatch would look like a security failure but be a
maintenance one.
"""
from __future__ import annotations

import hashlib
import hmac
import time

# Requests older than this are refused, which bounds the replay window.
WINDOW_SECONDS = 300

TIMESTAMP_HEADER = "x-deskpilot-timestamp"
SIGNATURE_HEADER = "x-deskpilot-signature"


def sign(secret: str, timestamp: str, body: bytes) -> str:
    """HMAC-SHA256 over ``timestamp + "." + body``, hex encoded."""
    message = timestamp.encode("utf-8") + b"." + body
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def verify(
    secret: str,
    timestamp: str | None,
    body: bytes,
    signature: str | None,
    *,
    now: float | None = None,
) -> tuple[bool, str]:
    """Return ``(ok, reason)``; reason is empty when the signature is valid."""
    if not secret:
        return False, "host agent token is not configured"
    if not timestamp or not signature:
        return False, "missing signature headers"

    try:
        sent_at = int(timestamp)
    except (TypeError, ValueError):
        return False, "malformed timestamp"

    current = time.time() if now is None else now
    if abs(current - sent_at) > WINDOW_SECONDS:
        return False, "timestamp outside the allowed window"

    if not hmac.compare_digest(sign(secret, timestamp, body), signature):
        return False, "signature mismatch"
    return True, ""
