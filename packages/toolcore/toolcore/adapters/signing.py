"""HMAC request signing shared by the host agent and its client.

Defined once here (in the framework-free package) so the signer and the verifier
can never drift apart — a mismatch would look like a security failure but be a
maintenance one.

The signed message is ``timestamp "." nonce "." body``. Each part earns its place:

* **timestamp** bounds how long a captured request stays interesting;
* **nonce** makes each request unique, so a captured one cannot be replayed even
  inside that window. Without it an identical body signed in the same second is
  byte-for-byte reusable, and the window is a 300-second licence to replay;
* **body** binds the signature to the payload, so a signed "list services" cannot
  be edited into something else.
"""
from __future__ import annotations

import hashlib
import hmac
import threading
import time

# Requests older than this are refused, which bounds the replay window.
WINDOW_SECONDS = 300

TIMESTAMP_HEADER = "x-deskpilot-timestamp"
SIGNATURE_HEADER = "x-deskpilot-signature"
NONCE_HEADER = "x-deskpilot-nonce"


def sign(secret: str, timestamp: str, nonce: str, body: bytes) -> str:
    """HMAC-SHA256 over ``timestamp "." nonce "." body``, hex encoded."""
    message = f"{timestamp}.{nonce}.".encode("utf-8") + body
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


class NonceCache:
    """Remembers nonces long enough that a replay cannot outlive its own window.

    In-process and bounded: an entry is dropped once it is older than the signature
    window, because a nonce that can no longer appear inside a valid signature does
    not need remembering. That is enough for one host-agent process; a
    multi-process deployment would need a shared store.
    """

    def __init__(self) -> None:
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def remember(self, nonce: str, *, now: float | None = None) -> bool:
        """Record ``nonce``. Returns False when it has already been used."""
        current = time.time() if now is None else now
        with self._lock:
            self._evict(current)
            if nonce in self._seen:
                return False
            self._seen[nonce] = current + WINDOW_SECONDS
            return True

    def _evict(self, now: float) -> None:
        for key in [key for key, deadline in self._seen.items() if deadline <= now]:
            del self._seen[key]

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()


def verify(
    secret: str,
    timestamp: str | None,
    nonce: str | None,
    body: bytes,
    signature: str | None,
    *,
    now: float | None = None,
    nonce_cache: NonceCache | None = None,
) -> tuple[bool, str]:
    """Return ``(ok, reason)``; reason is empty when the signature is valid.

    ``nonce_cache`` is optional so callers that only need to check a signature are
    not forced to keep state. The host agent always passes one — replay protection
    is the entire point of the nonce.
    """
    if not secret:
        return False, "host agent token is not configured"
    if not timestamp or not signature:
        return False, "missing signature headers"
    if not nonce:
        return False, "missing nonce"

    try:
        sent_at = int(timestamp)
    except (TypeError, ValueError):
        return False, "malformed timestamp"

    current = time.time() if now is None else now
    if abs(current - sent_at) > WINDOW_SECONDS:
        return False, "timestamp outside the allowed window"

    if not hmac.compare_digest(sign(secret, timestamp, nonce, body), signature):
        return False, "signature mismatch"

    # Burn the nonce only after the signature is proven good, so an attacker cannot
    # poison the cache by replaying garbage under a nonce a real client will use.
    if nonce_cache is not None and not nonce_cache.remember(nonce, now=current):
        return False, "nonce already used"

    return True, ""
