"""Argument redaction and hashing.

Two jobs, both load-bearing:

* ``redact_args`` — the audit row must be readable without ever storing a secret.
* ``args_hash`` — the approval gate freezes a hash of the validated arguments, so
  approving one argument set can never execute a different one (TOCTOU defence).

Plus ``redact_text`` / ``redact_deep``, which scrub credentials out of free text —
provider error bodies, exception messages — before it reaches a database column or
a console screen.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable

# Substring match on the lowercased key: catches password, new_password,
# api_key, access_token, client_secret, ...
_SENSITIVE_HINTS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "credential",
    "authorization",
    "private_key",
)

_MAX_STR = 200
_MAX_ITEMS = 20
_MAX_DEPTH = 4


def _is_sensitive(key: str) -> bool:
    lowered = key.lower()
    return any(hint in lowered for hint in _SENSITIVE_HINTS)


def redact_args(args: Any, _depth: int = 0) -> Any:
    """Return a JSON-safe copy with sensitive values masked and sizes bounded."""
    if _depth > _MAX_DEPTH:
        return "<max-depth>"
    if isinstance(args, dict):
        out = {}
        for key, value in list(args.items())[:_MAX_ITEMS]:
            out[key] = "***" if _is_sensitive(str(key)) else redact_args(value, _depth + 1)
        if len(args) > _MAX_ITEMS:
            out["__omitted_keys"] = len(args) - _MAX_ITEMS
        return out
    if isinstance(args, (list, tuple)):
        items = [redact_args(v, _depth + 1) for v in list(args)[:_MAX_ITEMS]]
        if len(args) > _MAX_ITEMS:
            return {"items": items, "omitted_items": len(args) - _MAX_ITEMS}
        return items
    if isinstance(args, str):
        return args if len(args) <= _MAX_STR else args[:_MAX_STR] + "…"
    if isinstance(args, (int, float, bool)) or args is None:
        return args
    return f"<{type(args).__name__}>"


def args_hash(args: Any) -> str:
    """Stable SHA-256 over the canonical JSON form of the arguments."""
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Free-text redaction
# ---------------------------------------------------------------------------
# ``redact_args`` masks by *key name*: it knows "password" holds a secret. This
# masks by *shape*, because the text that reaches a step record or an audit row is
# not a structured argument — it is whatever a provider, an SDK or an exception
# chose to say. Provider error bodies are third-party text: they land in the
# database and are rendered in the console, so they need scrubbing before storage,
# not after.
_MASK = "***"
_MAX_TEXT = 600

# (pattern, replacement). Ordered so the specific shapes run before the generic
# ``key=value`` rule, which would otherwise swallow a whole URL.
_TEXT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # OpenAI-style and proxy keys: sk-…, sk-apx…, sk-ant-…
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{6,}"), _MASK),
    # Authorization headers quoted inside an error message.
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{8,}"), f"Bearer {_MASK}"),
    # user:password@host inside a DSN or URL.
    (re.compile(r"://[^/\s:@]{1,128}:[^/\s@]{1,128}@"), f"://{_MASK}@"),
    # key=value / key: value for anything that names itself a credential.
    # "token" is matched bare as well as prefixed: providers write `token=…`,
    # `access_token=…` and `x-api-token=…` in the same error body.
    (
        re.compile(
            r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|token|client[_-]?secret"
            r"|password|passwd|secret)\b(\s*[=:]\s*)\S+"
        ),
        rf"\1\2{_MASK}",
    ),
)


def redact_text(text: str | None, *, secrets: Iterable[str] = ()) -> str | None:
    """Scrub credentials out of free text before it is stored or displayed.

    ``secrets`` are exact values to remove regardless of shape — pass the
    configured API key and tokens so a provider with an unusual key format is
    still covered. Values shorter than 8 characters are skipped: replacing them
    would shred ordinary words rather than protect anything.
    """
    if not text:
        return text

    out = text
    for secret in secrets:
        if secret and len(secret) >= 8:
            out = out.replace(secret, _MASK)
    for pattern, replacement in _TEXT_PATTERNS:
        out = pattern.sub(replacement, out)

    if len(out) > _MAX_TEXT:
        out = out[:_MAX_TEXT] + "…"
    return out


def redact_deep(value: Any, *, secrets: Iterable[str] = (), _depth: int = 0) -> Any:
    """Apply :func:`redact_text` to every string inside a nested structure."""
    if _depth > _MAX_DEPTH:
        return "<max-depth>"
    if isinstance(value, dict):
        return {
            key: redact_deep(item, secrets=secrets, _depth=_depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_deep(item, secrets=secrets, _depth=_depth + 1) for item in value]
    if isinstance(value, str):
        return redact_text(value, secrets=secrets)
    return value


_WS = re.compile(r"\s+")


def normalise_text(text: str) -> str:
    """Collapse whitespace — used when comparing a reply against a dry-run preview."""
    return _WS.sub(" ", text or "").strip()
