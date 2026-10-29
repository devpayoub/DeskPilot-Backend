"""Argument redaction and hashing.

Two jobs, both load-bearing:

* ``redact_args`` — the audit row must be readable without ever storing a secret.
* ``args_hash`` — the approval gate freezes a hash of the validated arguments, so
  approving one argument set can never execute a different one (TOCTOU defence).
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

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


_WS = re.compile(r"\s+")


def normalise_text(text: str) -> str:
    """Collapse whitespace — used when comparing a reply against a dry-run preview."""
    return _WS.sub(" ", text or "").strip()
