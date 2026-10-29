"""Production settings: fail fast on anything that is unsafe by default."""
from .base import *  # noqa: F401,F403

DEBUG = False

# A default secret in production is a security incident waiting to happen.
if SECRET_KEY.startswith("insecure-"):  # noqa: F405
    raise RuntimeError(
        "DJANGO_SECRET_KEY is not set. Refusing to start with the development default."
    )

ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS")  # noqa: F405
if not ALLOWED_HOSTS:
    raise RuntimeError("DJANGO_ALLOWED_HOSTS must list at least one host in production.")

SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 60 * 60 * 24 * 30
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
X_FRAME_OPTIONS = "DENY"

# Real write actions must be an explicit, deliberate act in production.
if ALLOW_REAL_WRITES and SAFE_MODE:  # noqa: F405
    raise RuntimeError("ALLOW_REAL_WRITES=1 is meaningless while SAFE_MODE=1. Pick one.")

# ---------------------------------------------------------------------------
# Every other well-known development value must also be rejected here.
#
# `base.py` has to carry usable defaults so a fresh clone runs; that means the
# weak values exist in the codebase and can reach production by being copied.
# Each one below is checked explicitly instead of trusted.
# ---------------------------------------------------------------------------
if DIRECTORY_BACKEND == "ldap" and LDAP_BIND_PASSWORD in {"", "admin"}:  # noqa: F405
    raise RuntimeError(
        "LDAP_BIND_PASSWORD is unset or still the OpenLDAP sample password."
    )

if HOSTAGENT_TOKEN in {"dev-shared-secret", "dev-token", "changeme"}:  # noqa: F405
    raise RuntimeError(
        "HOSTAGENT_TOKEN is still a documented development value. "
        "Generate one with `python -c \"import secrets; print(secrets.token_urlsafe(32))\"`."
    )

if DATABASE_URL and ":deskpilot@" in DATABASE_URL:  # noqa: F405
    raise RuntimeError(
        "DATABASE_URL still uses the compose default password 'deskpilot'."
    )

if not VAULT_ENCRYPTION_KEY:  # noqa: F405
    raise RuntimeError(
        "VAULT_ENCRYPTION_KEY must be set in production. Without it the vault key "
        "is derived from SECRET_KEY, so rotating SECRET_KEY would silently orphan "
        "every stored credential."
    )

# Prompts, tool output and ticket text leave the machine for this endpoint, so it
# must not be plaintext.
if not LLM_BASE_URL.startswith("https://"):  # noqa: F405
    raise RuntimeError(
        f"LLM_BASE_URL must be https:// in production, got {LLM_BASE_URL!r}."
    )

if not ALLOWED_HOSTS or "*" in ALLOWED_HOSTS:  # noqa: F405
    raise RuntimeError("DJANGO_ALLOWED_HOSTS must list concrete hosts, not '*'.")

# The OpenAPI schema describes every endpoint and payload shape. In a deployment
# that is free reconnaissance, so require a token there. Locally it stays open,
# because opening Swagger without logging in first is genuinely useful.
SPECTACULAR_SETTINGS = {  # noqa: F405
    **SPECTACULAR_SETTINGS,
    "SERVE_PERMISSIONS": ["rest_framework.permissions.IsAuthenticated"],
}
