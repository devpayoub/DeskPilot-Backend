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
