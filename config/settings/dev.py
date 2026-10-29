"""Development settings: verbose errors, permissive hosts, no HTTPS forcing."""
from .base import *  # noqa: F401,F403

DEBUG = True
ALLOWED_HOSTS = ["*"]

# Local dev only: print emails instead of sending them.
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
