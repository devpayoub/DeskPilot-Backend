"""Development settings: verbose errors, permissive hosts, no HTTPS forcing."""
import os

from .base import *  # noqa: F401,F403

DEBUG = True
ALLOWED_HOSTS = ["*"]

# Local dev defaults to printing emails instead of sending them, but an explicit
# EMAIL_BACKEND in the environment wins — otherwise a developer who configures
# real SMTP in .env sees codes appear in the terminal and assumes the relay works.
EMAIL_BACKEND = os.getenv(
    "EMAIL_BACKEND", "django.core.mail.backends.console.EmailBackend"
)
