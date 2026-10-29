"""Base settings shared by every environment.

Environment-specific modules (``dev``/``prod``) import * from here and override
only what differs. All secrets and endpoints come from the environment; nothing
sensitive is ever defaulted to something real.
"""
from __future__ import annotations

import os
from pathlib import Path

import dj_database_url
from dotenv import load_dotenv

# backend/config/settings/base.py -> backend/
#
# The project lives entirely inside backend/ (packages, services, evals, docs);
# only the Next.js console sits beside it, in ../web. So "the root of the
# project" is this directory, not its parent.
BASE_DIR = Path(__file__).resolve().parent.parent.parent
REPO_ROOT = BASE_DIR

load_dotenv(REPO_ROOT / ".env")


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_list(name: str, default: str = "") -> list[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "insecure-dev-key-do-not-use-in-production")
DEBUG = env_bool("DJANGO_DEBUG", False)
ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # third party
    "rest_framework",
    "drf_spectacular",
    "corsheaders",
    "channels",
    # local
    "apps.common",
    "apps.accounts",
    "apps.llm",
    "apps.helpdesk",
    "apps.directory",
    "apps.guardrails",
    "apps.agent",
    "apps.evals",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
# Postgres is the real target. The sqlite fallback exists only so a fresh clone
# can run `pytest` before Docker is up; it is never used in the compose stack.
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'db.sqlite3'}")

DATABASES = {
    "default": dj_database_url.parse(
        DATABASE_URL,
        conn_max_age=600,
        conn_health_checks=True,
    )
}
DATABASES["default"]["ATOMIC_REQUESTS"] = True

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
AUTH_USER_MODEL = "accounts.CustomUser"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# ---------------------------------------------------------------------------
# i18n / static
# ---------------------------------------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

# ---------------------------------------------------------------------------
# DRF / schema
# ---------------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_PAGINATION_CLASS": "apps.common.pagination.DefaultPagination",
    "PAGE_SIZE": 25,
    "EXCEPTION_HANDLER": "apps.common.exceptions.api_exception_handler",
}

SPECTACULAR_SETTINGS = {
    "TITLE": "DeskPilot API",
    "DESCRIPTION": "IT helpdesk agent with a guardrailed tool layer.",
    "VERSION": "0.1.0",
    "SERVE_INCLUDE_SCHEMA": False,
}

CORS_ALLOWED_ORIGINS = env_list("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")

# ---------------------------------------------------------------------------
# Cache / Celery
# ---------------------------------------------------------------------------
REDIS_URL = os.getenv("REDIS_URL", "")

if REDIS_URL:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": REDIS_URL,
            "KEY_PREFIX": "deskpilot",
        }
    }
else:
    # Tests and bare-metal runs without redis. The kill switch still works,
    # it is simply per-process instead of shared.
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "deskpilot-locmem",
        }
    }

CELERY_BROKER_URL = REDIS_URL or "memory://"
CELERY_RESULT_BACKEND = REDIS_URL or "cache+memory://"
CELERY_TASK_ALWAYS_EAGER = env_bool("CELERY_TASK_ALWAYS_EAGER", False)
CELERY_TASK_EAGER_PROPAGATES = True
CELERY_TASK_ACKS_LATE = True
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_TIMEZONE = TIME_ZONE

# The live agent trace. Redis when available so the worker and the web process
# share a channel layer; in-memory otherwise, which only works when both run in
# the same process (tests, single-process dev).
if REDIS_URL:
    CHANNEL_LAYERS = {
        "default": {
            "BACKEND": "channels_redis.core.RedisChannelLayer",
            "CONFIG": {"hosts": [REDIS_URL]},
        }
    }
else:
    CHANNEL_LAYERS = {
        "default": {"BACKEND": "channels.layers.InMemoryChannelLayer"},
    }

# ---------------------------------------------------------------------------
# LLM (provider-agnostic OpenAI-compatible endpoint)
# ---------------------------------------------------------------------------
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1")
LLM_MODEL = os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")
# IteraCompute needs {"reasoning": false}; Groq/OpenAI reject unknown body fields.
LLM_SEND_REASONING_PARAM = env_bool("LLM_SEND_REASONING_PARAM", False)
LLM_MAX_COST_PER_RUN_USD = float(os.getenv("LLM_MAX_COST_PER_RUN_USD", "0.15"))

# ---------------------------------------------------------------------------
# DeskPilot safety posture
# ---------------------------------------------------------------------------
# SAFE_MODE routes write tools to a simulated host. Default on, deliberately.
SAFE_MODE = env_bool("SAFE_MODE", True)
ALLOW_REAL_WRITES = env_bool("ALLOW_REAL_WRITES", False)

HOSTAGENT_URL = os.getenv("HOSTAGENT_URL", "http://127.0.0.1:8765")
HOSTAGENT_TOKEN = os.getenv("HOSTAGENT_TOKEN", "")

# ---------------------------------------------------------------------------
# Directory (identity)
# ---------------------------------------------------------------------------
# "fake" uses the seeded local tenant; "ldap" talks to a real directory.
DIRECTORY_BACKEND = os.getenv("DIRECTORY_BACKEND", "fake")
LDAP_URI = os.getenv("LDAP_URI", "ldap://localhost:3890")
LDAP_BASE_DN = os.getenv("LDAP_BASE_DN", "dc=deskpilot,dc=test")
LDAP_BIND_DN = os.getenv("LDAP_BIND_DN", "cn=admin,dc=deskpilot,dc=test")
LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD", "admin")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {name} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "verbose"},
    },
    "root": {"handlers": ["console"], "level": "INFO"},
    "loggers": {
        "toolcore": {"handlers": ["console"], "level": "INFO", "propagate": False},
        "apps": {"handlers": ["console"], "level": "INFO", "propagate": False},
    },
}
