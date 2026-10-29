"""Celery is initialised here so `celery -A config` finds the app."""
from .celery import app as celery_app

__all__ = ("celery_app",)
