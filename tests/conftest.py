"""Shared fixtures.

Conventions (same as the ISBM suite):
- DB tests declare ``pytestmark = pytest.mark.django_db``.
- ``no_external_calls`` blocks outbound sockets, silences email/Celery and clears
  the cache, because the kill switch and the policy cache are process-global state
  that would otherwise leak between tests.
- Tests build their own minimal state; nothing depends on a seed command having run.
"""
from __future__ import annotations

import socket
from types import SimpleNamespace

import pytest
from django.core.cache import cache
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import Role
from tests.factories import PASSWORD, make_user  # noqa: F401  (PASSWORD re-exported)
from tests.fakes import FakeDiagnostics
from toolcore.tools import register_all

# Reachable in tests so the LDAP contract suite can talk to a local container.
_LOOPBACK = {"127.0.0.1", "::1", "localhost", "0.0.0.0", ""}


def _is_local(host: str) -> bool:
    host = (host or "").strip("[]")
    if host in _LOOPBACK:
        return True
    return host.startswith("127.")


@pytest.fixture(autouse=True)
def no_external_calls(settings, monkeypatch):
    """Make the suite offline for real.

    This fixture previously only silenced email and Celery while claiming to stop
    external calls — so the moment a real ``LLM_API_KEY`` was configured, tests
    started calling a paid provider. Blocking ``socket.connect`` is the only
    version of this that keeps its promise.
    """
    settings.EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
    settings.CELERY_TASK_ALWAYS_EAGER = True
    cache.clear()

    real_connect = socket.socket.connect

    def guarded_connect(self, address, *args, **kwargs):
        if isinstance(address, tuple) and address:
            host = str(address[0])
            if not _is_local(host):
                raise RuntimeError(
                    f"Blocked external network call to {host}:{address[1]}. "
                    "Inject a scripted LLM (llm_call=...) or mock the client."
                )
        return real_connect(self, address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    yield
    cache.clear()


@pytest.fixture(autouse=True)
def tool_registry():
    """Guarantee the catalog is loaded; idempotent, so repeated calls are safe."""
    register_all()
    yield
    register_all()


@pytest.fixture
def fake_diagnostics() -> FakeDiagnostics:
    return FakeDiagnostics()


@pytest.fixture
def adapters(fake_diagnostics):
    return SimpleNamespace(diagnostics=fake_diagnostics)


@pytest.fixture
def admin_user(db):
    return make_user("admin@deskpilot.test", Role.ADMIN)


@pytest.fixture
def desk_user(db):
    return make_user("desk@deskpilot.test", Role.SERVICE_DESK)


@pytest.fixture
def technician_user(db):
    return make_user("tech@deskpilot.test", Role.TECHNICIAN)


@pytest.fixture
def requester_user(db):
    return make_user("requester@deskpilot.test", Role.REQUESTER)


def _authenticated(user) -> APIClient:
    client = APIClient()
    token = RefreshToken.for_user(user).access_token
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    return client


@pytest.fixture
def api_client() -> APIClient:
    return APIClient()


@pytest.fixture
def admin_client(admin_user) -> APIClient:
    return _authenticated(admin_user)


@pytest.fixture
def desk_client(desk_user) -> APIClient:
    return _authenticated(desk_user)


@pytest.fixture
def technician_client(technician_user) -> APIClient:
    return _authenticated(technician_user)


@pytest.fixture
def requester_client(requester_user) -> APIClient:
    return _authenticated(requester_user)


@pytest.fixture
def api_fake_adapters(monkeypatch, adapters):
    """Make the HTTP layer use the fake diagnostics adapter."""
    monkeypatch.setattr("apps.guardrails.context.default_adapters", lambda: adapters)
    return adapters
