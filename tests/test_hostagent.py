"""Host agent: HMAC signing, the capability allowlist, and the HTTP client."""
from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

from hostagent.main import create_app
from tests.fakes import FakeDiagnostics
from toolcore.adapters import HostAgentDiagnostics
from toolcore.adapters.signing import (
    NONCE_HEADER,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    WINDOW_SECONDS,
    NonceCache,
    sign,
    verify,
)
from toolcore.errors import ToolExecutionError

TOKEN = "test-token"


# ---------------------------------------------------------------------------
# Signing primitives
# ---------------------------------------------------------------------------
def test_sign_and_verify_roundtrip():
    body = b'{"sample_seconds":0}'
    stamp = str(int(time.time()))

    ok, reason = verify(TOKEN, stamp, "nonce-1", body, sign(TOKEN, stamp, "nonce-1", body))

    assert ok is True
    assert reason == ""


def test_verify_rejects_a_stale_timestamp():
    body = b"{}"
    old = str(int(time.time()) - WINDOW_SECONDS - 60)

    ok, reason = verify(TOKEN, old, "n", body, sign(TOKEN, old, "n", body))

    assert ok is False
    assert "window" in reason


def test_verify_rejects_a_tampered_body():
    stamp = str(int(time.time()))
    signature = sign(TOKEN, stamp, "n", b'{"sample_seconds":0}')

    ok, reason = verify(TOKEN, stamp, "n", b'{"sample_seconds":9}', signature)

    assert ok is False
    assert "mismatch" in reason


def test_verify_rejects_missing_headers():
    ok, reason = verify(TOKEN, None, None, b"{}", None)

    assert ok is False
    assert "missing" in reason


def test_verify_requires_a_nonce():
    """Without a nonce a captured request stays replayable inside the window."""
    stamp = str(int(time.time()))
    signature = sign(TOKEN, stamp, "", b"{}")

    ok, reason = verify(TOKEN, stamp, None, b"{}", signature)

    assert ok is False
    assert "nonce" in reason


def test_verify_rejects_a_replayed_nonce():
    """The whole point: the same signed request cannot be used twice."""
    body = b'{"sample_seconds":0}'
    stamp = str(int(time.time()))
    signature = sign(TOKEN, stamp, "once", body)
    cache = NonceCache()

    first, _ = verify(TOKEN, stamp, "once", body, signature, nonce_cache=cache)
    second, reason = verify(TOKEN, stamp, "once", body, signature, nonce_cache=cache)

    assert first is True
    assert second is False
    assert "already used" in reason


def test_nonce_cache_forgets_entries_past_the_window():
    """A nonce only needs remembering while a signature carrying it could verify."""
    cache = NonceCache()
    now = 1_000_000.0

    assert cache.remember("n", now=now) is True
    assert cache.remember("n", now=now + 1) is False
    assert cache.remember("n", now=now + WINDOW_SECONDS + 1) is True


def test_verify_rejects_a_missing_secret():
    ok, reason = verify("", "1", "n", b"{}", "abc")

    assert ok is False
    assert "not configured" in reason


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------
@pytest.fixture
def client():
    return TestClient(create_app(diagnostics=FakeDiagnostics(), secret=TOKEN))


def _headers(
    body: bytes,
    *,
    token: str = TOKEN,
    timestamp: str | None = None,
    nonce: str | None = None,
) -> dict:
    stamp = timestamp if timestamp is not None else str(int(time.time()))
    used = nonce if nonce is not None else f"n-{time.time_ns()}"
    return {
        "content-type": "application/json",
        TIMESTAMP_HEADER: stamp,
        NONCE_HEADER: used,
        SIGNATURE_HEADER: sign(token, stamp, used, body),
    }


def test_health_is_unsigned_and_lists_capabilities(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert "system_health" in response.json()["capabilities"]


def test_probe_requires_a_signature(client):
    body = json.dumps({}).encode()

    response = client.post("/probe/disk_health", content=body, headers={"content-type": "application/json"})

    assert response.status_code == 401


def test_probe_rejects_a_wrong_token(client):
    body = json.dumps({}).encode()

    response = client.post(
        "/probe/disk_health", content=body, headers=_headers(body, token="wrong-token")
    )

    assert response.status_code == 401


def test_signed_probe_returns_the_adapter_result(client):
    body = json.dumps({"sample_seconds": 0}).encode()

    response = client.post("/probe/system_health", content=body, headers=_headers(body))

    assert response.status_code == 200
    payload = response.json()
    assert payload["capability"] == "system_health"
    assert payload["result"]["hostname"] == "TEST-HOST"


def test_unknown_capability_is_404(client):
    body = json.dumps({}).encode()

    response = client.post("/probe/format_c_drive", content=body, headers=_headers(body))

    assert response.status_code == 404


def test_unexpected_arguments_are_rejected(client):
    """The allowlist is per capability — extra keys are a 400, not silently ignored."""
    body = json.dumps({"sample_seconds": 0, "sudo": True}).encode()

    response = client.post("/probe/system_health", content=body, headers=_headers(body))

    assert response.status_code == 400
    assert "sudo" in response.json()["detail"]


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------
class _FakeResponse:
    def __init__(self, status_code: int, payload: dict):
        self.status_code = status_code
        self._payload = payload

    def json(self) -> dict:
        return self._payload

    @property
    def text(self) -> str:
        return json.dumps(self._payload)


def test_client_signs_requests_the_server_accepts(monkeypatch):
    captured: dict = {}

    def fake_post(url, content=None, headers=None, timeout=None):
        captured["url"] = url
        captured["body"] = content
        captured["headers"] = headers
        return _FakeResponse(200, {"ok": True, "result": {"hostname": "REMOTE-HOST"}})

    monkeypatch.setattr("toolcore.adapters.host_agent.httpx.post", fake_post)

    adapter = HostAgentDiagnostics("http://127.0.0.1:8765", TOKEN)
    result = adapter.system_health(0)

    assert result == {"hostname": "REMOTE-HOST"}
    assert captured["url"].endswith("/probe/system_health")

    # The signature the client produced must verify with the server's verifier.
    ok, reason = verify(
        TOKEN,
        captured["headers"][TIMESTAMP_HEADER],
        captured["headers"][NONCE_HEADER],
        captured["body"],
        captured["headers"][SIGNATURE_HEADER],
    )
    assert ok is True, reason


def test_the_server_refuses_a_replayed_request(client):
    """A captured request must not work twice, even inside the timestamp window."""
    body = json.dumps({}).encode()
    headers = _headers(body)

    first = client.post("/probe/disk_health", content=body, headers=headers)
    replay = client.post("/probe/disk_health", content=body, headers=headers)

    assert first.status_code == 200
    assert replay.status_code == 401
    assert "nonce already used" in replay.json()["detail"]


def test_each_client_request_carries_a_fresh_nonce(monkeypatch):
    seen: list[str] = []

    def fake_post(url, content=None, headers=None, timeout=None):
        seen.append(headers[NONCE_HEADER])
        return _FakeResponse(200, {"ok": True, "result": {"hostname": "H"}})

    monkeypatch.setattr("toolcore.adapters.host_agent.httpx.post", fake_post)
    adapter = HostAgentDiagnostics("http://127.0.0.1:8765", TOKEN)

    adapter.disk_health()
    adapter.disk_health()

    assert len(seen) == 2
    assert seen[0] != seen[1], "a reused nonce would make every request replayable"


def test_client_raises_on_a_non_200(monkeypatch):
    monkeypatch.setattr(
        "toolcore.adapters.host_agent.httpx.post",
        lambda *a, **k: _FakeResponse(500, {"detail": "boom"}),
    )
    adapter = HostAgentDiagnostics("http://127.0.0.1:8765", TOKEN)

    with pytest.raises(ToolExecutionError, match="returned 500"):
        adapter.disk_health()


def test_client_requires_a_token():
    with pytest.raises(ToolExecutionError, match="HOSTAGENT_TOKEN"):
        HostAgentDiagnostics("http://127.0.0.1:8765", "")
