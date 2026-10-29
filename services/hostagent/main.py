"""DeskPilot host agent — a read-only probe endpoint that runs natively on Windows.

Why this exists: the Django worker runs in a Linux container, so it measures the
*container's* CPU and disks, not the user's machine. Real RMM and endpoint agents
solve this the same way — a small privileged process on the host, reached over a
narrow authenticated interface.

The security posture is deliberately minimal:

* it exposes a fixed **allowlist of eight capabilities**, not a generic dispatcher;
* each capability declares exactly which arguments it accepts, and anything else
  is a 400 rather than being silently dropped;
* every request must be HMAC-signed with a timestamp (see ``auth.py``);
* there is no write capability at all — this build cannot change the host.

Run:
    python -m hostagent.main --port 8765
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Any, Callable

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from toolcore.adapters import LocalDiagnostics
from toolcore.errors import ToolCoreError

from .auth import SIGNATURE_HEADER, TIMESTAMP_HEADER, verify

logger = logging.getLogger("deskpilot.hostagent")

# capability -> (adapter method, accepted argument names)
CAPABILITIES: dict[str, tuple[str, frozenset[str]]] = {
    "system_health": ("system_health", frozenset({"sample_seconds"})),
    "disk_health": ("disk_health", frozenset()),
    "list_services": ("list_services", frozenset({"name_filter", "state", "detail"})),
    "read_event_log": ("read_event_log", frozenset({"log", "level", "hours", "limit"})),
    "installed_software": ("installed_software", frozenset({"name_contains"})),
    "windows_update_status": ("windows_update_status", frozenset()),
    "listening_ports": ("listening_ports", frozenset({"include_loopback"})),
    "connectivity": ("connectivity", frozenset({"host", "port", "timeout"})),
}


def create_app(
    diagnostics: Any | None = None,
    secret: str | None = None,
) -> FastAPI:
    """Build the app. Dependencies are injectable so tests never touch the host."""
    adapter = diagnostics if diagnostics is not None else LocalDiagnostics()
    token = secret if secret is not None else os.getenv("HOSTAGENT_TOKEN", "")

    app = FastAPI(
        title="DeskPilot Host Agent",
        version="0.1.0",
        description="Read-only Windows diagnostics for the DeskPilot agent.",
    )

    async def require_signature(
        request: Request,
        timestamp: str | None = Header(default=None, alias=TIMESTAMP_HEADER),
        signature: str | None = Header(default=None, alias=SIGNATURE_HEADER),
    ) -> None:
        body = await request.body()
        ok, reason = verify(token, timestamp, body, signature)
        if not ok:
            logger.warning("rejected host agent request: %s", reason)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=reason)

    @app.get("/health")
    def health() -> dict:
        """Unsigned liveness probe. Reveals nothing about the host."""
        return {"status": "ok", "capabilities": sorted(CAPABILITIES)}

    @app.post("/probe/{capability}", dependencies=[Depends(require_signature)])
    def probe(capability: str, payload: dict) -> JSONResponse:
        if capability not in CAPABILITIES:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, detail=f"unknown capability '{capability}'"
            )

        method_name, allowed = CAPABILITIES[capability]
        unexpected = set(payload) - allowed
        if unexpected:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail=f"unexpected arguments: {sorted(unexpected)}",
            )

        try:
            result = getattr(adapter, method_name)(**payload)
        except ToolCoreError as exc:
            # Expected, explainable failure (e.g. not a Windows host).
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("host agent capability %s failed", capability)
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR, detail="host probe failed"
            ) from exc

        return JSONResponse({"ok": True, "capability": capability, "result": result})

    return app


def main(argv: list[str] | None = None) -> None:
    import uvicorn

    parser = argparse.ArgumentParser(description="DeskPilot host agent")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)

    logging.basicConfig(stream=sys.stderr, level=logging.INFO)

    if not os.getenv("HOSTAGENT_TOKEN"):
        print(
            "HOSTAGENT_TOKEN is not set — every signed request will be refused.",
            file=sys.stderr,
        )

    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
