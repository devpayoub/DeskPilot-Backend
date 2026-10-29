"""Diagnostics adapter that calls the native Windows host agent over HTTP.

This is the implementation the Django worker uses when it runs inside a
container: it cannot see the host's disks, so it asks the host agent, which can.
It implements the same ``DiagnosticsAdapter`` protocol as ``LocalDiagnostics``, so
no tool knows or cares which one is wired in.
"""
from __future__ import annotations

import json
import time

import httpx

from ..errors import ToolExecutionError
from .signing import SIGNATURE_HEADER, TIMESTAMP_HEADER, sign


class HostAgentDiagnostics:
    """``DiagnosticsAdapter`` backed by the DeskPilot host agent."""

    def __init__(self, base_url: str, token: str, timeout: float = 60.0):
        if not token:
            raise ToolExecutionError(
                "HOSTAGENT_TOKEN is not set; the host agent would refuse every request."
            )
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _post(self, capability: str, payload: dict | None = None):
        body = json.dumps(payload or {}, separators=(",", ":")).encode("utf-8")
        timestamp = str(int(time.time()))
        headers = {
            "content-type": "application/json",
            TIMESTAMP_HEADER: timestamp,
            SIGNATURE_HEADER: sign(self.token, timestamp, body),
        }
        try:
            response = httpx.post(
                f"{self.base_url}/probe/{capability}",
                content=body,
                headers=headers,
                timeout=self.timeout,
            )
        except httpx.HTTPError as exc:
            raise ToolExecutionError(
                f"Host agent unreachable at {self.base_url}: {type(exc).__name__}"
            ) from exc

        if response.status_code != 200:
            detail = response.text[:300]
            raise ToolExecutionError(
                f"Host agent returned {response.status_code} for '{capability}': {detail}"
            )
        try:
            return response.json()["result"]
        except (KeyError, ValueError) as exc:
            raise ToolExecutionError("Host agent returned an unexpected payload.") from exc

    # -- DiagnosticsAdapter -------------------------------------------------
    def system_health(self, sample_seconds: float) -> dict:
        return self._post("system_health", {"sample_seconds": sample_seconds})

    def disk_health(self) -> dict:
        return self._post("disk_health")

    def list_services(self, name_filter, state, detail) -> dict:
        return self._post(
            "list_services",
            {"name_filter": name_filter, "state": state, "detail": detail},
        )

    def read_event_log(self, log, level, hours, limit) -> dict:
        return self._post(
            "read_event_log",
            {"log": log, "level": level, "hours": hours, "limit": limit},
        )

    def installed_software(self, name_contains) -> dict:
        return self._post("installed_software", {"name_contains": name_contains})

    def windows_update_status(self) -> dict:
        return self._post("windows_update_status")

    def listening_ports(self, include_loopback) -> dict:
        return self._post("listening_ports", {"include_loopback": include_loopback})

    def connectivity(self, host, port, timeout) -> dict:
        return self._post("connectivity", {"host": host, "port": port, "timeout": timeout})
