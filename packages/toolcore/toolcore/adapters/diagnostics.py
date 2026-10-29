"""The diagnostics capability interface.

Any implementation may be injected: the real one, a fixture-backed one for CI, a
simulated one for ``SAFE_MODE``, or an HTTP client for the native Windows host
agent. Tools depend only on this shape.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class DiagnosticsAdapter(Protocol):
    # -- host ---------------------------------------------------------------
    def system_health(self, sample_seconds: float) -> dict:
        """CPU, memory, uptime, boot time, pending-reboot flag."""

    def disk_health(self) -> dict:
        """Per-volume capacity and free space."""

    def list_services(self, name_filter: str | None, state: str, detail: bool) -> dict:
        """Windows services filtered by name/state."""

    # -- logs, inventory, updates -------------------------------------------
    def read_event_log(self, log: str, level: str, hours: int, limit: int) -> dict:
        """Recent Event Log entries from an allowlisted log and level."""

    def installed_software(self, name_contains: str | None) -> dict:
        """Installed software from the Uninstall registry keys."""

    def windows_update_status(self) -> dict:
        """Pending update count, recent hotfixes, pending-reboot flag."""

    # -- network ------------------------------------------------------------
    def listening_ports(self, include_loopback: bool) -> dict:
        """Listening TCP sockets with owning processes."""

    def connectivity(self, host: str, port: int, timeout: float) -> dict:
        """DNS resolution plus one timed TCP connection attempt."""
