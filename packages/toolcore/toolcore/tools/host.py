"""Host diagnostic tools — the first three of the catalog, all READ risk.

Each tool is a thin, typed wrapper over a ``DiagnosticsAdapter`` call. There is no
argument that can reach a shell, so the blast radius of a malformed or hostile
model proposal is bounded by the adapter's own read-only implementation.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..base import Tool, ToolContext
from ..risk import READ
from .. import registry


class NoArgs(BaseModel):
    """Explicit empty schema, so a stray argument is rejected instead of ignored."""

    model_config = ConfigDict(extra="forbid")


class SystemHealthArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sample_seconds: float = Field(
        default=0.5,
        ge=0.0,
        le=10.0,
        description="How long to sample CPU usage. 0 returns an instantaneous value.",
    )


class ListServicesArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name_filter: str | None = Field(
        default=None,
        max_length=120,
        description="Case-insensitive substring of the service name.",
    )
    state: Literal["all", "running", "stopped"] = Field(
        default="all", description="Filter by service state."
    )
    detail: bool = Field(
        default=False,
        description="Include display name, start type, account and PID (slower).",
    )


class ReadEventLogArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    log: Literal["system", "application", "security"] = Field(
        default="system", description="Which event log to read."
    )
    level: Literal["all", "critical", "error", "warning", "information"] = Field(
        default="error", description="Minimum severity to return."
    )
    hours: int = Field(default=24, ge=1, le=24, description="Look-back window in hours.")
    limit: int = Field(default=20, ge=1, le=100, description="Maximum events to return.")


class ListListeningPortsArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    include_loopback: bool = Field(
        default=False,
        description="Include sockets bound to 127.0.0.1 / ::1.",
    )


class TestConnectivityArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = Field(
        min_length=1, max_length=253, description="Hostname or IP address to test."
    )
    port: int = Field(ge=1, le=65535, description="TCP port to connect to.")
    timeout: float = Field(
        default=3.0, ge=0.5, le=5.0, description="Connection timeout in seconds."
    )


class GetInstalledSoftwareArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name_contains: str | None = Field(
        default=None,
        max_length=120,
        description="Case-insensitive substring filter on the product name.",
    )


def _get_system_health(ctx: ToolContext, args: dict) -> dict:
    return ctx.adapter("diagnostics").system_health(args["sample_seconds"])


def _get_disk_health(ctx: ToolContext, args: dict) -> dict:
    return ctx.adapter("diagnostics").disk_health()


def _list_services(ctx: ToolContext, args: dict) -> dict:
    return ctx.adapter("diagnostics").list_services(
        args["name_filter"], args["state"], args["detail"]
    )


def _read_event_log(ctx: ToolContext, args: dict) -> dict:
    return ctx.adapter("diagnostics").read_event_log(
        args["log"], args["level"], args["hours"], args["limit"]
    )


def _list_listening_ports(ctx: ToolContext, args: dict) -> dict:
    return ctx.adapter("diagnostics").listening_ports(args["include_loopback"])


def _test_connectivity(ctx: ToolContext, args: dict) -> dict:
    return ctx.adapter("diagnostics").connectivity(
        args["host"], args["port"], args["timeout"]
    )


def _get_installed_software(ctx: ToolContext, args: dict) -> dict:
    return ctx.adapter("diagnostics").installed_software(args["name_contains"])


def _get_windows_update_status(ctx: ToolContext, args: dict) -> dict:
    return ctx.adapter("diagnostics").windows_update_status()


HOST_TOOLS: tuple[Tool, ...] = (
    Tool(
        name="get_system_health",
        description=(
            "Read CPU, memory, uptime, boot time and pending-reboot state for the host. "
            "Use this first when a user reports a slow or unresponsive machine."
        ),
        handler=_get_system_health,
        input_model=SystemHealthArgs,
        risk_class=READ,
        domain="host",
    ),
    Tool(
        name="get_disk_health",
        description=(
            "Read per-volume capacity, used and free space, and a low-space flag. "
            "Use when a user reports a full disk, failed saves or slow startup."
        ),
        handler=_get_disk_health,
        input_model=NoArgs,
        risk_class=READ,
        domain="host",
    ),
    Tool(
        name="list_services",
        description=(
            "List Windows services filtered by name and state. Use to check whether a "
            "specific service (spooler, VPN, update) is running before proposing a fix."
        ),
        handler=_list_services,
        input_model=ListServicesArgs,
        risk_class=READ,
        domain="host",
    ),
    Tool(
        name="read_event_log",
        description=(
            "Read recent Windows Event Log entries (System, Application, Security) "
            "filtered by severity and time window. Use to find the underlying cause of "
            "a crash, driver failure or service start error."
        ),
        handler=_read_event_log,
        input_model=ReadEventLogArgs,
        risk_class=READ,
        domain="host",
    ),
    Tool(
        name="list_listening_ports",
        description=(
            "List listening TCP sockets with the owning process. Use when a user reports "
            "a port conflict, an unexpected service, or a connection that will not open."
        ),
        handler=_list_listening_ports,
        input_model=ListListeningPortsArgs,
        risk_class=READ,
        domain="network",
    ),
    Tool(
        name="test_connectivity",
        description=(
            "Resolve a hostname and attempt one TCP connection, reporting DNS success, "
            "resolved addresses and latency. Use to separate a DNS problem from a "
            "firewall or service problem."
        ),
        handler=_test_connectivity,
        input_model=TestConnectivityArgs,
        risk_class=READ,
        domain="network",
    ),
    Tool(
        name="get_installed_software",
        description=(
            "List installed software with version, publisher and install date. Use to "
            "check whether an application or patch level is present."
        ),
        handler=_get_installed_software,
        input_model=GetInstalledSoftwareArgs,
        risk_class=READ,
        domain="host",
    ),
    Tool(
        name="get_windows_update_status",
        description=(
            "Report the pending Windows Update count, the last installed hotfixes and "
            "whether a reboot is pending. Use when a user reports update failures or an "
            "unexplained reboot prompt."
        ),
        handler=_get_windows_update_status,
        input_model=NoArgs,
        risk_class=READ,
        domain="host",
    ),
)


def register_host_tools() -> None:
    for tool in HOST_TOOLS:
        registry.register_if_absent(tool)
