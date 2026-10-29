"""Remediation tools — the first capabilities that change a machine.

Every one of these declares ``dry_run_supported=True``, because an approver who
cannot see what will change is not really approving anything. Risk classes are
deliberate: restarting a service is reversible, deleting files is not.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .. import registry
from ..base import Tool, ToolContext
from ..risk import WRITE_DESTRUCTIVE, WRITE_REVERSIBLE

# Role identifiers belong to the host application; toolcore does not import Django.
_TECHNICIAN = frozenset({"TECHNICIAN", "ADMIN"})
_DESK = frozenset({"SERVICE_DESK", "TECHNICIAN", "ADMIN"})


class NoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RestartServiceArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service_name: str = Field(
        min_length=1,
        max_length=120,
        pattern=r"^[A-Za-z0-9_.\-]+$",
        description="Windows service key, e.g. 'Spooler'. Not a display name.",
    )
    reason: str | None = Field(
        default=None,
        max_length=300,
        description="Why the restart is needed. Shown to the approver.",
    )


class ClearTempFilesArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    root: Literal["user_temp", "windows_temp"] = Field(
        description="Which temp root to clear. No arbitrary paths are accepted."
    )
    max_gb: float = Field(
        default=1.0,
        ge=0.1,
        le=5.0,
        description="Upper bound on how much to delete, in gigabytes.",
    )


def _restart_service(ctx: ToolContext, args: dict) -> dict:
    return ctx.adapter("remediation").restart_service(
        args["service_name"], dry_run=ctx.dry_run
    )


def _clear_temp_files(ctx: ToolContext, args: dict) -> dict:
    return ctx.adapter("remediation").clear_temp_files(
        args["root"], args["max_gb"], dry_run=ctx.dry_run
    )


def _flush_dns_cache(ctx: ToolContext, args: dict) -> dict:
    return ctx.adapter("remediation").flush_dns_cache(dry_run=ctx.dry_run)


REMEDIATION_TOOLS: tuple[Tool, ...] = (
    Tool(
        name="restart_service",
        description=(
            "Restart a Windows service. Reversible: the service comes back up. "
            "Use when a service is stopped, hung, or stuck after a config change. "
            "Dependents may briefly fail while it restarts."
        ),
        handler=_restart_service,
        input_model=RestartServiceArgs,
        risk_class=WRITE_REVERSIBLE,
        dry_run_supported=True,
        allowed_roles=_TECHNICIAN,
        domain="remediation",
    ),
    Tool(
        name="clear_temp_files",
        description=(
            "Delete files under a temp root to free disk space. NOT reversible. "
            "Only use after confirming the volume is genuinely full and the temp "
            "directory is the cause. Files in use are skipped, not forced."
        ),
        handler=_clear_temp_files,
        input_model=ClearTempFilesArgs,
        risk_class=WRITE_DESTRUCTIVE,
        dry_run_supported=True,
        allowed_roles=_TECHNICIAN,
        domain="remediation",
    ),
    Tool(
        name="flush_dns_cache",
        description=(
            "Flush the DNS resolver cache. Reversible and harmless. Use when a name "
            "resolves to a stale or wrong address after a network or VPN change."
        ),
        handler=_flush_dns_cache,
        input_model=NoArgs,
        risk_class=WRITE_REVERSIBLE,
        # Deliberately does not require approval: the blast radius is nil and
        # gating it would train people to approve without reading.
        approval_required=False,
        dry_run_supported=True,
        allowed_roles=_DESK,
        domain="remediation",
    ),
)


def register_remediation_tools() -> None:
    for tool in REMEDIATION_TOOLS:
        registry.register_if_absent(tool)
