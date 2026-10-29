"""Core types: the Tool declaration, the call context, and the audit record.

Nothing in this module imports Django. The Django application injects its own
policy resolver, kill switch and auditor into ``ToolContext``; the MCP server
injects no-ops or its own. That is what lets one registry serve both consumers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping

from pydantic import BaseModel, ValidationError

from .errors import ToolValidationError
from .risk import RiskClass


class Outcome(str, Enum):
    OK = "ok"
    ERROR = "error"
    DENIED = "denied"
    APPROVAL_REQUIRED = "approval_required"
    DRY_RUN = "dry_run"


class KillSwitchState(str, Enum):
    OPEN = "open"      # everything allowed
    PAUSED = "paused"  # writes denied, reads still work
    HALTED = "halted"  # nothing runs at all


@dataclass(frozen=True)
class PolicySnapshot:
    """One tool's policy as resolved by the host application.

    ``None`` on any field means "defer to the tool's own declaration" — policy can
    only tighten a tool, never loosen it below its declared risk.
    """

    tool_name: str
    enabled: bool = True
    risk_class: RiskClass | None = None
    requires_approval: bool | None = None
    allowed_roles: frozenset[str] | None = None
    max_calls_per_run: int | None = None


@dataclass(frozen=True)
class InvocationRecord:
    """What the host is told about every attempt, successful or not.

    Deliberately carries no result payload: results are unbounded and belong in
    the agent's step record, not in a table that must stay append-only and small.
    """

    tool_name: str
    risk_class: str
    actor_type: str
    actor_id: str
    outcome: Outcome
    args_hash: str
    args_redacted: Any
    error_code: str | None = None
    error_message: str | None = None
    duration_ms: int = 0
    trace_id: str = ""
    transport: str = "internal"
    dry_run: bool = False


def _default_killswitch() -> KillSwitchState:
    return KillSwitchState.OPEN


def _default_policy(_name: str) -> PolicySnapshot | None:
    return None


def _default_auditor(_record: InvocationRecord) -> None:
    return None


@dataclass(frozen=True)
class ApprovalContext:
    """What the host needs to persist an approval request.

    ``args_redacted`` is for humans to read; ``args_hash`` is what the approval is
    actually bound to. The two are deliberately separate — a human must not be
    asked to eyeball a hash, and the hash must not be computed from redacted data.
    """

    tool_name: str
    risk_class: str
    args_redacted: Any
    args_hash: str
    rationale: str = ""
    preview: Any = None
    dry_run_ok: bool = False


def _default_approval_handler(_context: ApprovalContext) -> None:
    return None


def _default_password_sink(_sam: str, _password: str, _force_change: bool) -> str:
    """Fails closed: a host that has not supplied a sink must not leak a password."""
    from .errors import ToolExecutionError

    raise ToolExecutionError(
        "No password sink is configured; refusing to generate a credential."
    )


@dataclass
class ToolContext:
    """Identity, adapters and host hooks a tool runs under.

    ``adapters`` is intentionally untyped here: it is a namespace object supplied
    by the host (``.diagnostics``, ``.remediation``, ``.directory``, ``.tickets``).
    The tool only touches the adapter attributes it needs.
    """

    actor_id: str = "anonymous"
    actor_role: str = ""
    actor_type: str = "agent"
    adapters: Any = None
    approval_token: str | None = None
    dry_run: bool = False
    trace_id: str = ""
    transport: str = "internal"
    killswitch: Callable[[], KillSwitchState] = field(default=_default_killswitch)
    policy_resolver: Callable[[str], PolicySnapshot | None] = field(default=_default_policy)
    auditor: Callable[[InvocationRecord], None] = field(default=_default_auditor)
    # Called by the chokepoint when a write is proposed without approval, so the
    # host can persist an ApprovalRequest before the exception propagates.
    on_approval_required: Callable[[ApprovalContext], None] = field(
        default=_default_approval_handler
    )
    # Stores a freshly generated password and returns an opaque reference. The
    # secret must never travel back through the model, so the tool returns only the
    # reference this hook produces.
    password_sink: Callable[[str, str, bool], str] = field(default=_default_password_sink)

    def adapter(self, name: str) -> Any:
        """Return a named adapter, or raise if the host did not supply one."""
        from .errors import ToolExecutionError

        adapter = getattr(self.adapters, name, None) if self.adapters is not None else None
        if adapter is None:
            raise ToolExecutionError(
                f"No '{name}' adapter is configured for this call context."
            )
        return adapter


@dataclass(frozen=True)
class Tool:
    """A named, schema-validated capability the agent may propose."""

    name: str
    description: str
    handler: Callable[[ToolContext, dict], Any]
    input_model: type[BaseModel] | None = None
    risk_class: RiskClass = RiskClass.READ
    # None -> derive from risk_class (writes need approval, reads do not).
    approval_required: bool | None = None
    # None -> any authenticated role. A frozenset is an explicit allowlist.
    allowed_roles: frozenset[str] | None = None
    dry_run_supported: bool = False
    domain: str = "general"
    # Refuses the call from the *validated arguments*, before the approval gate.
    # For rules no approval can waive (privileged groups), asking a human first
    # would waste their attention and leave a misleading audit trail.
    guard: Callable[[dict], None] | None = None

    def validate(self, raw_args: Mapping[str, Any] | None) -> dict:
        if self.input_model is None:
            if raw_args not in (None, {}, []):
                raise ToolValidationError(f"Tool '{self.name}' takes no arguments.")
            return {}
        if raw_args is None:
            raw_args = {}
        if not isinstance(raw_args, Mapping):
            raise ToolValidationError(
                f"Arguments for '{self.name}' must be an object, got {type(raw_args).__name__}."
            )
        try:
            return self.input_model(**dict(raw_args)).model_dump()
        except ValidationError as exc:
            raise ToolValidationError(
                f"Invalid arguments for '{self.name}': {exc.errors(include_url=False)}"
            ) from exc

    def resolved_approval_required(self, risk: RiskClass | None = None) -> bool:
        if self.approval_required is not None:
            return self.approval_required
        return (risk or self.risk_class).requires_approval_by_default

    def spec(self) -> dict:
        schema: dict = {}
        if self.input_model is not None:
            schema = self.input_model.model_json_schema()
        return {
            "name": self.name,
            "description": self.description,
            "domain": self.domain,
            "risk_class": self.risk_class.label,
            "requires_approval": self.resolved_approval_required(),
            "dry_run_supported": self.dry_run_supported,
            "allowed_roles": sorted(self.allowed_roles) if self.allowed_roles else None,
            "input_schema": schema,
        }
