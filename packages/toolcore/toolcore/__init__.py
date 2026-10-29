"""toolcore — framework-free validated tool registry.

Consumed by two hosts that share this exact code:

* the Django/Celery agent runtime (``apps.agent``), and
* the standalone MCP server (``services/mcp_server``).

Neither the Django ORM nor any HTTP framework is imported here on purpose.
"""
from .base import (
    ApprovalContext,
    InvocationRecord,
    KillSwitchState,
    Outcome,
    PolicySnapshot,
    Tool,
    ToolContext,
)
from .errors import (
    ApprovalRequired,
    ToolCoreError,
    ToolDenied,
    ToolExecutionError,
    ToolNotFound,
    ToolValidationError,
)
from .execute import execute_tool
from .redaction import args_hash, normalise_text, redact_args
from .registry import (
    clear,
    count,
    get_tool,
    list_specs,
    list_tools,
    register,
    register_if_absent,
    try_get_tool,
    unregister,
)
from .risk import READ, WRITE_DESTRUCTIVE, WRITE_REVERSIBLE, RiskClass

__all__ = [
    "ApprovalContext",
    "ApprovalRequired",
    "InvocationRecord",
    "KillSwitchState",
    "Outcome",
    "PolicySnapshot",
    "READ",
    "RiskClass",
    "Tool",
    "ToolContext",
    "ToolCoreError",
    "ToolDenied",
    "ToolExecutionError",
    "ToolNotFound",
    "ToolValidationError",
    "WRITE_DESTRUCTIVE",
    "WRITE_REVERSIBLE",
    "args_hash",
    "clear",
    "count",
    "execute_tool",
    "get_tool",
    "list_specs",
    "list_tools",
    "normalise_text",
    "redact_args",
    "register",
    "register_if_absent",
    "try_get_tool",
    "unregister",
]
