"""Tool-layer exceptions.

Every one carries a stable ``code`` so the audit trail and the HTTP layer can
report the same identifier without string-matching messages.
"""
from __future__ import annotations


class ToolCoreError(Exception):
    code = "tool_error"


class ToolNotFound(ToolCoreError):
    code = "tool_not_found"


class ToolValidationError(ToolCoreError):
    code = "invalid_arguments"


class ToolDenied(ToolCoreError):
    """Policy, kill switch, or role authorization refused the call."""

    code = "denied"


class ApprovalRequired(ToolCoreError):
    """A write was proposed without a valid approval token for this argument set."""

    code = "approval_required"


class ToolExecutionError(ToolCoreError):
    code = "tool_failed"
