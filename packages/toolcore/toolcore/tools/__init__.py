"""Tool implementations, grouped by domain.

``register_all`` is the one entry point a host calls at startup. It is idempotent,
so calling it from an AppConfig.ready() and again from a test fixture is safe.
"""
from .host import HOST_TOOLS, register_host_tools
from .identity import IDENTITY_TOOLS, register_identity_tools
from .remediation import REMEDIATION_TOOLS, register_remediation_tools


def register_all() -> None:
    """Register every tool in the catalog."""
    register_host_tools()
    register_remediation_tools()
    register_identity_tools()


__all__ = [
    "HOST_TOOLS",
    "IDENTITY_TOOLS",
    "REMEDIATION_TOOLS",
    "register_all",
    "register_host_tools",
    "register_identity_tools",
    "register_remediation_tools",
]
