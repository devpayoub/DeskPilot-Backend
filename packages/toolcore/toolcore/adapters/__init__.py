"""Adapter interfaces and their implementations.

The tool layer never talks to an operating system directly. It calls an adapter,
which is why the same tools work against a real Windows host, a recorded fixture
in CI, a simulated host under ``SAFE_MODE``, or a remote host agent.
"""
from .diagnostics import DiagnosticsAdapter
from .directory import DirectoryAdapter, PRIVILEGED_GROUPS, ensure_not_privileged, generate_password
from .host_agent import HostAgentDiagnostics
from .ldap_directory import LdapDirectory
from .local_diagnostics import LocalDiagnostics
from .remediation import (
    LocalRemediation,
    RemediationAdapter,
    SimulatedHost,
    build_remediation_adapter,
)

__all__ = [
    "DiagnosticsAdapter",
    "DirectoryAdapter",
    "HostAgentDiagnostics",
    "LdapDirectory",
    "LocalDiagnostics",
    "LocalRemediation",
    "PRIVILEGED_GROUPS",
    "RemediationAdapter",
    "SimulatedHost",
    "build_remediation_adapter",
    "ensure_not_privileged",
    "generate_password",
]
