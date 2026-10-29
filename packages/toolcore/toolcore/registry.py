"""The tool registry.

A plain module-level dict. Registration happens once at host startup; tests can
clear it and re-register to get a clean slate.
"""
from __future__ import annotations

from .base import Tool
from .errors import ToolNotFound

_REGISTRY: dict[str, Tool] = {}


def register(tool: Tool) -> Tool:
    if tool.name in _REGISTRY:
        raise ValueError(f"Duplicate tool name '{tool.name}'.")
    _REGISTRY[tool.name] = tool
    return tool


def register_if_absent(tool: Tool) -> Tool:
    """Idempotent registration — safe to call from an AppConfig.ready()."""
    existing = _REGISTRY.get(tool.name)
    if existing is not None:
        return existing
    _REGISTRY[tool.name] = tool
    return tool


def unregister(name: str) -> None:
    _REGISTRY.pop(name, None)


def clear() -> None:
    """Test helper. Never call this from application code."""
    _REGISTRY.clear()


def get_tool(name: str) -> Tool:
    tool = _REGISTRY.get(name)
    if tool is None:
        raise ToolNotFound(f"Unknown tool '{name}'.")
    return tool


def try_get_tool(name: str) -> Tool | None:
    return _REGISTRY.get(name)


def list_tools() -> list[Tool]:
    return sorted(_REGISTRY.values(), key=lambda t: t.name)


def list_specs() -> list[dict]:
    return [tool.spec() for tool in list_tools()]


def count() -> int:
    return len(_REGISTRY)
