"""Remediation adapters: the only code in DeskPilot that can change a machine.

Three implementations, one protocol:

* ``SimulatedHost`` — the default. Records what *would* happen and mutates nothing
  real. Selected whenever ``SAFE_MODE`` is on.
* ``LocalRemediation`` — real actions on the host this process runs on. Only
  reachable when ``ALLOW_REAL_WRITES=1``, and its temp roots are injectable so the
  deletion logic can be tested against a throwaway directory instead of yours.

Every method takes ``dry_run`` explicitly rather than reading it from context: a
destructive method should be unable to run without the caller having decided which
mode it is in.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..errors import ToolExecutionError

logger = logging.getLogger(__name__)

_ALLOWED_ROOTS = ("user_temp", "windows_temp")


@runtime_checkable
class RemediationAdapter(Protocol):
    def restart_service(self, service_name: str, *, dry_run: bool) -> dict: ...

    def clear_temp_files(self, root: str, max_gb: float, *, dry_run: bool) -> dict: ...

    def flush_dns_cache(self, *, dry_run: bool) -> dict: ...


class SimulatedHost:
    """A fake host that keeps state in memory. Nothing here touches the machine."""

    def __init__(self) -> None:
        self.services: dict[str, str] = {}
        self.temp_bytes: dict[str, int] = {"user_temp": 2_400_000_000, "windows_temp": 800_000_000}
        self.dns_flushes = 0

    def restart_service(self, service_name: str, *, dry_run: bool) -> dict:
        current = self.services.get(service_name, "running")
        plan = {
            "service": service_name,
            "current_status": current,
            "action": "stop, then start",
            "dependent_services": [],
        }
        if dry_run:
            return {"dry_run": True, "simulated": True, **plan}
        self.services[service_name] = "running"
        return {
            "dry_run": False,
            "simulated": True,
            **plan,
            "status": "running",
            "verified": True,
        }

    def clear_temp_files(self, root: str, max_gb: float, *, dry_run: bool) -> dict:
        available = self.temp_bytes.get(root, 0)
        budget = int(max_gb * 1024**3)
        removable = min(available, budget)
        if dry_run:
            return {
                "dry_run": True,
                "simulated": True,
                "root": root,
                "bytes_available": available,
                "bytes_removable": removable,
            }
        self.temp_bytes[root] = available - removable
        return {
            "dry_run": False,
            "simulated": True,
            "root": root,
            "bytes_removed": removable,
            "verified": True,
        }

    def flush_dns_cache(self, *, dry_run: bool) -> dict:
        if dry_run:
            return {"dry_run": True, "simulated": True, "action": "flush DNS resolver cache"}
        self.dns_flushes += 1
        return {"dry_run": False, "simulated": True, "flushed": True, "verified": True}


def _default_roots() -> dict[str, Path]:
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    return {
        "user_temp": Path(tempfile.gettempdir()),
        "windows_temp": Path(system_root) / "Temp",
    }


class LocalRemediation:
    """Real remediation on this host. Constructed only when explicitly enabled."""

    def __init__(self, roots: dict[str, Path] | None = None, *, runner=subprocess.run):
        self.roots = dict(roots) if roots is not None else _default_roots()
        self._run = runner

    # -- services -----------------------------------------------------------
    def restart_service(self, service_name: str, *, dry_run: bool) -> dict:
        if os.name != "nt":
            raise ToolExecutionError("Service restarts are only available on Windows.")

        current = self._service_status(service_name)
        if current is None:
            raise ToolExecutionError(f"Service '{service_name}' does not exist on this host.")

        plan = {
            "service": service_name,
            "current_status": current,
            "action": "stop, then start",
        }
        if dry_run:
            return {"dry_run": True, "simulated": False, **plan}

        # argv list, never a shell string: the service name cannot become a command.
        for verb in ("stop", "start"):
            completed = self._run(
                ["sc", verb, service_name],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if completed.returncode not in (0, 1056, 1062):
                raise ToolExecutionError(
                    f"sc {verb} {service_name} failed: {(completed.stderr or '').strip()[:200]}"
                )

        status = self._service_status(service_name)
        return {
            "dry_run": False,
            "simulated": False,
            **plan,
            "status": status,
            # An unverified success is recorded as a failure, not as a win.
            "verified": status == "running",
        }

    @staticmethod
    def _service_status(service_name: str) -> str | None:
        import psutil

        if not hasattr(psutil, "win_service_iter"):
            return None
        try:
            service = psutil.win_service_get(service_name)
            return service.status()
        except Exception:
            return None

    # -- temp files ---------------------------------------------------------
    def clear_temp_files(self, root: str, max_gb: float, *, dry_run: bool) -> dict:
        if root not in _ALLOWED_ROOTS:
            raise ToolExecutionError(f"Unknown temp root '{root}'.")

        base = self.roots.get(root)
        if base is None or not base.exists():
            raise ToolExecutionError(f"Temp root '{root}' is not present on this host.")

        budget = int(max_gb * 1024**3)
        planned: list[tuple[Path, int]] = []
        total = 0

        for entry in base.rglob("*"):
            if total >= budget:
                break
            try:
                if entry.is_symlink() or not entry.is_file():
                    continue
                size = entry.stat().st_size
            except OSError:
                continue
            if total + size > budget:
                break
            planned.append((entry, size))
            total += size

        preview = {
            "root": str(base),
            "file_count": len(planned),
            "bytes_removable": total,
            "sample": [path.name for path, _ in planned[:10]],
        }
        if dry_run:
            return {"dry_run": True, "simulated": False, **preview}

        removed = 0
        failures = 0
        for path, size in planned:
            try:
                path.unlink()
                removed += size
            except OSError:
                failures += 1  # locked or already gone; keep going

        return {
            "dry_run": False,
            "simulated": False,
            **preview,
            "bytes_removed": removed,
            "failed_files": failures,
            "verified": removed > 0 or not planned,
        }

    # -- dns ----------------------------------------------------------------
    def flush_dns_cache(self, *, dry_run: bool) -> dict:
        if os.name != "nt":
            raise ToolExecutionError("DNS cache flushing is only available on Windows.")
        if dry_run:
            return {"dry_run": True, "simulated": False, "action": "ipconfig /flushdns"}
        completed = self._run(
            ["ipconfig", "/flushdns"], capture_output=True, text=True, timeout=30, check=False
        )
        if completed.returncode != 0:
            raise ToolExecutionError(
                f"ipconfig /flushdns failed: {(completed.stderr or '').strip()[:200]}"
            )
        return {"dry_run": False, "simulated": False, "flushed": True, "verified": True}


def build_remediation_adapter(*, safe_mode: bool, allow_real_writes: bool) -> RemediationAdapter:
    """Pick the adapter. Real actions require *both* switches to be off/on correctly."""
    if safe_mode or not allow_real_writes:
        return SimulatedHost()
    logger.warning("REAL remediation adapter enabled — actions will change this machine")
    return LocalRemediation()


def disk_usage_of(path: Path) -> int:
    """Total bytes under a directory, for reporting. Never raises."""
    try:
        return shutil.disk_usage(path).used
    except OSError:
        return 0
