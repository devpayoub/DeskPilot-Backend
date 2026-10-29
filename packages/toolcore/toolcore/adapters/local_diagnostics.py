"""Real diagnostics for the host this process runs on.

Read-only by construction: nothing here mutates state, so it is safe to call from
a container-side agent as well as from the native Windows host agent.

Note on service enumeration: ``psutil.win_service_iter()`` issues a WMI query per
service, so a full scan is the slowest call in the catalog (hundreds of ms). The
result is capped and reports how many were scanned, rather than silently trimming.
"""
from __future__ import annotations

import os
import platform
import socket
import time
from datetime import datetime, timezone

import psutil

from ..errors import ToolExecutionError
from . import windows_probe

_MAX_SERVICES_RETURNED = 100


def _windows_pending_reboot() -> bool | None:
    """Best-effort pending-reboot flag from the two canonical registry keys."""
    if os.name != "nt":
        return None
    try:
        import winreg
    except ImportError:  # pragma: no cover - only on non-Windows
        return None

    keys = (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
    )
    try:
        for path in keys:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path):
                    return True
            except FileNotFoundError:
                continue
        return False
    except OSError:
        return None


class LocalDiagnostics:
    """psutil-backed implementation of ``DiagnosticsAdapter``."""

    def warm_up(self) -> None:
        """Pay the one-time WMI cold-start cost at worker boot, not on first ticket.

        Measured on Windows 11: the first ``disk_partitions()`` call in a fresh
        process costs ~2.5s while WMI initialises; warm calls are 0.4-9ms. If a
        worker warms the adapter at startup, the p95 latency figure reflects real
        work instead of process start-up noise.
        """
        try:
            self.disk_health()
            self.system_health(0)
        except Exception:  # never let warm-up break boot
            pass

    def system_health(self, sample_seconds: float = 0.5) -> dict:
        cpu_percent = psutil.cpu_percent(interval=max(0.0, float(sample_seconds)))
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        boot = psutil.boot_time()
        now = time.time()

        return {
            "hostname": socket.gethostname(),
            "platform": f"{platform.system()} {platform.release()}",
            "cpu_percent": round(cpu_percent, 1),
            "cpu_count_logical": psutil.cpu_count(logical=True),
            "cpu_count_physical": psutil.cpu_count(logical=False),
            "memory_total_mb": round(memory.total / 1024 / 1024, 1),
            "memory_available_mb": round(memory.available / 1024 / 1024, 1),
            "memory_percent": memory.percent,
            "swap_percent": swap.percent,
            "uptime_seconds": max(0, int(now - boot)),
            "boot_time_utc": datetime.fromtimestamp(boot, tz=timezone.utc).isoformat(
                timespec="seconds"
            ),
            "pending_reboot": _windows_pending_reboot(),
        }

    def disk_health(self) -> dict:
        volumes: list[dict] = []
        skipped: list[str] = []

        for partition in psutil.disk_partitions(all=False):
            if "cdrom" in partition.opts or not partition.fstype:
                continue
            try:
                usage = psutil.disk_usage(partition.mountpoint)
            except (PermissionError, OSError):
                # Removable or protected volume: report it rather than hide it.
                skipped.append(partition.mountpoint)
                continue

            free_percent = round(100.0 - usage.percent, 1)
            volumes.append(
                {
                    "mount": partition.mountpoint,
                    "device": partition.device,
                    "fstype": partition.fstype,
                    "total_gb": round(usage.total / 1024**3, 1),
                    "used_gb": round(usage.used / 1024**3, 1),
                    "free_gb": round(usage.free / 1024**3, 1),
                    "free_percent": free_percent,
                    "low_space": free_percent < 10.0,
                }
            )

        volumes.sort(key=lambda v: v["free_percent"])
        return {
            "volumes": volumes,
            "volume_count": len(volumes),
            "any_low_space": any(v["low_space"] for v in volumes),
            "skipped_mounts": skipped,
        }

    def list_services(self, name_filter: str | None, state: str, detail: bool) -> dict:
        if not hasattr(psutil, "win_service_iter"):
            raise ToolExecutionError(
                "Service enumeration is only available on Windows hosts."
            )

        needle = (name_filter or "").lower()
        matched: list[dict] = []
        scanned = 0

        for service in psutil.win_service_iter():
            try:
                name = service.name()
            except Exception:
                continue
            scanned += 1
            if needle and needle not in name.lower():
                continue
            try:
                status = service.status()
            except Exception:
                continue
            if state != "all" and status != state:
                continue

            item = {"name": name, "status": status}
            if detail:
                try:
                    info = service.as_dict()
                    item["display_name"] = info.get("display_name")
                    item["start_type"] = info.get("start_type")
                    item["username"] = info.get("username")
                    item["pid"] = info.get("pid")
                except Exception:
                    item["detail_error"] = True
            matched.append(item)

        matched.sort(key=lambda s: s["name"].lower())
        return {
            "count": len(matched),
            "scanned": scanned,
            "truncated": len(matched) > _MAX_SERVICES_RETURNED,
            "services": matched[:_MAX_SERVICES_RETURNED],
        }

    # -- delegated probes ---------------------------------------------------
    # Event Log, registry and Windows Update need PowerShell or winreg; they live
    # in windows_probe so this module stays readable and the argv templates stay
    # in one auditable place.

    def read_event_log(self, log: str, level: str, hours: int, limit: int) -> dict:
        return windows_probe.read_event_log(log, level, hours, limit)

    def installed_software(self, name_contains: str | None) -> dict:
        return windows_probe.installed_software(name_contains)

    def windows_update_status(self) -> dict:
        return windows_probe.windows_update_status()

    def listening_ports(self, include_loopback: bool) -> dict:
        return windows_probe.listening_ports(include_loopback)

    def connectivity(self, host: str, port: int, timeout: float) -> dict:
        return windows_probe.connectivity(host, port, timeout)
