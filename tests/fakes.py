"""Deterministic stand-ins for the adapter layer.

CI must never depend on the machine it runs on, so every tool test injects a fake
adapter rather than touching psutil.
"""
from __future__ import annotations


class FakeDiagnostics:
    """Minimal DiagnosticsAdapter with canned, assertable results."""

    def __init__(self, health: dict | None = None, disks: dict | None = None,
                 services: dict | None = None):
        self.health = health if health is not None else {
            "hostname": "TEST-HOST",
            "platform": "Windows 11",
            "cpu_percent": 12.5,
            "cpu_count_logical": 8,
            "cpu_count_physical": 4,
            "memory_total_mb": 16384.0,
            "memory_available_mb": 9216.0,
            "memory_percent": 43.8,
            "swap_percent": 2.0,
            "uptime_seconds": 7200,
            "boot_time_utc": "2026-10-26T08:00:00+00:00",
            "pending_reboot": False,
        }
        self.disks = disks if disks is not None else {
            "volumes": [
                {
                    "mount": "C:\\",
                    "device": "C:",
                    "fstype": "NTFS",
                    "total_gb": 476.9,
                    "used_gb": 456.8,
                    "free_gb": 20.1,
                    "free_percent": 4.2,
                    "low_space": True,
                }
            ],
            "volume_count": 1,
            "any_low_space": True,
            "skipped_mounts": [],
        }
        self.services = services if services is not None else {
            "count": 1,
            "scanned": 1,
            "truncated": False,
            "services": [{"name": "Spooler", "status": "stopped"}],
        }
        self.events = {
            "log": "System",
            "level": "error",
            "count": 1,
            "events": [
                {
                    "time": "2026-10-26T09:14:00+00:00",
                    "level": "Error",
                    "provider": "PrintService",
                    "id": 372,
                    "message": "The print spooler terminated unexpectedly.",
                }
            ],
        }
        self.software = {
            "count": 2,
            "truncated": False,
            "unreadable_entries": 0,
            "software": [
                {"name": "Microsoft 365 Apps", "version": "16.0.1", "publisher": "Microsoft",
                 "install_date": "20260901"},
                {"name": "7-Zip 24.07", "version": "24.07", "publisher": "Igor Pavlov",
                 "install_date": "20260812"},
            ],
        }
        self.updates = {
            "pending_count": 3,
            "pending_reboot": False,
            "recent_hotfixes": [{"id": "KB5043145", "description": "Security Update",
                                 "installed_on": "2026-10-10"}],
            "note": "fixture",
        }
        self.ports = {
            "count": 1,
            "truncated": False,
            "ports": [{"port": 3389, "address": "0.0.0.0", "family": "ipv4",
                       "pid": 1180, "process": "svchost.exe"}],
        }
        self.connectivity_result = {
            "host": "intranet.example",
            "port": 443,
            "dns_resolved": True,
            "addresses": ["10.0.0.12"],
            "reachable": True,
            "latency_ms": 4.2,
        }
        self.calls: list[tuple[str, tuple]] = []

    def system_health(self, sample_seconds: float) -> dict:
        self.calls.append(("system_health", (sample_seconds,)))
        return self.health

    def disk_health(self) -> dict:
        self.calls.append(("disk_health", ()))
        return self.disks

    def list_services(self, name_filter, state, detail) -> dict:
        self.calls.append(("list_services", (name_filter, state, detail)))
        return self.services

    def read_event_log(self, log, level, hours, limit) -> dict:
        self.calls.append(("read_event_log", (log, level, hours, limit)))
        return self.events

    def installed_software(self, name_contains) -> dict:
        self.calls.append(("installed_software", (name_contains,)))
        return self.software

    def windows_update_status(self) -> dict:
        self.calls.append(("windows_update_status", ()))
        return self.updates

    def listening_ports(self, include_loopback) -> dict:
        self.calls.append(("listening_ports", (include_loopback,)))
        return self.ports

    def connectivity(self, host, port, timeout) -> dict:
        self.calls.append(("connectivity", (host, port, timeout)))
        return self.connectivity_result
