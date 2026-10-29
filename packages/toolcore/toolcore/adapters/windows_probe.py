"""Windows-only probes: Event Log, installed software, Windows Update, sockets.

Every external process call here uses a **fixed argv** with ``shell=False``. User
input never reaches a command line: log names and levels are mapped through
allowlists, and numeric arguments are cast to ``int`` before interpolation. This
is the same reason there is no generic ``run_command`` tool — the surface for a
command injection simply does not exist.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time

import psutil

from ..errors import ToolExecutionError

_PS_TIMEOUT = 30

# Allowlisted Event Log names. A caller cannot name an arbitrary log.
EVENT_LOGS = {
    "system": "System",
    "application": "Application",
    "security": "Security",
}

# Level numbers as used by the Windows Event Log (Get-WinEvent -FilterHashtable).
EVENT_LEVELS = {
    "all": None,
    "critical": 1,
    "error": 2,
    "warning": 3,
    "information": 4,
}

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")


def _require_windows(what: str) -> None:
    if os.name != "nt":
        raise ToolExecutionError(f"{what} is only available on Windows hosts.")


def _run_powershell(script: str, timeout: int = _PS_TIMEOUT) -> str:
    """Run a constant script through PowerShell. Never takes user-supplied text."""
    _require_windows("PowerShell probing")
    try:
        completed = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolExecutionError(f"PowerShell probe timed out after {timeout}s.") from exc
    except FileNotFoundError as exc:
        raise ToolExecutionError("powershell.exe was not found on PATH.") from exc

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip().splitlines()
        detail = stderr[-1] if stderr else "unknown error"
        raise ToolExecutionError(f"PowerShell probe failed: {detail}")
    return completed.stdout.strip()


def read_event_log(log: str, level: str, hours: int, limit: int) -> dict:
    """Query the Windows Event Log with allowlisted log names and levels."""
    _require_windows("Reading the event log")

    if log not in EVENT_LOGS:
        raise ToolExecutionError(f"Unknown log '{log}'. Allowed: {sorted(EVENT_LOGS)}.")
    if level not in EVENT_LEVELS:
        raise ToolExecutionError(f"Unknown level '{level}'. Allowed: {sorted(EVENT_LEVELS)}.")

    log_name = EVENT_LOGS[log]                      # allowlisted constant
    level_filter = EVENT_LEVELS[level]
    hours = int(hours)                              # cast: cannot carry a payload
    limit = int(limit)

    level_line = f'$filter["Level"] = {level_filter}' if level_filter is not None else ""

    script = f"""
$ErrorActionPreference = "Stop"
$filter = @{{ LogName = "{log_name}"; StartTime = (Get-Date).AddHours(-{hours}) }}
{level_line}
try {{
    $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents {limit} -ErrorAction Stop)
}} catch {{
    if ($_.Exception.Message -match "No events were found") {{
        Write-Output "[]"
        exit 0
    }}
    throw
}}
if ($events.Count -eq 0) {{ Write-Output "[]"; exit 0 }}
$events |
    Select-Object @{{ n = "time";     e = {{ $_.TimeCreated.ToString("o") }} }},
                  @{{ n = "level";    e = {{ $_.LevelDisplayName }} }},
                  @{{ n = "provider"; e = {{ $_.ProviderName }} }},
                  @{{ n = "id";       e = {{ $_.Id }} }},
                  @{{ n = "message";  e = {{ ($_.Message -split "`r?`n")[0] }} }} |
    ConvertTo-Json -Depth 3 -Compress
"""

    raw = _run_powershell(script)
    if not raw:
        return {"log": log_name, "level": level, "count": 0, "events": []}

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ToolExecutionError("Event log output was not valid JSON.") from exc

    # ConvertTo-Json emits a bare object for a single result.
    events = parsed if isinstance(parsed, list) else [parsed]
    for event in events:
        if isinstance(event.get("message"), str) and len(event["message"]) > 300:
            event["message"] = event["message"][:300] + "…"

    return {"log": log_name, "level": level, "count": len(events), "events": events}


def installed_software(name_contains: str | None, limit: int = 150) -> dict:
    """Enumerate installed software from the three canonical Uninstall registry keys."""
    _require_windows("Reading installed software")
    import winreg

    roots = (
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    )
    fields = ("DisplayName", "DisplayVersion", "Publisher", "InstallDate")
    needle = (name_contains or "").lower()

    seen: set[tuple[str, str]] = set()
    found: list[dict] = []
    unreadable = 0

    for hive, path in roots:
        try:
            key = winreg.OpenKey(hive, path)
        except OSError:
            continue
        with key:
            index = 0
            while True:
                try:
                    sub_name = winreg.EnumKey(key, index)
                except OSError:
                    break
                index += 1
                try:
                    with winreg.OpenKey(key, sub_name) as sub:
                        values = {}
                        for field in fields:
                            try:
                                values[field] = winreg.QueryValueEx(sub, field)[0]
                            except OSError:
                                values[field] = None
                except OSError:
                    unreadable += 1
                    continue

                name = values.get("DisplayName")
                if not name:
                    continue  # patch entries have no display name
                if needle and needle not in str(name).lower():
                    continue

                dedupe = (str(name), str(values.get("DisplayVersion") or ""))
                if dedupe in seen:
                    continue
                seen.add(dedupe)

                found.append(
                    {
                        "name": str(name),
                        "version": values.get("DisplayVersion"),
                        "publisher": values.get("Publisher"),
                        "install_date": values.get("InstallDate"),
                    }
                )

    found.sort(key=lambda item: item["name"].lower())
    return {
        "count": len(found),
        "truncated": len(found) > limit,
        "unreadable_entries": unreadable,
        "software": found[:limit],
    }


def windows_update_status() -> dict:
    """Pending-update count via the Windows Update COM API, plus recent hotfixes."""
    _require_windows("Reading Windows Update status")

    script = """
$ErrorActionPreference = "Stop"
$pending = $null
try {
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $pending  = $searcher.Search("IsInstalled=0").Updates.Count
} catch {
    $pending = $null
}
$hotfixes = @()
try {
    $hotfixes = @(Get-HotFix -ErrorAction Stop |
        Sort-Object InstalledOn -Descending |
        Select-Object -First 5 |
        ForEach-Object {
            @{ id = $_.HotFixID; description = $_.Description
               installed_on = if ($_.InstalledOn) { $_.InstalledOn.ToString("yyyy-MM-dd") } else { $null } }
        })
} catch { $hotfixes = @() }
$reboot = $false
if (Test-Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending") { $reboot = $true }
if (Test-Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired") { $reboot = $true }
@{ pending_count = $pending; pending_reboot = $reboot; recent_hotfixes = $hotfixes } |
    ConvertTo-Json -Depth 4 -Compress
"""

    raw = _run_powershell(script, timeout=60)
    try:
        data = json.loads(raw) if raw else {}
    except json.JSONDecodeError as exc:
        raise ToolExecutionError("Windows Update output was not valid JSON.") from exc

    hotfixes = data.get("recent_hotfixes") or []
    if isinstance(hotfixes, dict):  # single item is serialised as an object
        hotfixes = [hotfixes]

    return {
        "pending_count": data.get("pending_count"),
        "pending_reboot": bool(data.get("pending_reboot")),
        "recent_hotfixes": hotfixes,
        "note": (
            "pending_count is null when the Windows Update service is unreachable "
            "or the COM search failed."
        ),
    }


def listening_ports(include_loopback: bool = False, limit: int = 80) -> dict:
    """Listening TCP sockets with their owning process, when resolvable."""
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError) as exc:
        raise ToolExecutionError(
            "Reading the socket table requires elevated privileges on this host."
        ) from exc

    rows: list[dict] = []
    for conn in connections:
        if conn.status != psutil.CONN_LISTEN:
            continue
        host = conn.laddr.ip if conn.laddr else ""
        if not include_loopback and host in ("127.0.0.1", "::1"):
            continue

        process_name = None
        if conn.pid:
            try:
                process_name = psutil.Process(conn.pid).name()
            except (psutil.Error, OSError):
                process_name = None

        rows.append(
            {
                "port": conn.laddr.port if conn.laddr else None,
                "address": host,
                "family": "ipv6" if ":" in host else "ipv4",
                "pid": conn.pid,
                "process": process_name,
            }
        )

    rows.sort(key=lambda row: (row["port"] or 0))
    return {
        "count": len(rows),
        "truncated": len(rows) > limit,
        "ports": rows[:limit],
    }


def connectivity(host: str, port: int, timeout: float = 3.0) -> dict:
    """Resolve a hostname and attempt one TCP connection, timing it."""
    if not _HOSTNAME_RE.match(host or ""):
        raise ToolExecutionError("'host' is not a valid hostname or IP address.")
    port = int(port)

    try:
        addresses = sorted({info[4][0] for info in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)})
    except socket.gaierror as exc:
        return {
            "host": host,
            "port": port,
            "dns_resolved": False,
            "reachable": False,
            "error": f"DNS resolution failed: {exc}",
        }

    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency_ms = round((time.perf_counter() - started) * 1000, 1)
            return {
                "host": host,
                "port": port,
                "dns_resolved": True,
                "addresses": addresses,
                "reachable": True,
                "latency_ms": latency_ms,
            }
    except (socket.timeout, TimeoutError):
        return {
            "host": host,
            "port": port,
            "dns_resolved": True,
            "addresses": addresses,
            "reachable": False,
            "error": f"TCP connect timed out after {timeout}s",
        }
    except OSError as exc:
        return {
            "host": host,
            "port": port,
            "dns_resolved": True,
            "addresses": addresses,
            "reachable": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
