"""Remediation adapters: simulation by default, real logic tested on a temp dir."""
from __future__ import annotations

from pathlib import Path

import pytest

from toolcore.adapters.remediation import (
    LocalRemediation,
    SimulatedHost,
    build_remediation_adapter,
)
from toolcore.errors import ToolExecutionError


# ---------------------------------------------------------------------------
# Simulated host — the default
# ---------------------------------------------------------------------------
def test_simulated_restart_does_not_change_state_on_dry_run():
    host = SimulatedHost()

    result = host.restart_service("Spooler", dry_run=True)

    assert result["dry_run"] is True
    assert result["simulated"] is True
    assert "Spooler" not in host.services


def test_simulated_restart_reports_running_after_execution():
    host = SimulatedHost()

    result = host.restart_service("Spooler", dry_run=False)

    assert result["status"] == "running"
    assert result["verified"] is True
    assert host.services["Spooler"] == "running"


def test_simulated_clear_temp_reports_removable_bytes_without_removing():
    host = SimulatedHost()
    before = host.temp_bytes["user_temp"]

    result = host.clear_temp_files("user_temp", 1.0, dry_run=True)

    assert result["bytes_removable"] == 1024**3
    assert host.temp_bytes["user_temp"] == before


def test_simulated_clear_temp_bounds_by_the_budget():
    host = SimulatedHost()

    result = host.clear_temp_files("user_temp", 0.5, dry_run=True)

    assert result["bytes_removable"] == int(0.5 * 1024**3)


# ---------------------------------------------------------------------------
# Adapter selection
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("safe_mode", "allow_real"),
    [(True, False), (True, True), (False, False)],
)
def test_real_adapter_requires_both_switches(safe_mode, allow_real):
    adapter = build_remediation_adapter(safe_mode=safe_mode, allow_real_writes=allow_real)

    assert isinstance(adapter, SimulatedHost)


def test_real_adapter_is_selected_only_when_explicitly_enabled():
    adapter = build_remediation_adapter(safe_mode=False, allow_real_writes=True)

    assert isinstance(adapter, LocalRemediation)


# ---------------------------------------------------------------------------
# Real deletion logic, exercised against a throwaway directory
# ---------------------------------------------------------------------------
@pytest.fixture
def temp_root(tmp_path: Path) -> Path:
    for index in range(5):
        (tmp_path / f"file{index}.tmp").write_bytes(b"x" * 1024)
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "deep.log").write_bytes(b"y" * 2048)
    return tmp_path


EXPECTED_BYTES = 5 * 1024 + 2048  # five 1 KB files plus one 2 KB file


def test_real_dry_run_lists_files_without_deleting(temp_root):
    adapter = LocalRemediation(roots={"user_temp": temp_root})

    result = adapter.clear_temp_files("user_temp", 1.0, dry_run=True)

    assert result["dry_run"] is True
    assert result["file_count"] == 6
    assert result["bytes_removable"] == EXPECTED_BYTES
    assert len(list(temp_root.rglob("*"))) >= 6, "dry run must not delete anything"


def test_real_run_deletes_and_reports_what_it_removed(temp_root):
    adapter = LocalRemediation(roots={"user_temp": temp_root})

    result = adapter.clear_temp_files("user_temp", 1.0, dry_run=False)

    assert result["dry_run"] is False
    assert result["bytes_removed"] == EXPECTED_BYTES
    assert result["failed_files"] == 0
    # Files are removed; empty directories are deliberately left in place —
    # deleting directories is a much larger blast radius for zero bytes saved.
    assert [p for p in temp_root.rglob("*") if p.is_file()] == []


def test_real_run_respects_the_size_budget(temp_root):
    adapter = LocalRemediation(roots={"user_temp": temp_root})

    # 1 KB budget: it must stop well short of the 6 KB available.
    result = adapter.clear_temp_files("user_temp", 0.1 / 1024, dry_run=True)

    assert result["bytes_removable"] <= 0.1 / 1024 * 1024**3


def test_real_run_rejects_an_unknown_root(temp_root):
    adapter = LocalRemediation(roots={"user_temp": temp_root})

    with pytest.raises(ToolExecutionError, match="Unknown temp root"):
        adapter.clear_temp_files("c_drive_root", 1.0, dry_run=True)


def test_real_run_errors_when_the_root_is_missing(tmp_path):
    adapter = LocalRemediation(roots={"user_temp": tmp_path / "does-not-exist"})

    with pytest.raises(ToolExecutionError, match="not present"):
        adapter.clear_temp_files("user_temp", 1.0, dry_run=True)


# ---------------------------------------------------------------------------
# Real service restart, with a fake `sc` runner
# ---------------------------------------------------------------------------
def test_real_restart_dry_run_issues_no_commands(monkeypatch):
    calls: list[list[str]] = []
    monkeypatch.setattr(
        LocalRemediation, "_service_status", staticmethod(lambda name: "stopped")
    )
    adapter = LocalRemediation(runner=lambda argv, **kw: calls.append(argv))

    result = adapter.restart_service("Spooler", dry_run=True)

    assert result["dry_run"] is True
    assert result["current_status"] == "stopped"
    assert calls == []


def test_real_restart_runs_sc_and_verifies(monkeypatch):
    calls: list[list[str]] = []

    states = iter(["stopped", "running"])
    monkeypatch.setattr(
        LocalRemediation, "_service_status", staticmethod(lambda name: next(states))
    )

    class _Completed:
        returncode = 0
        stderr = ""

    adapter = LocalRemediation(runner=lambda argv, **kw: calls.append(argv) or _Completed())

    result = adapter.restart_service("Spooler", dry_run=False)

    assert calls == [["sc", "stop", "Spooler"], ["sc", "start", "Spooler"]]
    assert result["status"] == "running"
    assert result["verified"] is True


def test_real_restart_reports_unverified_when_the_service_stays_down(monkeypatch):
    monkeypatch.setattr(
        LocalRemediation, "_service_status", staticmethod(lambda name: "stopped")
    )

    class _Completed:
        returncode = 0
        stderr = ""

    adapter = LocalRemediation(runner=lambda argv, **kw: _Completed())

    result = adapter.restart_service("Spooler", dry_run=False)

    assert result["verified"] is False, "an unverified success must not be reported as success"


def test_real_restart_rejects_a_service_that_does_not_exist(monkeypatch):
    monkeypatch.setattr(
        LocalRemediation, "_service_status", staticmethod(lambda name: None)
    )
    adapter = LocalRemediation(runner=lambda argv, **kw: None)

    with pytest.raises(ToolExecutionError, match="does not exist"):
        adapter.restart_service("NotARealService", dry_run=False)
