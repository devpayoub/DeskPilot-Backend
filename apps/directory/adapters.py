"""Directory adapter backed by the local database — the seeded fake tenant.

Implements exactly the same interface as ``LdapDirectory``, so the tools and the
agent cannot tell which one is wired in. ``source`` stays ``fake`` on every row so an
audit can never mistake this data for a real domain.
"""
from __future__ import annotations

from django.db.models import Q
from django.utils import timezone

from toolcore.adapters.directory import ensure_not_privileged, generate_password
from toolcore.errors import ToolExecutionError

from .models import DirectoryGroup, Employee


def _serialise(employee: Employee) -> dict:
    return {
        "sam": employee.sam,
        "upn": employee.upn,
        "display_name": employee.display_name,
        "email": employee.email,
        "department": employee.department,
        "title": employee.title,
        "account_enabled": employee.account_enabled,
        "locked_out": employee.locked_out,
        "bad_password_count": employee.bad_password_count,
        "password_last_set": employee.password_last_set.isoformat()
        if employee.password_last_set
        else None,
        "last_logon": employee.last_logon.isoformat() if employee.last_logon else None,
        "manager": employee.manager.sam if employee.manager else None,
        "groups": sorted(employee.groups.values_list("name", flat=True)),
        "devices": sorted(employee.devices.values_list("hostname", flat=True)),
        "source": employee.source,
    }


class DatabaseDirectory:
    def _get(self, sam: str) -> Employee:
        employee = Employee.objects.filter(sam__iexact=sam).first()
        if employee is None:
            raise ToolExecutionError(f"User '{sam}' was not found.")
        return employee

    def lookup_user(self, query: str) -> dict | None:
        needle = (query or "").strip()
        if not needle:
            return None
        employee = Employee.objects.filter(
            Q(sam__iexact=needle) | Q(email__iexact=needle) | Q(upn__iexact=needle)
        ).first()
        if employee is None:
            employee = Employee.objects.filter(
                Q(display_name__icontains=needle) | Q(sam__icontains=needle)
            ).first()
        return _serialise(employee) if employee else None

    def get_group_membership(self, group: str | None, sam: str | None = None) -> dict:
        if sam:
            return {"user": sam, "groups": sorted(self._get(sam).groups.values_list("name", flat=True))}
        if not group:
            raise ToolExecutionError("Provide either 'group' or 'sam'.")

        record = DirectoryGroup.objects.filter(name__iexact=group).first()
        if record is None:
            raise ToolExecutionError(f"Group '{group}' was not found.")
        return {
            "group": record.name,
            "is_privileged": record.is_privileged,
            "members": sorted(
                (
                    {"sam": member.sam, "display_name": member.display_name}
                    for member in record.members.all()
                ),
                key=lambda item: item["sam"],
            ),
        }

    def unlock_account(self, sam: str, *, dry_run: bool) -> dict:
        employee = self._get(sam)
        plan = {
            "sam": employee.sam,
            "action": "clear lockout",
            "locked_out": employee.locked_out,
            "bad_password_count": employee.bad_password_count,
        }
        if dry_run:
            return {"dry_run": True, **plan}

        employee.locked_out = False
        employee.bad_password_count = 0
        employee.save(update_fields=["locked_out", "bad_password_count"])
        return {"dry_run": False, **plan, "unlocked": True, "verified": True}

    def reset_password(self, sam: str, force_change: bool, *, dry_run: bool) -> dict:
        employee = self._get(sam)
        if dry_run:
            return {"dry_run": True, "sam": employee.sam, "action": "set a new password"}

        employee.password_last_set = timezone.now()
        employee.locked_out = False
        employee.bad_password_count = 0
        employee.save(update_fields=["password_last_set", "locked_out", "bad_password_count"])
        return {
            "dry_run": False,
            "sam": employee.sam,
            "force_change": force_change,
            "password": generate_password(),
            "verified": True,
        }

    def _change_membership(self, group: str, sam: str, *, dry_run: bool, add: bool) -> dict:
        ensure_not_privileged(group)
        employee = self._get(sam)
        record = DirectoryGroup.objects.filter(name__iexact=group).first()
        if record is None:
            raise ToolExecutionError(f"Group '{group}' was not found.")

        already = employee.groups.filter(pk=record.pk).exists()
        plan = {
            "group": record.name,
            "sam": employee.sam,
            "action": "add" if add else "remove",
            "already_member": already,
        }
        if dry_run:
            return {"dry_run": True, **plan}

        if add:
            employee.groups.add(record)
        else:
            employee.groups.remove(record)
        return {"dry_run": False, **plan, "changed": True, "verified": True}

    def add_group_member(self, group: str, sam: str, *, dry_run: bool) -> dict:
        return self._change_membership(group, sam, dry_run=dry_run, add=True)

    def remove_group_member(self, group: str, sam: str, *, dry_run: bool) -> dict:
        return self._change_membership(group, sam, dry_run=dry_run, add=False)
