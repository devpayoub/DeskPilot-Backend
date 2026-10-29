"""Seed a small, realistic fake tenant so the agent has something to investigate.

Idempotent: re-running updates the same rows rather than duplicating them. Every
row is marked ``source=fake``.
"""
from __future__ import annotations

from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.directory.models import Device, DirectoryGroup, Employee

GROUPS = [
    ("IT Support", False),
    ("VPN Users", False),
    ("Finance", False),
    ("Domain Admins", True),
    ("Administrators", True),
]

EMPLOYEES = [
    # sam, name, dept, title, locked, bad_pw, groups
    ("a.trabelsi", "Ayoub Trabelsi", "IT", "IT Technician", False, 0, ["IT Support", "VPN Users"]),
    ("s.benali", "Sami Ben Ali", "Finance", "Accountant", False, 0, ["Finance", "VPN Users"]),
    ("m.gharbi", "Mouna Gharbi", "Finance", "Finance Manager", True, 7, ["Finance"]),
    ("l.mansour", "Leila Mansour", "Sales", "Sales Lead", False, 0, ["VPN Users"]),
    ("k.zaidi", "Karim Zaidi", "IT", "Systems Administrator", False, 0, ["IT Support", "Domain Admins"]),
    ("n.jaziri", "Nour Jaziri", "HR", "HR Officer", False, 2, []),
    ("h.bouazizi", "Hedi Bouazizi", "Operations", "Site Supervisor", False, 0, ["VPN Users"]),
    ("f.sassi", "Fatma Sassi", "Sales", "Account Manager", False, 1, []),
]

DEVICES = [
    ("DESK-01", "OptiPlex 7090", "a.trabelsi", "BitLocker on", 12.4),
    ("DESK-02", "OptiPlex 7090", "s.benali", "BitLocker on", 41.0),
    ("DESK-03", "Latitude 5430", "m.gharbi", "BitLocker on", 6.1),
    ("LAP-07", "Latitude 7440", "l.mansour", "BitLocker off", 63.5),
    ("DESK-11", "ThinkCentre M70q", "h.bouazizi", "BitLocker on", 28.9),
]


class Command(BaseCommand):
    help = "Seed the fake directory tenant (groups, employees, devices)."

    def handle(self, *args, **options):
        now = timezone.now()

        group_objects = {}
        for name, privileged in GROUPS:
            group, _ = DirectoryGroup.objects.update_or_create(
                name=name,
                defaults={
                    "distinguished_name": f"cn={name},ou=groups,dc=deskpilot,dc=test",
                    "is_privileged": privileged,
                },
            )
            group_objects[name] = group

        for sam, display_name, dept, title, locked, bad_pw, groups in EMPLOYEES:
            employee, _ = Employee.objects.update_or_create(
                sam=sam,
                defaults={
                    "external_id": f"fake-{sam}",
                    "upn": f"{sam}@deskpilot.test",
                    "display_name": display_name,
                    "email": f"{sam}@deskpilot.test",
                    "department": dept,
                    "title": title,
                    "account_enabled": True,
                    "locked_out": locked,
                    "bad_password_count": bad_pw,
                    "password_last_set": now - timedelta(days=42),
                    "last_logon": now - timedelta(hours=6),
                    "source": Employee.Source.FAKE,
                    "synced_at": now,
                },
            )
            employee.groups.set([group_objects[name] for name in groups])

        for hostname, model, sam, bitlocker, free_pct in DEVICES:
            owner = Employee.objects.filter(sam=sam).first()
            Device.objects.update_or_create(
                hostname=hostname,
                defaults={
                    "model": model,
                    "serial": f"SN-{hostname}",
                    "os_build": "Windows 11 23H2",
                    "assigned_employee": owner,
                    "last_seen": now - timedelta(minutes=12),
                    "bitlocker_status": bitlocker,
                    "free_disk_pct": free_pct,
                },
            )

        self.stdout.write(
            self.style.SUCCESS(
                f"Seeded {len(GROUPS)} groups, {len(EMPLOYEES)} employees, "
                f"{len(DEVICES)} devices."
            )
        )
