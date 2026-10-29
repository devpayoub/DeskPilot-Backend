"""One command to make the console usable: users, tool policies, and demo tickets.

    python manage.py bootstrap_demo

Idempotent. Passwords are development defaults and are printed, so nobody mistakes
them for secrets.
"""
from __future__ import annotations

from django.core.management import call_command
from django.core.management.base import BaseCommand

from apps.accounts.models import CustomUser, Role
from apps.guardrails.models import ToolPolicy
from apps.helpdesk.services import create_ticket

PASSWORD = "DeskPilot!2026"

USERS = [
    ("admin@deskpilot.test", "Amina Admin", Role.ADMIN),
    ("desk@deskpilot.test", "Sami Desk", Role.SERVICE_DESK),
    ("tech@deskpilot.test", "Karim Tech", Role.TECHNICIAN),
]

DEMO_TICKETS = [
    (
        "Laptop is out of space and won't save files",
        "Since yesterday I get 'disk full' when saving anything. Everything is slow too.",
        "DESK-01",
        "sam.user@deskpilot.test",
    ),
    (
        "Locked out after the holiday",
        "I came back from two weeks off and my account is locked. I cannot sign in at all.",
        "DESK-03",
        "m.gharbi@deskpilot.test",
    ),
    (
        "Printer shows offline",
        "The Finance printer shows offline on my PC but other people can still print.",
        "DESK-02",
        "s.benali@deskpilot.test",
    ),
]


class Command(BaseCommand):
    help = "Create demo users, seed tool policies and the directory, and add sample tickets."

    def handle(self, *args, **options):
        for email, display_name, role in USERS:
            user, created = CustomUser.objects.get_or_create(
                email=email, defaults={"display_name": display_name, "role": role}
            )
            user.display_name = display_name
            user.role = role
            user.set_password(PASSWORD)
            user.is_staff = role == Role.ADMIN
            user.save()
            self.stdout.write(f"  {'created' if created else 'updated'} {email} ({role})")

        call_command("seed_tool_policies")
        try:
            call_command("seed_directory")
        except Exception as exc:  # directory seeding is optional for a demo
            self.stderr.write(f"  directory seed skipped: {exc}")

        # Give every registered tool a policy row so the console's tools page is populated.
        self.stdout.write(f"  tool policies: {ToolPolicy.objects.count()}")

        from apps.helpdesk.models import Ticket

        for subject, body, host, email in DEMO_TICKETS:
            if Ticket.objects.filter(subject=subject).exists():
                continue
            create_ticket(
                subject=subject,
                body=body,
                device_hostname=host,
                requester_email=email,
                requester_name=email.split("@")[0].replace(".", " ").title(),
            )
            self.stdout.write(f"  ticket: {subject}")

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("Demo ready. Sign in with:"))
        self.stdout.write(f"  admin@deskpilot.test / {PASSWORD}   (full access)")
        self.stdout.write(f"  tech@deskpilot.test  / {PASSWORD}   (can approve writes)")
