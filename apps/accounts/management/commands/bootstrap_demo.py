"""One command to make the console usable: users, tool policies, and demo tickets.

    python manage.py bootstrap_demo

Idempotent. Passwords are development defaults and are printed, so nobody mistakes
them for secrets.
"""
from __future__ import annotations

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.accounts.models import CustomUser, Role
from apps.guardrails.models import ToolPolicy
from apps.helpdesk.services import create_ticket
from apps.organizations.models import Membership
from apps.organizations.services import default_organization

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

    def add_arguments(self, parser):
        parser.add_argument(
            "--force",
            action="store_true",
            help="Allow running outside DEBUG. Needed because this sets a known password.",
        )

    def handle(self, *args, **options):
        # The password below is public — it is in a public repository. Creating an
        # is_staff account with it outside development is a backdoor, so refuse
        # unless someone deliberately overrides.
        if not settings.DEBUG and not options["force"]:
            self.stderr.write(
                self.style.ERROR(
                    "Refusing to seed demo accounts with the published development "
                    "password while DEBUG is off. Pass --force if this is intentional."
                )
            )
            raise SystemExit(1)

        organization = default_organization()

        for email, display_name, role in USERS:
            user, created = CustomUser.objects.get_or_create(
                email=email, defaults={"display_name": display_name, "role": role}
            )
            user.display_name = display_name
            user.role = role
            user.set_password(PASSWORD)
            user.is_staff = role == Role.ADMIN
            user.save()

            # The role the console gates on lives on the membership now; the field
            # on the user is only the single-workspace fallback.
            membership, _ = Membership.objects.get_or_create(
                user=user,
                organization=organization,
                defaults={"role": role, "accepted_at": timezone.now()},
            )
            if membership.role != role:
                membership.role = role
                membership.save(update_fields=["role"])
            if not Membership.objects.filter(
                organization=organization, is_owner=True
            ).exists():
                membership.is_owner = True
                membership.save(update_fields=["is_owner"])

            self.stdout.write(f"  {'created' if created else 'updated'} {email} ({role})")

        call_command("seed_tool_policies")
        try:
            call_command("seed_directory")
        except Exception as exc:  # directory seeding is optional for a demo
            self.stderr.write(f"  directory seed skipped: {exc}")

        # Give every registered tool a policy row so the console's tools page is populated.
        self.stdout.write(f"  tool policies: {ToolPolicy.objects.count()}")

        # Two departments so the Settings → Departments screen has something real
        # in it, and the desk user has somewhere to live.
        from apps.organizations.services import create_department
        from apps.organizations.services import TenancyError

        departments = {}
        for name, code in (("Service desk", "L1"), ("Field technicians", "FLD")):
            try:
                departments[code] = create_department(organization, name=name, code=code)
            except TenancyError:
                from apps.organizations.models import Department

                departments[code] = Department.objects.get(
                    organization=organization, name=name
                )
            self.stdout.write(f"  department: {name} ({code})")

        desk_membership = Membership.objects.filter(
            organization=organization, user__email="desk@deskpilot.test"
        ).first()
        if desk_membership is not None and desk_membership.department_id is None:
            desk_membership.department = departments["L1"]
            desk_membership.save(update_fields=["department"])

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
                organization=organization,
            )
            self.stdout.write(f"  ticket: {subject}")

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("Demo ready. Sign in with:"))
        self.stdout.write(f"  admin@deskpilot.test / {PASSWORD}   (full access)")
        self.stdout.write(f"  tech@deskpilot.test  / {PASSWORD}   (can approve writes)")
