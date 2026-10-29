"""Turn the single hardcoded workspace into a real one.

Every deployment that already exists has users, tickets and audit rows but no
organisation. Rather than make those rows permanently invisible to the tenant
filters, this creates the default organisation and adopts them:

* one organisation, slug ``deskpilot`` — the same handle the API used to return
  from a constant;
* one membership per existing user, carrying that user's current role, so nobody
  loses access on deploy;
* every ticket and audit row assigned to it.

The first administrator becomes the owner. If there is no administrator at all the
oldest member is made owner, because an organisation with no owner is one nobody
can administer.
"""
from __future__ import annotations

from django.db import migrations
from django.utils import timezone

DEFAULT_SLUG = "deskpilot"
DEFAULT_NAME = "DeskPilot"


def backfill(apps, schema_editor):
    Organization = apps.get_model("organizations", "Organization")
    Membership = apps.get_model("organizations", "Membership")
    User = apps.get_model("accounts", "CustomUser")
    Ticket = apps.get_model("helpdesk", "Ticket")
    ToolInvocation = apps.get_model("guardrails", "ToolInvocation")

    organization, _ = Organization.objects.get_or_create(
        slug=DEFAULT_SLUG, defaults={"name": DEFAULT_NAME}
    )

    owner_assigned = False
    for user in User.objects.all().order_by("date_joined", "pk"):
        role = user.role or "REQUESTER"
        membership, created = Membership.objects.get_or_create(
            user=user,
            organization=organization,
            defaults={"role": role, "accepted_at": timezone.now()},
        )
        if created and not owner_assigned and role == "ADMIN":
            membership.is_owner = True
            membership.save(update_fields=["is_owner"])
            owner_assigned = True

    if not owner_assigned:
        oldest = Membership.objects.filter(organization=organization).order_by("pk").first()
        if oldest is not None:
            oldest.is_owner = True
            oldest.save(update_fields=["is_owner"])

    Ticket.objects.filter(organization__isnull=True).update(organization=organization)
    ToolInvocation.objects.filter(organization__isnull=True).update(organization=organization)


def unbackfill(apps, schema_editor):
    """Reverse only the adoption, never the memberships.

    Dropping memberships on a rollback would be a data-loss event dressed up as a
    schema change; the columns can go back to null without them.
    """
    Ticket = apps.get_model("helpdesk", "Ticket")
    ToolInvocation = apps.get_model("guardrails", "ToolInvocation")
    Ticket.objects.update(organization=None)
    ToolInvocation.objects.update(organization=None)


class Migration(migrations.Migration):

    dependencies = [
        ("organizations", "0001_initial"),
        ("accounts", "0001_initial"),
        ("helpdesk", "0004_ticket_organization_and_more"),
        ("guardrails", "0003_toolinvocation_organization_and_more"),
    ]

    operations = [migrations.RunPython(backfill, unbackfill)]
