"""Remove platform admins from customer rosters.

``0002`` adopted every existing user into the default organisation, including
Django superusers. That was right for the accounts that predated tenancy, but it
was wrong for the platform operator: a ``is_superuser`` is the operator of
DeskPilot itself, deliberately **not** a member of any customer's account.

Leaving those rows in place had three consequences, all of them wrong:

* the project admin appeared on the company member list at
  ``/dashboard/settings/members``, alongside the real company administrators;
* the membership became their default tenant, so the documented escape hatch —
  name an account with ``X-Organization`` and act in it — was ignored in favour
  of the membership they happened to be given;
* their row counted towards the "last administrator" check, so a real
  administrator could be demoted while an invisible platform admin kept the
  account looking staffed.

This migration deletes those rows. Any organisation they owned passes ownership
to another active member, so no account is left without an administrator.

The rows are *memberships*, not people: the superuser account itself is
untouched and keeps working. This is not a rollback-friendly operation and does
not pretend to be — reversing it would mean re-adding rows whose primary keys
are long gone. The reverse is a no-op, deliberately.
"""
from __future__ import annotations

from django.db import migrations


def _replacement_owner(Membership, organization):
    """Another member who can take ownership, preferring an administrator.

    Ordering by role *string* would be wrong — "TECHNICIAN" sorts above "ADMIN"
    alphabetically — so the administrator is selected explicitly and the rest are
    only considered if there is no administrator left.
    """
    candidates = Membership.objects.filter(
        organization=organization, is_active=True
    ).exclude(user__is_superuser=True)
    administrator = candidates.filter(role="ADMIN").order_by("created_at", "pk").first()
    if administrator is not None:
        return administrator
    return candidates.order_by("created_at", "pk").first()


def purge_platform_admin_memberships(apps, schema_editor):
    Membership = apps.get_model("organizations", "Membership")

    stale = list(Membership.objects.filter(user__is_superuser=True))
    for membership in stale:
        organization = membership.organization
        if membership.is_owner:
            replacement = _replacement_owner(Membership, organization)
            if replacement is not None:
                replacement.is_owner = True
                replacement.save(update_fields=["is_owner"])
        membership.delete()


def restore_platform_admin_memberships(apps, schema_editor):
    """Deliberately empty.

    Re-creating these rows would put the platform operator back on customer
    rosters and re-break the escape hatch. The correct way to get a superuser
    membership back, if one is ever genuinely wanted, is to create it
    deliberately — not to roll back a data migration.
    """


class Migration(migrations.Migration):

    dependencies = [
        ("organizations", "0002_backfill_default_organization"),
        ("accounts", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(
            purge_platform_admin_memberships,
            restore_platform_admin_memberships,
        )
    ]
