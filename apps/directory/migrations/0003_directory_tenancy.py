"""Give every directory row an organisation, without losing the seeded rows.

Three steps rather than one because the column is non-nullable and the table is not
empty: adding a required FK straight to existing rows is refused by every database,
and a hand-written default here would silently decide that every person and machine
on the platform belongs to whichever workspace the migration author happened to have
in mind. So the field goes in nullable, the rows are pointed at the default
single-workspace organisation that already exists for exactly this purpose, and only
then is the column closed.
"""

from django.db import migrations, models
import django.db.models.deletion

# Inlined rather than imported from apps.organizations: a migration must keep
# running after the app code around it changes, and the default organisation has
# been the same pair of strings since tenancy began.
DEFAULT_ORGANIZATION_SLUG = "deskpilot"
DEFAULT_ORGANIZATION_NAME = "DeskPilot"

MODEL_NAMES = ("DirectoryGroup", "Employee", "Device", "PasswordReset")


def backfill_organization(apps, schema_editor):
    Organization = apps.get_model("organizations", "Organization")
    organization, _ = Organization.objects.get_or_create(
        slug=DEFAULT_ORGANIZATION_SLUG,
        defaults={"name": DEFAULT_ORGANIZATION_NAME},
    )
    for name in MODEL_NAMES:
        Model = apps.get_model("directory", name)
        Model.objects.filter(organization__isnull=True).update(organization=organization)


def drop_organization(apps, schema_editor):
    """Reverse only has to null the column again; the FK is removed by the schema."""
    for name in MODEL_NAMES:
        Model = apps.get_model("directory", name)
        Model.objects.filter(organization__isnull=False).update(organization=None)


class Migration(migrations.Migration):
    dependencies = [
        ("organizations", "0002_backfill_default_organization"),
        ("directory", "0002_encrypt_password_reset"),
    ]

    operations = [
        migrations.AddField(
            model_name="directorygroup",
            name="organization",
            field=models.ForeignKey(
                "organizations.Organization",
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="directory_groups",
            ),
        ),
        migrations.AddField(
            model_name="employee",
            name="organization",
            field=models.ForeignKey(
                "organizations.Organization",
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="employees",
            ),
        ),
        migrations.AddField(
            model_name="device",
            name="organization",
            field=models.ForeignKey(
                "organizations.Organization",
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="directory_devices",
            ),
        ),
        migrations.AddField(
            model_name="passwordreset",
            name="organization",
            field=models.ForeignKey(
                "organizations.Organization",
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="password_resets",
            ),
        ),
        migrations.RunPython(backfill_organization, drop_organization),
        migrations.AlterField(
            model_name="directorygroup",
            name="organization",
            field=models.ForeignKey(
                "organizations.Organization",
                on_delete=django.db.models.deletion.CASCADE,
                related_name="directory_groups",
            ),
        ),
        migrations.AlterField(
            model_name="employee",
            name="organization",
            field=models.ForeignKey(
                "organizations.Organization",
                on_delete=django.db.models.deletion.CASCADE,
                related_name="employees",
            ),
        ),
        migrations.AlterField(
            model_name="device",
            name="organization",
            field=models.ForeignKey(
                "organizations.Organization",
                on_delete=django.db.models.deletion.CASCADE,
                related_name="directory_devices",
            ),
        ),
        migrations.AlterField(
            model_name="passwordreset",
            name="organization",
            field=models.ForeignKey(
                "organizations.Organization",
                on_delete=django.db.models.deletion.CASCADE,
                related_name="password_resets",
            ),
        ),
    ]
