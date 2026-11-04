"""Move uniqueness inside the organisation.

Follows ``0003_directory_tenancy`` rather than riding along with it, because the two
halves have to happen in that order: a per-tenant ``UniqueConstraint`` cannot be added
while the global ``unique=True`` is still on the column, and dropping the global one
first would leave a window where a duplicate ``sam`` could be written. Every row
already belongs to an organisation by now, so the composite constraints are being
added to data that already satisfies them.

The ``sam`` index goes from a single column to ``(organization, sam)``: every lookup
in ``DatabaseDirectory`` is now qualified by tenant, and an index on ``sam`` alone
would be used by none of them.
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("directory", "0003_directory_tenancy"),
        ("organizations", "0003_purge_platform_admin_memberships"),
    ]

    operations = [
        migrations.RemoveIndex(
            model_name="employee",
            name="directory_e_sam_3ed028_idx",
        ),
        migrations.AlterField(
            model_name="device",
            name="hostname",
            field=models.CharField(max_length=120),
        ),
        migrations.AlterField(
            model_name="directorygroup",
            name="name",
            field=models.CharField(max_length=150),
        ),
        migrations.AlterField(
            model_name="employee",
            name="external_id",
            field=models.CharField(max_length=120),
        ),
        migrations.AlterField(
            model_name="employee",
            name="sam",
            field=models.CharField(help_text="sAMAccountName", max_length=64),
        ),
        migrations.AddIndex(
            model_name="employee",
            index=models.Index(fields=["organization", "sam"], name="directory_e_organiz_0793ae_idx"),
        ),
        migrations.AddConstraint(
            model_name="device",
            constraint=models.UniqueConstraint(
                fields=("organization", "hostname"), name="uniq_device_hostname_per_organization"
            ),
        ),
        migrations.AddConstraint(
            model_name="directorygroup",
            constraint=models.UniqueConstraint(
                fields=("organization", "name"), name="uniq_directory_group_name_per_organization"
            ),
        ),
        migrations.AddConstraint(
            model_name="employee",
            constraint=models.UniqueConstraint(
                fields=("organization", "sam"), name="uniq_employee_sam_per_organization"
            ),
        ),
        migrations.AddConstraint(
            model_name="employee",
            constraint=models.UniqueConstraint(
                fields=("organization", "external_id"), name="uniq_employee_external_id_per_organization"
            ),
        ),
    ]
