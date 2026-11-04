"""Record when an account's credential last changed.

Nullable on purpose. Backfilling it from ``date_joined`` would give every seeded and
pre-existing account a confident-looking answer that nobody observed, and the whole
value of a "last changed" timestamp is that a person can act on it. Rows written
before this column existed stay null and the console says so.
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0003_passwordresettoken"),
    ]

    operations = [
        migrations.AddField(
            model_name="customuser",
            name="password_updated_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
