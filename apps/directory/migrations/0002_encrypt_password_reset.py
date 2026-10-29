"""Encrypt stored directory passwords.

`PasswordReset.password` held the generated credential in plaintext. Keeping it out
of the model's context was already solved; keeping it out of a database dump was
not. This migration swaps the column for ciphertext.

Three steps, in this order, so the migration is safe on a database that already has
rows (the development database has none, but a real one would):

1. add the new column, nullable;
2. encrypt every existing value into it;
3. make it non-null and drop the plaintext column.

Rows written by this migration cannot be decrypted if `VAULT_ENCRYPTION_KEY` (or
`SECRET_KEY`) later changes — which is acceptable for a 15-minute credential, and is
reported as `VaultDecryptionError` rather than silently returning an empty string.
"""
from __future__ import annotations

from django.db import migrations, models


def encrypt_existing(apps, schema_editor):
    PasswordReset = apps.get_model("directory", "PasswordReset")
    from apps.directory.crypto import encrypt

    for row in PasswordReset.objects.exclude(password="").iterator():
        row.password_ciphertext = encrypt(row.password)
        row.save(update_fields=["password_ciphertext"])


def decrypt_existing(apps, schema_editor):
    """Reverse: restore plaintext so the migration can be rolled back."""
    PasswordReset = apps.get_model("directory", "PasswordReset")
    from apps.directory.crypto import decrypt

    for row in PasswordReset.objects.exclude(password_ciphertext="").iterator():
        row.password = decrypt(row.password_ciphertext)
        row.save(update_fields=["password"])


class Migration(migrations.Migration):

    dependencies = [
        ("directory", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="passwordreset",
            name="password_ciphertext",
            field=models.TextField(default=""),
            preserve_default=False,
        ),
        migrations.RunPython(encrypt_existing, decrypt_existing),
        migrations.AlterField(
            model_name="passwordreset",
            name="password_ciphertext",
            field=models.TextField(),
        ),
        migrations.RemoveField(
            model_name="passwordreset",
            name="password",
        ),
    ]
