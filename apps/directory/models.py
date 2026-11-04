"""Directory domain: employees, devices and groups mirrored from AD (or faked).

The point of this app is to give the agent a realistic identity surface without
requiring a Windows domain to run the project. ``source`` records where a row came
from, so a fake tenant can never be mistaken for a real one in an audit.

Every row belongs to one ``Organization``. An identity surface is the most private
thing a company has, so a directory shared between workspaces would be worse than a
leak of tickets: two unrelated companies would each hold the other's complete staff
list, machine inventory and group membership. Identity names are therefore unique
*within* an organisation, not across the platform — ``sam``, ``hostname`` and group
``name`` are corporate-internal identifiers that collide between companies all the
time.
"""
from __future__ import annotations

import uuid

from django.db import models
from django.utils import timezone


class DirectoryGroup(models.Model):
    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="directory_groups"
    )
    name = models.CharField(max_length=150)
    distinguished_name = models.CharField(max_length=500, blank=True)
    is_privileged = models.BooleanField(
        default=False,
        help_text="Privileged groups are a hard deny: no approval can authorise them.",
    )

    class Meta:
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "name"],
                name="uniq_directory_group_name_per_organization",
            )
        ]

    def __str__(self) -> str:
        return self.name


class Employee(models.Model):
    class Source(models.TextChoices):
        FAKE = "fake", "Fake tenant"
        LDAP = "ldap", "LDAP"

    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="employees"
    )
    external_id = models.CharField(max_length=120)
    sam = models.CharField(max_length=64, help_text="sAMAccountName")
    upn = models.CharField(max_length=255, blank=True)
    display_name = models.CharField(max_length=150)
    email = models.EmailField(blank=True)
    department = models.CharField(max_length=120, blank=True)
    title = models.CharField(max_length=120, blank=True)

    manager = models.ForeignKey(
        "self", on_delete=models.SET_NULL, null=True, blank=True, related_name="reports"
    )
    groups = models.ManyToManyField(DirectoryGroup, blank=True, related_name="members")

    account_enabled = models.BooleanField(default=True)
    locked_out = models.BooleanField(default=False)
    bad_password_count = models.PositiveIntegerField(default=0)
    password_last_set = models.DateTimeField(null=True, blank=True)
    last_logon = models.DateTimeField(null=True, blank=True)

    source = models.CharField(max_length=10, choices=Source.choices, default=Source.FAKE)
    synced_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["sam"]
        indexes = [
            models.Index(fields=["organization", "sam"]),
            models.Index(fields=["locked_out"]),
        ]
        constraints = [
            # Both names are corporate-internal identifiers. Two companies can each
            # have a `j.smith`, and a platform-wide unique constraint would make the
            # second one's sync fail — which reads as a data problem rather than the
            # tenancy bug it is.
            models.UniqueConstraint(fields=["organization", "sam"], name="uniq_employee_sam_per_organization"),
            models.UniqueConstraint(
                fields=["organization", "external_id"], name="uniq_employee_external_id_per_organization"
            ),
        ]

    def __str__(self) -> str:
        return f"{self.sam} ({self.display_name})"


class Device(models.Model):
    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="directory_devices"
    )
    hostname = models.CharField(max_length=120)
    serial = models.CharField(max_length=120, blank=True)
    model = models.CharField(max_length=120, blank=True)
    os_build = models.CharField(max_length=120, blank=True)
    assigned_employee = models.ForeignKey(
        Employee, on_delete=models.SET_NULL, null=True, blank=True, related_name="devices"
    )
    last_seen = models.DateTimeField(null=True, blank=True)
    bitlocker_status = models.CharField(max_length=40, blank=True)
    free_disk_pct = models.FloatField(null=True, blank=True)

    class Meta:
        ordering = ["hostname"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "hostname"], name="uniq_device_hostname_per_organization"
            )
        ]

    def __str__(self) -> str:
        return self.hostname


class PasswordReset(models.Model):
    """A generated password held for the approver, never returned to the model.

    The agent sees only ``reference``. A human with the right role retrieves the
    secret once, before it expires — which keeps credentials out of the prompt, the
    step record and the audit row.

    The column holds **ciphertext**, not the password. Keeping it out of the prompt
    is only half the job; a database dump would otherwise hand over working
    credentials. See ``crypto.py``.

    ``organization`` is what makes retrieval safe. A reference is a random UUID, so it
    cannot be guessed — but it does get logged, and a holder of ``directory:read`` in
    one workspace who came across one from another would otherwise be handed a working
    corporate password. The reference itself stays globally unique: it is an opaque
    token, not a name two companies could both use.
    """

    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="password_resets"
    )
    reference = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    sam = models.CharField(max_length=64)
    password_ciphertext = models.TextField()
    force_change = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    retrieved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"PasswordReset {self.reference} for {self.sam}"

    def reveal_password(self) -> str:
        """Decrypt for the one authorised human who asks for it."""
        from .crypto import decrypt

        return decrypt(self.password_ciphertext)

    @property
    def is_expired(self) -> bool:
        return self.expires_at <= timezone.now()
