"""The tenancy layer: organisations, memberships and operator departments.

Before this app, DeskPilot was single-workspace. ``CustomUser.role`` was one
global field and the "workspace" the console saw was a hardcoded string, so
"administrator of *this* account" was not expressible — one user could hold
exactly one role for the whole installation.

The shape here is the ordinary one:

    Organization 1 ── N Department
    Organization 1 ── N Membership N ── 1 CustomUser
    Membership   ── 0..1 Department

A **department** is an operator-side org unit — L1 desk, field technicians,
security — used to group the humans who work tickets. It is *not* an entry in
the customer's AD directory: ``directory.Employee.department`` stays free text
mirrored from LDAP, and the two are deliberately never conflated. One is who
works here; the other is who we support.

``Membership.role`` is authoritative. ``CustomUser.role`` survives as the
single-workspace fallback for accounts with no membership (management commands,
the test fixtures, a deployment that never turned tenancy on), which is why the
role ladder stays defined exactly once in ``apps.accounts.models``.
"""
from __future__ import annotations

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from apps.accounts.models import ROLE_RANK, Role

DEFAULT_ORGANIZATION_SLUG = "deskpilot"
DEFAULT_ORGANIZATION_NAME = "DeskPilot"


class Organization(models.Model):
    """A customer account. Everything a member can see hangs off one of these."""

    name = models.CharField(max_length=150)
    # Stable, human-readable handle. It is what a client sends in
    # ``X-Organization`` when a person belongs to more than one account.
    slug = models.SlugField(max_length=80, unique=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class Department(models.Model):
    """An operator org unit inside one organisation.

    Self-referential ``parent`` allows a tree (Support → L1 / L2) without a second
    table. ``clean()`` refuses cycles and cross-organisation parents; the service
    layer is what enforces it on the API path, because Django does not call
    ``full_clean()`` from ``save()``.
    """

    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="departments"
    )
    name = models.CharField(max_length=120)
    code = models.CharField(
        max_length=32, blank=True, help_text="Short handle, e.g. L1 or FLD."
    )
    parent = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="children",
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "name"],
                name="uniq_department_name_per_organization",
            )
        ]
        indexes = [models.Index(fields=["organization", "is_active"])]

    def __str__(self) -> str:
        return f"{self.name} ({self.organization.slug})"

    def clean(self) -> None:
        if self.parent_id is None:
            return
        if self.pk is not None and self.parent_id == self.pk:
            raise ValidationError({"parent": "A department cannot be its own parent."})
        if self.parent.organization_id != self.organization_id:
            raise ValidationError(
                {"parent": "The parent department must belong to the same organisation."}
            )

        seen = {self.pk} if self.pk is not None else set()
        node = self.parent
        while node is not None:
            if node.pk in seen:
                raise ValidationError({"parent": "That parent would create a cycle."})
            seen.add(node.pk)
            node = node.parent


class Membership(models.Model):
    """One person's place in one organisation.

    This is where a role lives now. The unique constraint is the whole point of
    the table: the same human can be an ADMIN of their own account and a
    REQUESTER in a customer's account, without either role leaking into the
    other.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="memberships"
    )
    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="memberships"
    )
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.REQUESTER)
    department = models.ForeignKey(
        Department,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="members",
        help_text="Optional operator department. Must belong to the same organisation.",
    )
    # The first membership in an organisation is its owner: the account cannot be
    # left without at least one person who can administer it.
    is_owner = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    # Invitation. Only the hash is stored — a leaked database row must not be a
    # working invitation link, for the same reason passwords are not stored.
    invite_token_hash = models.CharField(max_length=64, blank=True, db_index=True)
    invite_expires_at = models.DateTimeField(null=True, blank=True)
    invited_at = models.DateTimeField(null=True, blank=True)
    accepted_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["organization", "user__email"]
        constraints = [
            models.UniqueConstraint(
                fields=["user", "organization"],
                name="uniq_membership_user_per_organization",
            )
        ]
        indexes = [
            models.Index(fields=["organization", "role"]),
            models.Index(fields=["organization", "is_active"]),
        ]

    def __str__(self) -> str:
        return f"{self.user_id} @ {self.organization.slug} ({self.role})"

    @property
    def role_rank(self) -> int:
        return ROLE_RANK.get(self.role, -1)

    @property
    def is_pending_invite(self) -> bool:
        return bool(self.invite_token_hash) and self.accepted_at is None

    @property
    def status(self) -> str:
        if self.is_pending_invite:
            return "invited"
        return "active" if self.is_active else "disabled"

    def clean(self) -> None:
        if self.department_id is None:
            return
        if self.department.organization_id != self.organization_id:
            raise ValidationError(
                {"department": "That department belongs to a different organisation."}
            )
