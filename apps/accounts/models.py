"""Custom user with an email login and an explicit role ladder.

The ladder is the single source of truth the guardrails authorise against: a tool
declares ``allowed_roles`` and the chokepoint compares ranks. Ordering is the real
IT support hierarchy (L1 desk < L2 technician < admin), not alphabetical.
"""
from __future__ import annotations

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone


class Role(models.TextChoices):
    ADMIN = "ADMIN", "Administrator"
    SERVICE_DESK = "SERVICE_DESK", "Service desk"
    TECHNICIAN = "TECHNICIAN", "Technician"
    REQUESTER = "REQUESTER", "Requester"


ROLE_RANK: dict[str, int] = {
    Role.REQUESTER: 0,
    Role.SERVICE_DESK: 10,
    Role.TECHNICIAN: 20,
    Role.ADMIN: 30,
}


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email: str, password: str | None, **extra):
        if not email:
            raise ValueError("Users must have an email address.")
        email = self.normalize_email(email).lower()
        user = self.model(email=email, **extra)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email: str, password: str | None = None, **extra):
        extra.setdefault("role", Role.REQUESTER)
        extra.setdefault("is_active", True)
        return self._create_user(email, password, **extra)

    def create_superuser(self, email: str, password: str | None = None, **extra):
        extra.setdefault("role", Role.ADMIN)
        extra.setdefault("is_staff", True)
        extra.setdefault("is_superuser", True)
        extra.setdefault("is_active", True)
        if extra.get("is_staff") is not True or extra.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_staff=True and is_superuser=True.")
        return self._create_user(email, password, **extra)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    display_name = models.CharField(max_length=150, blank=True)
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.REQUESTER)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS: list[str] = []

    class Meta:
        ordering = ["email"]
        indexes = [models.Index(fields=["role"])]

    def __str__(self) -> str:
        return self.email

    @property
    def role_rank(self) -> int:
        return ROLE_RANK.get(self.role, -1)

    def has_role_at_least(self, role: str) -> bool:
        return self.role_rank >= ROLE_RANK[role]


def effective_role(user) -> str:
    """The role to authorise against.

    Once tenancy is in play a person's role is a property of *which organisation
    they are acting in*, not of the person. ``TenantJWTAuthentication`` sets
    ``user.active_role`` from the resolved membership; when no tenant was resolved
    — a management command, a fixture, a single-workspace deployment — the field on
    ``CustomUser`` is still the answer.

    Kept as a free function rather than a ``CustomUser`` property because Django
    fields cannot be shadowed by a property of the same name, and every existing
    call site reads ``user.role``.
    """
    if user is None:
        return ""
    return getattr(user, "active_role", None) or getattr(user, "role", "") or ""
