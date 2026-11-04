"""Custom user with an email login and an explicit role ladder.

The ladder is the single source of truth the guardrails authorise against: a tool
declares ``allowed_roles`` and the chokepoint compares ranks. Ordering is the real
IT support hierarchy (L1 desk < L2 technician < admin), not alphabetical.
"""
from __future__ import annotations

from datetime import timedelta

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
    # Null until a password is written by code that knows to stamp it. Rows created
    # before this column existed are honestly "unknown", not backfilled to the join
    # date — telling someone their password is three weeks old because their account
    # is would be a guess dressed up as a fact.
    password_updated_at = models.DateTimeField(null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS: list[str] = []

    class Meta:
        ordering = ["email"]
        indexes = [models.Index(fields=["role"])]

    def __str__(self) -> str:
        return self.email

    def set_password(self, raw_password):
        """Stamp when the credential changed, at the one place every change passes.

        Overriding this rather than remembering to write the column in each view is
        the point: sign-up, invitation accept, an administrator setting a member's
        password, self-service and reset all reach the hash through here, so a path
        added tomorrow cannot forget to record itself.
        """
        super().set_password(raw_password)
        self.password_updated_at = timezone.now()

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


# ---------------------------------------------------------------------------
# Self-service sign-up
# ---------------------------------------------------------------------------

CODE_LIFETIME = timedelta(minutes=10)
VERIFICATION_LIFETIME = timedelta(minutes=15)
# A six-digit code gets five guesses, then the row is dead and a new code has to
# be requested. Without a cap the endpoint is a lottery: 10^6 combinations at the
# default anonymous throttle is a few hours of work.
MAX_CODE_ATTEMPTS = 5


class RegistrationCode(models.Model):
    """One address waiting to prove it receives mail, during sign-up.

    The code is stored with Django's **password** hashers, not a plain digest. A
    bare SHA-256 of a six-digit number is reversed offline by trying a million
    inputs, so a leaked row would be a leaked code — the same column on an invite
    token is safe only because that token carries 256 bits of entropy. This one
    carries twenty.

    Row lifetime is short and the table is expected to stay small; expired rows
    are deleted when a new code is issued rather than by a scheduled job.
    """

    email = models.EmailField(db_index=True)
    code_hash = models.CharField(max_length=255)
    # Issued when the code is correct and spent at the final step, so the password
    # and the company name are submitted without sending the code a second time.
    # High-entropy, so a digest is enough here.
    verification_hash = models.CharField(max_length=64, blank=True, db_index=True)
    attempts = models.PositiveSmallIntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"sign-up code for {self.email}"

    @property
    def is_live(self) -> bool:
        return (
            self.consumed_at is None
            and self.expires_at > timezone.now()
            and self.attempts < MAX_CODE_ATTEMPTS
        )

    @property
    def verification_is_live(self) -> bool:
        return bool(self.verification_hash) and self.consumed_at is None


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------

RESET_LIFETIME = timedelta(minutes=30)


class PasswordResetToken(models.Model):
    """One emailed link that lets a person take back their own account.

    The link carries ``secrets.token_urlsafe(32)`` — 256 bits — so a SHA-256
    digest is the right thing to store, unlike the six-digit sign-up code above,
    where the input itself is guessable and only a password hasher helps. A leaked
    table therefore leaks no working link.

    Rows outlive the session they were used to end: a reset is a security event
    and the audit question ("when did this address ask for one?") is answered by
    the rows that were spent, so ``consumed_at`` is a stamp rather than a delete.
    """

    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name="password_reset_tokens"
    )
    token_hash = models.CharField(max_length=64, db_index=True)
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["user", "-created_at"])]

    def __str__(self) -> str:
        return f"password reset for {self.user_id}"

    @property
    def is_live(self) -> bool:
        return self.consumed_at is None and self.expires_at > timezone.now()
