"""Tenancy operations.

Everything that changes *who may do what* lives here rather than in the views, so
the same rules apply whether the caller is the API, a management command or a
test. Two rules in particular are not negotiable and are enforced in one place
only:

* an organisation can never be left without an active administrator;
* nobody can grant a role above their own.

Both are the kind of guard that looks paranoid until the first time a client admin
deactivates themselves and locks the whole account out, with no platform-level
superadmin to rescue them.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.utils import timezone

from apps.accounts.models import ROLE_RANK, CustomUser, Role

from .models import (
    DEFAULT_ORGANIZATION_NAME,
    DEFAULT_ORGANIZATION_SLUG,
    Department,
    Membership,
    Organization,
)

INVITE_LIFETIME = timedelta(days=7)
MIN_PASSWORD_LENGTH = 8


class TenancyError(Exception):
    """A request the tenancy rules refuse, carrying a machine-readable code.

    Views translate this into the project's ``{"error": {"code", "message"}}``
    envelope. Raising a typed error rather than returning ``None`` keeps the rule
    impossible to ignore at the call site.
    """

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Organisation + membership bootstrap
# ---------------------------------------------------------------------------


def default_organization() -> Organization:
    """The organisation a single-workspace deployment runs as."""
    organization, _ = Organization.objects.get_or_create(
        slug=DEFAULT_ORGANIZATION_SLUG,
        defaults={"name": DEFAULT_ORGANIZATION_NAME},
    )
    return organization


def ensure_membership(user) -> Membership:
    """Give a user a membership, once, in the default organisation.

    Called at login and by ``/auth/me/``. Accounts that predate tenancy — and
    every account the test fixtures build — would otherwise be able to
    authenticate but belong nowhere, which the console renders as "not
    authorised" with no way out.
    """
    existing = (
        user.memberships.select_related("organization")
        .filter(is_active=True, organization__is_active=True)
        .order_by("created_at")
        .first()
    )
    if existing is not None:
        return existing

    organization = default_organization()
    with transaction.atomic():
        first_member = not Membership.objects.filter(organization=organization).exists()
        role = getattr(user, "role", "") or Role.REQUESTER
        membership, _ = Membership.objects.get_or_create(
            user=user,
            organization=organization,
            defaults={
                "role": role,
                "is_owner": first_member,
                "accepted_at": timezone.now(),
            },
        )
    return membership


def _sync_legacy_role(membership: Membership) -> None:
    """Keep ``CustomUser.role`` honest while it is still a fallback.

    Only when the user belongs to exactly one organisation. With two memberships a
    single global role would be a lie, and the console reads the real per-org role
    from the membership anyway.
    """
    user = membership.user
    if user.memberships.count() != 1:
        return
    if user.role != membership.role:
        user.role = membership.role
        user.save(update_fields=["role"])


# ---------------------------------------------------------------------------
# Departments
# ---------------------------------------------------------------------------


def create_department(
    organization: Organization,
    *,
    name: str,
    code: str = "",
    parent: Department | None = None,
) -> Department:
    name = (name or "").strip()
    if not name:
        raise TenancyError("invalid_name", "A department needs a name.")
    if len(name) > 120:
        raise TenancyError("invalid_name", "That name is too long (120 characters).")
    if Department.objects.filter(organization=organization, name__iexact=name).exists():
        raise TenancyError(
            "duplicate_department",
            f"'{name}' already exists in this organisation.",
        )
    if parent is not None and parent.organization_id != organization.pk:
        raise TenancyError(
            "cross_organization",
            "That parent department belongs to a different organisation.",
        )

    return Department.objects.create(
        organization=organization,
        name=name,
        code=(code or "").strip()[:32],
        parent=parent,
    )


def update_department(
    department: Department,
    *,
    name: str | None = None,
    code: str | None = None,
    parent: Department | None = None,
    is_active: bool | None = None,
) -> Department:
    if name is not None:
        name = name.strip()
        if not name:
            raise TenancyError("invalid_name", "A department needs a name.")
        clash = (
            Department.objects.filter(
                organization=department.organization, name__iexact=name
            )
            .exclude(pk=department.pk)
            .exists()
        )
        if clash:
            raise TenancyError(
                "duplicate_department",
                f"'{name}' already exists in this organisation.",
            )
        department.name = name

    if code is not None:
        department.code = code.strip()[:32]

    if parent is not None:
        if parent.pk == department.pk:
            raise TenancyError("invalid_parent", "A department cannot be its own parent.")
        if parent.organization_id != department.organization_id:
            raise TenancyError(
                "cross_organization",
                "That parent department belongs to a different organisation.",
            )
        # Walk up from the proposed parent: if we meet ourselves, it is a cycle.
        node, seen = parent, {department.pk}
        while node is not None:
            if node.pk in seen:
                raise TenancyError(
                    "invalid_parent", "That parent would create a cycle."
                )
            seen.add(node.pk)
            node = node.parent
        department.parent = parent

    if is_active is not None:
        department.is_active = is_active

    department.save()
    return department


def delete_department(department: Department, *, reassign_to: Department | None = None) -> None:
    """Delete a department, refusing to silently orphan its members.

    Deleting the row with members still attached would leave people "in a
    department" that no longer exists, and ``SET_NULL`` would quietly move them to
    no department at all. Neither is a decision a delete endpoint should make on
    the operator's behalf, so it asks.
    """
    members = department.members.filter(is_active=True)
    if members.exists():
        if reassign_to is None:
            raise TenancyError(
                "department_has_members",
                f"{members.count()} active member(s) still belong to this department. "
                "Move them first, or pass reassign_to.",
            )
        if reassign_to.pk == department.pk:
            raise TenancyError("invalid_reassign", "Cannot reassign to the department being deleted.")
        if reassign_to.organization_id != department.organization_id:
            raise TenancyError(
                "cross_organization", "The target department is in another organisation."
            )
        members.update(department=reassign_to)

    department.delete()


# ---------------------------------------------------------------------------
# Members
# ---------------------------------------------------------------------------


def _assert_can_assign(actor_role: str, role: str) -> None:
    if role not in ROLE_RANK:
        raise TenancyError("invalid_role", f"'{role}' is not a role.")
    if ROLE_RANK[role] > ROLE_RANK.get(actor_role, -1):
        raise TenancyError(
            "role_too_high",
            "You cannot grant a role above your own.",
        )


def _assert_not_last_admin(membership: Membership) -> None:
    """Refuse to remove the only way back into the account."""
    if membership.role != Role.ADMIN:
        return
    others = (
        Membership.objects.filter(
            organization=membership.organization, role=Role.ADMIN, is_active=True
        )
        .exclude(pk=membership.pk)
        .count()
    )
    if others == 0:
        raise TenancyError(
            "last_admin",
            "This is the only administrator of the account. Promote someone else first.",
        )


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------

# No l, I, 1, O or 0. A password an admin has to read aloud or retype over the
# phone should not contain characters that are ambiguous in a proportional font.
_PASSWORD_ALPHABET = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def generate_password(length: int = 16) -> str:
    return "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(length))


def _validate_password(password: str, user) -> None:
    """Apply Django's configured validators rather than inventing a second policy."""
    if not password:
        raise TenancyError("invalid_password", "A password is required.")
    try:
        validate_password(password, user)
    except DjangoValidationError as exc:
        raise TenancyError("weak_password", " ".join(exc.messages)) from exc


def create_member(
    organization: Organization,
    *,
    email: str,
    role: str = Role.REQUESTER,
    password: str | None = None,
    department: Department | None = None,
    actor_role: str = Role.ADMIN,
) -> tuple[Membership, str]:
    """Add a person who can sign in immediately, with a password.

    Unlike an invitation, this is a working credential from the moment it returns:
    the account is created active with a usable password, and the membership is
    already accepted. The password is generated when the caller does not supply
    one, and either way it is returned exactly once — only its hash is stored.

    An administrator setting someone's first password is normal in an IT helpdesk
    (the desk already resets passwords as a tool). What matters is that the choice
    is explicit, validated, and never silently left blank.
    """
    email = (email or "").strip().lower()
    if "@" not in email or email.startswith("@") or email.endswith("@"):
        raise TenancyError("invalid_email", "A valid email address is required.")
    _assert_can_assign(actor_role, role)

    if department is not None and department.organization_id != organization.pk:
        raise TenancyError(
            "cross_organization", "That department belongs to a different organisation."
        )

    if Membership.objects.filter(organization=organization, user__email=email).exists():
        raise TenancyError(
            "already_a_member", f"{email} is already a member of this organisation."
        )

    with transaction.atomic():
        user = CustomUser.objects.filter(email=email).first()
        if user is None:
            user = CustomUser(
                email=email,
                display_name=email.split("@")[0].replace(".", " ").title(),
                role=role,
            )
            user.set_unusable_password()
            user.save()

        chosen = password or generate_password()
        _validate_password(chosen, user)

        user.set_password(chosen)
        # An account that already existed but was switched off is being given a new
        # credential on purpose, so it comes back on with it.
        user.is_active = True
        user.save(update_fields=["password", "is_active"])

        membership = Membership.objects.create(
            user=user,
            organization=organization,
            role=role,
            department=department,
            accepted_at=timezone.now(),
        )
        _sync_legacy_role(membership)

    return membership, chosen


def set_member_password(
    membership: Membership,
    *,
    password: str | None = None,
    actor_role: str = Role.ADMIN,
) -> str:
    """Set or reset a member's password, and hand it back once.

    This is the account's "forgot password" path. There is no mail transport, so
    without it a member who forgets their password has no way back in except a
    shell on the server — which is not something a client administrator should
    need.
    """
    chosen = password or generate_password()
    _validate_password(chosen, membership.user)

    with transaction.atomic():
        user = membership.user
        user.set_password(chosen)
        # Deliberately not touching ``is_active``: resetting a password must not
        # quietly undo a suspension an administrator made for a reason.
        user.save(update_fields=["password"])

        if membership.accepted_at is None:
            # A pending invitation is satisfied by a real password; the token is
            # dead from here so it cannot be replayed.
            membership.accepted_at = timezone.now()
            membership.invite_token_hash = ""
            membership.invite_expires_at = None
            membership.save(
                update_fields=[
                    "accepted_at",
                    "invite_token_hash",
                    "invite_expires_at",
                    "updated_at",
                ]
            )

    return chosen


def invite_member(
    organization: Organization,
    *,
    email: str,
    role: str = Role.REQUESTER,
    department: Department | None = None,
    actor_role: str = Role.ADMIN,
) -> tuple[Membership, str]:
    """Add a person to the organisation and hand back a one-time invite token.

    The account is created with an unusable password, so an invitation is not a
    login: the person has to accept it and choose their own password. Returning the
    raw token rather than emailing it is a deliberate limitation — there is no mail
    transport in this project, and pretending otherwise would mean an invitation
    nobody can ever accept.
    """
    email = (email or "").strip().lower()
    if "@" not in email or email.startswith("@") or email.endswith("@"):
        raise TenancyError("invalid_email", "A valid email address is required.")
    _assert_can_assign(actor_role, role)

    if department is not None and department.organization_id != organization.pk:
        raise TenancyError(
            "cross_organization", "That department belongs to a different organisation."
        )

    if Membership.objects.filter(organization=organization, user__email=email).exists():
        raise TenancyError(
            "already_a_member", f"{email} is already a member of this organisation."
        )

    with transaction.atomic():
        user = CustomUser.objects.filter(email=email).first()
        if user is None:
            user = CustomUser(
                email=email,
                display_name=email.split("@")[0].replace(".", " ").title(),
                role=role,
            )
            user.set_unusable_password()
            user.save()

        token = secrets.token_urlsafe(32)
        membership = Membership.objects.create(
            user=user,
            organization=organization,
            role=role,
            department=department,
            invite_token_hash=_hash(token),
            invite_expires_at=timezone.now() + INVITE_LIFETIME,
            invited_at=timezone.now(),
        )
        _sync_legacy_role(membership)

    return membership, token


def accept_invite(raw_token: str, password: str) -> Membership:
    """Turn an invitation into a usable login."""
    if not raw_token:
        raise TenancyError("invalid_invite", "An invitation token is required.")
    if len(password or "") < MIN_PASSWORD_LENGTH:
        raise TenancyError(
            "weak_password", f"Choose a password of at least {MIN_PASSWORD_LENGTH} characters."
        )

    membership = (
        Membership.objects.select_related("user", "organization")
        .filter(invite_token_hash=_hash(raw_token))
        .first()
    )
    if membership is None or membership.accepted_at is not None:
        raise TenancyError("invalid_invite", "That invitation is not valid.")
    if membership.invite_expires_at and membership.invite_expires_at <= timezone.now():
        raise TenancyError("invite_expired", "That invitation has expired. Ask for a new one.")

    with transaction.atomic():
        user = membership.user
        user.set_password(password)
        user.save(update_fields=["password"])

        membership.accepted_at = timezone.now()
        # Single use: clearing the hash makes a replay a plain "not valid".
        membership.invite_token_hash = ""
        membership.invite_expires_at = None
        membership.save(
            update_fields=[
                "accepted_at",
                "invite_token_hash",
                "invite_expires_at",
                "updated_at",
            ]
        )
    return membership


def update_member(
    membership: Membership,
    *,
    role: str | None = None,
    department: Department | None = None,
    clear_department: bool = False,
    is_active: bool | None = None,
    actor_role: str = Role.ADMIN,
) -> Membership:
    if role is not None and role != membership.role:
        _assert_can_assign(actor_role, role)
        # Demoting the last admin is the same lockout as deactivating them.
        if membership.role == Role.ADMIN:
            _assert_not_last_admin(membership)
        membership.role = role

    if clear_department:
        membership.department = None
    elif department is not None:
        if department.organization_id != membership.organization_id:
            raise TenancyError(
                "cross_organization",
                "That department belongs to a different organisation.",
            )
        membership.department = department

    if is_active is not None and is_active != membership.is_active:
        if not is_active:
            if membership.is_owner:
                raise TenancyError(
                    "cannot_disable_owner",
                    "The owner of the account cannot be deactivated.",
                )
            _assert_not_last_admin(membership)
        membership.is_active = is_active

    membership.save()
    _sync_legacy_role(membership)
    return membership
