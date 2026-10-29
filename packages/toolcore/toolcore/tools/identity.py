"""Identity tools — the account side of the helpdesk.

Group membership is split into ``add_group_member`` / ``remove_group_member`` rather
than one tool with a dynamic risk class. That is deliberate: risk is then a property
of the code the reviewer can read, not of an argument the model chose. A single
``group_membership(action=...)`` tool would make the risk depend on model output,
which is exactly the pattern this project exists to avoid.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .. import registry
from ..adapters.directory import ensure_not_privileged
from ..base import Tool, ToolContext
from ..risk import READ, WRITE_DESTRUCTIVE, WRITE_REVERSIBLE

_STAFF = frozenset({"SERVICE_DESK", "TECHNICIAN", "ADMIN"})
_TECHNICIAN = frozenset({"TECHNICIAN", "ADMIN"})

_SAM = r"^[A-Za-z0-9._-]+$"


class LookupUserArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(
        min_length=2,
        max_length=120,
        description="sAMAccountName, email address, or display name.",
    )


class GroupMembershipArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    group: str | None = Field(default=None, max_length=150, description="Group name.")
    sam: str | None = Field(
        default=None, max_length=64, description="User's sAMAccountName, to list their groups."
    )


class UnlockAccountArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sam: str = Field(min_length=1, max_length=64, pattern=_SAM, description="User to unlock.")


class ResetPasswordArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sam: str = Field(min_length=1, max_length=64, pattern=_SAM, description="User to reset.")
    force_change: bool = Field(
        default=True, description="Require a password change at next sign-in."
    )


class GroupMemberChangeArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    group: str = Field(min_length=1, max_length=150, description="Group name.")
    sam: str = Field(min_length=1, max_length=64, pattern=_SAM, description="User to change.")


def _lookup_user(ctx: ToolContext, args: dict) -> dict:
    found = ctx.adapter("directory").lookup_user(args["query"])
    return {"found": found is not None, "user": found}


def _get_group_membership(ctx: ToolContext, args: dict) -> dict:
    return ctx.adapter("directory").get_group_membership(args["group"], args["sam"])


def _unlock_account(ctx: ToolContext, args: dict) -> dict:
    return ctx.adapter("directory").unlock_account(args["sam"], dry_run=ctx.dry_run)


def _reset_password(ctx: ToolContext, args: dict) -> dict:
    result = ctx.adapter("directory").reset_password(
        args["sam"], args["force_change"], dry_run=ctx.dry_run
    )
    if ctx.dry_run or "password" not in result:
        return result

    # The generated secret is stored by the host and replaced with a reference. It
    # must never reach the model, the step record, or the audit row.
    secret = result.pop("password")
    reference = ctx.password_sink(args["sam"], secret, args["force_change"])
    result["password_reference"] = reference
    result["delivery"] = (
        "The new password is held for an operator. Retrieve it with "
        f"GET /api/v1/directory/password-resets/{reference}/ before it expires."
    )
    return result


def _add_group_member(ctx: ToolContext, args: dict) -> dict:
    ensure_not_privileged(args["group"])
    return ctx.adapter("directory").add_group_member(
        args["group"], args["sam"], dry_run=ctx.dry_run
    )


def _remove_group_member(ctx: ToolContext, args: dict) -> dict:
    ensure_not_privileged(args["group"])
    return ctx.adapter("directory").remove_group_member(
        args["group"], args["sam"], dry_run=ctx.dry_run
    )


IDENTITY_TOOLS: tuple[Tool, ...] = (
    Tool(
        name="lookup_user",
        description=(
            "Look up a directory account by sAMAccountName, email or display name. "
            "Returns lockout state, bad-password count, last logon, group membership "
            "and assigned devices. Use this before proposing any account change."
        ),
        handler=_lookup_user,
        input_model=LookupUserArgs,
        risk_class=READ,
        allowed_roles=_STAFF,
        domain="identity",
    ),
    Tool(
        name="get_group_membership",
        description=(
            "List the members of a group, or the groups a user belongs to. Pass "
            "'group' or 'sam', not both."
        ),
        handler=_get_group_membership,
        input_model=GroupMembershipArgs,
        risk_class=READ,
        allowed_roles=_STAFF,
        domain="identity",
    ),
    Tool(
        name="unlock_account",
        description=(
            "Clear an account lockout caused by repeated bad passwords. Reversible and "
            "does not change the password. Use when a user reports being locked out "
            "after a password change or a stale cached credential."
        ),
        handler=_unlock_account,
        input_model=UnlockAccountArgs,
        risk_class=WRITE_REVERSIBLE,
        dry_run_supported=True,
        allowed_roles=_STAFF,
        domain="identity",
    ),
    Tool(
        name="reset_password",
        description=(
            "Set a new password for an account. The new password is NOT returned to "
            "you — it is held for an operator to retrieve. Use only when a user cannot "
            "sign in and unlocking is not the issue."
        ),
        handler=_reset_password,
        input_model=ResetPasswordArgs,
        risk_class=WRITE_DESTRUCTIVE,
        dry_run_supported=True,
        allowed_roles=_TECHNICIAN,
        domain="identity",
    ),
    Tool(
        name="add_group_member",
        description=(
            "Add a user to a group. Privileged groups (Domain Admins, Administrators, "
            "and similar) are refused outright and cannot be approved."
        ),
        handler=_add_group_member,
        input_model=GroupMemberChangeArgs,
        risk_class=WRITE_REVERSIBLE,
        dry_run_supported=True,
        guard=lambda args: ensure_not_privileged(args["group"]),
        allowed_roles=_TECHNICIAN,
        domain="identity",
    ),
    Tool(
        name="remove_group_member",
        description=(
            "Remove a user from a group. Removing the wrong group can revoke access the "
            "user needs, so check membership first. Privileged groups are refused."
        ),
        handler=_remove_group_member,
        input_model=GroupMemberChangeArgs,
        risk_class=WRITE_DESTRUCTIVE,
        dry_run_supported=True,
        guard=lambda args: ensure_not_privileged(args["group"]),
        allowed_roles=_TECHNICIAN,
        domain="identity",
    ),
)


def register_identity_tools() -> None:
    for tool in IDENTITY_TOOLS:
        registry.register_if_absent(tool)
