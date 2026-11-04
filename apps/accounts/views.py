"""Auth endpoints shaped for the web console's BFF.

The console does not talk to SimpleJWT directly. Its server-side BFF calls
``/auth/login/`` for tokens and ``/auth/me/`` for the session, and stores the
tokens in httpOnly cookies — so no token is ever readable from JavaScript.

``/auth/token/`` stays as-is for the CLI, the tests and anything else that wants
a plain SimpleJWT pair.
"""
from __future__ import annotations

from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from apps.common.capabilities import ROLE_CAPABILITIES
from apps.organizations.services import ensure_membership

from .models import CODE_LIFETIME, RESET_LIFETIME, VERIFICATION_LIFETIME, CustomUser
from .password_reset import (
    ResetError,
    check_password_strength,
    finalize_reset,
    issue_reset,
    revoke_sessions,
)
from .registration import (
    RegistrationError,
    finalize_registration,
    issue_code,
    verify_code,
)
from .sessions import live_sessions, revoke_session, serialize_session

# DeskPilot used to be one hardcoded workspace. Memberships are real now, so the
# session reports whatever the database says; accounts that predate tenancy are
# given a membership in the default organisation on first login.
WORKSPACE_NAME = "DeskPilot"


def _error(code: str, message: str, http_status: int) -> Response:
    return Response({"error": {"code": code, "message": message}}, status=http_status)


def serialize_user(user) -> dict:
    """The shape the console's `User` DTO expects.

    ``full_name`` and ``is_email_verified`` do not exist on ``CustomUser``: the
    display name is the closest thing to a full name, and there is no email
    verification flow, so it reports ``True`` rather than inventing a pending
    state the product cannot resolve.

    ``display_name`` is served alongside it, empty when unset. ``full_name`` falls
    back to the email so a header can always show something, but a form that
    prefilled from it would put an address in the name box and save it back as a
    name. ``password_updated_at`` is null for every account that predates the
    column — the console says "never recorded" rather than passing off
    ``date_joined`` as a change nobody made.
    """
    return {
        "id": str(user.pk),
        "email": user.email,
        "full_name": user.display_name or user.email,
        "display_name": user.display_name,
        "is_email_verified": True,
        "date_joined": user.date_joined.isoformat() if user.date_joined else None,
        "password_updated_at": (
            user.password_updated_at.isoformat() if user.password_updated_at else None
        ),
        "is_active": user.is_active,
    }


def serialize_membership(membership) -> dict:
    """One membership, in the shape the console's ``Membership`` DTO expects.

    ``role`` is the role **in that organisation**. The same person can hold a
    different one in another account, which is the whole reason this is a row and
    not a field on the user.
    """
    organization = membership.organization
    return {
        "organization_id": str(organization.pk),
        "organization_name": organization.name,
        "organization_slug": organization.slug,
        "role": membership.role,
        "department": (
            {"id": membership.department.pk, "name": membership.department.name}
            if membership.department_id
            else None
        ),
        "is_owner": membership.is_owner,
    }


class LoginView(APIView):
    """Email + password in, tokens and user out."""

    permission_classes = [AllowAny]
    authentication_classes: list = []

    def post(self, request):
        email = str((request.data or {}).get("email") or "").strip().lower()
        password = str((request.data or {}).get("password") or "")

        if not email or not password:
            return _error(
                "invalid_credentials",
                "Email and password are required.",
                status.HTTP_400_BAD_REQUEST,
            )

        user = authenticate(request, username=email, password=password)
        if user is None:
            # Django's ModelBackend refuses an inactive user, so it arrives here as
            # a plain failure. Re-check only to produce a useful message — and only
            # after the password matched, so learning that an account exists still
            # requires knowing its password. No enumeration oracle.
            candidate = CustomUser.objects.filter(email=email).first()
            if (
                candidate is not None
                and not candidate.is_active
                and candidate.check_password(password)
            ):
                return _error(
                    "account_inactive",
                    "This account has been deactivated.",
                    status.HTTP_403_FORBIDDEN,
                )
            # One message for both "no such account" and "wrong password": telling
            # them apart is a free account-enumeration oracle.
            return _error(
                "invalid_credentials",
                "That email and password do not match an account.",
                status.HTTP_401_UNAUTHORIZED,
            )

        refresh = RefreshToken.for_user(user)
        # Sign-in is the point where an account that predates tenancy (or was
        # created by a fixture) gets its place in an organisation. Doing it here
        # rather than on every request keeps the write off the read path.
        ensure_membership(user)
        return Response(
            {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "user": serialize_user(user),
            }
        )


class MeView(APIView):
    """The current session: who you are, and the organisations you may act in."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        memberships = list(
            request.user.memberships.select_related("organization", "department")
            .filter(is_active=True, organization__is_active=True)
            .exclude(user__is_superuser=True)
            .order_by("created_at")
        )
        # Belt and braces: a user with no membership cannot render the console at
        # all, and /auth/me/ is the first call it makes. A platform superuser is
        # the exception — they belong to no account by design, so this stays empty
        # and they are told so rather than being quietly given a tenant.
        if not memberships:
            provisioned = ensure_membership(request.user)
            if provisioned is not None:
                memberships = [provisioned]

        active = request.membership or (memberships[0] if memberships else None)
        return Response(
            {
                "user": serialize_user(request.user),
                "memberships": [serialize_membership(m) for m in memberships],
                "active_organization": serialize_membership(active) if active else None,
                # The role → capability map, served rather than duplicated. The
                # console used to keep its own table, and the two drifted — an
                # endpoint the table called administrator-only was open to anyone
                # signed in. Now the client renders what this server enforces; a
                # role it does not find here grants nothing.
                "role_capabilities": {
                    role: capabilities for role, capabilities in ROLE_CAPABILITIES.items()
                },
            }
        )

    def patch(self, request):
        """Change the name the console shows. Nothing else on this object is yours.

        Email is refused rather than silently ignored, and the refusal names the
        field: an account that quietly dropped ``email`` from a saved form would
        tell the person they now sign in with a different address than they do.
        Changing it is not a cosmetic edit either — it is the username, and reset
        links are mailed to it.
        """
        data = request.data or {}
        unchangeable = sorted(set(data) - {"display_name"})
        if unchangeable:
            return _error(
                "immutable_field",
                f"Cannot change: {', '.join(unchangeable)}. Your email address is your "
                "sign-in name and the address reset links are sent to, so it is not "
                "editable here.",
                status.HTTP_400_BAD_REQUEST,
            )
        if "display_name" not in data:
            return _error(
                "nothing_to_change", "Send a display_name.", status.HTTP_400_BAD_REQUEST
            )

        name = str(data.get("display_name") or "").strip()
        if len(name) > 150:
            # Same ceiling as the column, checked here so the answer is this
            # message and not a truncated save or a database error.
            return _error(
                "name_too_long", "Keep the display name under 150 characters.",
                status.HTTP_400_BAD_REQUEST,
            )

        request.user.display_name = name
        # Empty is a real answer — it means "no display name", and the console goes
        # back to showing the address. Nothing here decides it must be a full name.
        request.user.save(update_fields=["display_name"])
        return Response({"user": serialize_user(request.user)})


class LogoutView(APIView):
    """Revoke a refresh token server-side.

    Clearing a cookie only forgets the token on that one browser. Without this
    endpoint a stolen refresh token stays valid for its whole lifetime, because
    nothing on the server records that the session ended. Blacklisting is what
    makes "log out everywhere" and incident response possible at all.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        raw = str((request.data or {}).get("refresh") or "").strip()
        if raw:
            try:
                RefreshToken(raw).blacklist()
            except TokenError:
                # Already expired, already blacklisted, or simply not a refresh
                # token. None of those are worth failing the logout over: the
                # caller's intent is "end the session", and it is ending.
                pass
        return Response(status=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Self-service sign-up
# ---------------------------------------------------------------------------
#
# Three endpoints because the console's flow has three steps, and every one of
# them is unauthenticated — which is precisely why they are the surface this
# project has to be most careful about. None of them declares a capability: there
# is no role to check before an account exists, so ``tests/test_capabilities_matrix.py``
# lists them as public by name instead.
#
# Each step is scoped and rate-limited on its own (rates in
# ``REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]``): a code send costs mail credits,
# a verify is a guess-the-number game, and finishing mints an organisation — the
# slowest thing a stranger can ask this API for. ``ScopedRateThrottle`` keys an
# anonymous request on client IP, so one office behind a NAT shares a bucket; that
# is the trade a public signup page makes, and why the rates are env-overridable.
# Without ``REDIS_URL`` the cache is per-process, so the limit follows whichever
# worker served the request — the same caveat the kill switch documents.

# Codes that mean "your input is wrong" are 400; the two that mean "this collides
# with something that already exists" and the one that means "stop guessing" are not.
_REGISTRATION_STATUS = {
    "too_many_attempts": status.HTTP_429_TOO_MANY_REQUESTS,
    "email_taken": status.HTTP_409_CONFLICT,
    "organization_name_taken": status.HTTP_409_CONFLICT,
    # The caller did nothing wrong and retrying is the only fix, which is 503 —
    # a 400 here would teach the console to blame the email address they typed.
    "email_not_sent": status.HTTP_503_SERVICE_UNAVAILABLE,
}


def _registration_error(exc) -> Response:
    return _error(exc.code, exc.message, _REGISTRATION_STATUS.get(exc.code, status.HTTP_400_BAD_REQUEST))


class RegistrationCodeIssueView(APIView):
    """Step one: put a six-digit code on an address.

    Answers the same way whether the address is free or already registered — the
    code simply will not finish later. A page that says "this email is taken" on
    entry is an account-enumeration service, and ``LoginView`` already made the
    opposite trade for passwords; this is the same bargain.
    """

    permission_classes = [AllowAny]
    authentication_classes: list = []
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "register_issue"

    def post(self, request):
        try:
            issue_code((request.data or {}).get("email"))
        except RegistrationError as exc:
            return _registration_error(exc)

        # No code, no echo of the address, no hint about what was found. The
        # response is a receipt, and the code lives only in the email.
        return Response(
            {"sent": True, "expires_in": int(CODE_LIFETIME.total_seconds())},
            status=status.HTTP_202_ACCEPTED,
        )


class RegistrationCodeVerifyView(APIView):
    """Step two: check the code and trade it for a single-use token."""

    permission_classes = [AllowAny]
    authentication_classes: list = []
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "register_verify"

    def post(self, request):
        data = request.data or {}
        try:
            verification = verify_code(data.get("email"), data.get("code"))
        except RegistrationError as exc:
            return _registration_error(exc)

        return Response(
            {
                "verified": True,
                "verification": verification,
                "expires_in": int(VERIFICATION_LIFETIME.total_seconds()),
            }
        )


class RegisterView(APIView):
    """Step three: company name and password, and the account exists.

    Signed in on the way out. The password was just chosen by the person who owns
    the address, so making them type it again to arrive at their own workspace is
    a step nobody asked for — and the tokens are minted here rather than by a
    second call, so the console has one round trip per step.
    """

    permission_classes = [AllowAny]
    authentication_classes: list = []
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "register_finalize"

    def post(self, request):
        data = request.data or {}
        try:
            user, _organization, membership = finalize_registration(
                data.get("verification"),
                data.get("company_name"),
                data.get("password"),
            )
        except RegistrationError as exc:
            return _registration_error(exc)

        refresh = RefreshToken.for_user(user)
        return Response(
            {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "user": serialize_user(user),
                "organization": serialize_membership(membership),
            },
            status=status.HTTP_201_CREATED,
        )


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------
#
# ``/auth/login/`` already refuses to say whether an address exists, and this is
# the endpoint a stranger uses most: an email list from any breach, pasted one at
# a time into a form that mails the owners. So it answers identically for an
# account and a non-account, and the only thing that distinguishes them is whether
# somebody can open the mailbox.
#
# Both steps are public by name in ``tests/test_capabilities_matrix.py`` for the
# same reason the sign-up steps are — there is no role to authorise against before
# the token proves the address.

_RESET_STATUS = {
    "account_inactive": status.HTTP_403_FORBIDDEN,
}


class ForgotPasswordView(APIView):
    """Step one: mail a reset link to the address on an account, if there is one.

    Always the same 202. Not "we found it", not "not registered", and no
    difference in timing worth measuring — the lookup is one indexed query either
    way, and the send only happens on the path that has an account, which is why a
    failed send is logged rather than reported.
    """

    permission_classes = [AllowAny]
    authentication_classes: list = []
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "password_forgot"

    def post(self, request):
        issue_reset((request.data or {}).get("email"))

        return Response(
            {"sent": True, "expires_in": int(RESET_LIFETIME.total_seconds())},
            status=status.HTTP_202_ACCEPTED,
        )


class ResetPasswordView(APIView):
    """Step two: the link, the new password, and every old session ends.

    The response carries the account's email so the console can sign the person in
    with the password they just chose instead of sending them back to the login
    form to type it again — they proved the mailbox to get here.
    """

    permission_classes = [AllowAny]
    authentication_classes: list = []
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "password_reset"

    def post(self, request):
        data = request.data or {}
        try:
            user = finalize_reset(data.get("token"), data.get("password"))
        except ResetError as exc:
            return _error(
                exc.code,
                exc.message,
                _RESET_STATUS.get(exc.code, status.HTTP_400_BAD_REQUEST),
            )

        return Response({"done": True, "email": user.email})


# ---------------------------------------------------------------------------
# Self-service account and security
# ---------------------------------------------------------------------------
#
# These three are the part of "account settings" that a person owns rather than an
# administrator: the name on their profile, the password they sign in with, and the
# list of browsers holding a session. They declare no capability because there is
# no role to check against — every one of them acts on ``request.user`` and nothing
# else, so a technician and a requester get the same answers about their own
# account. ``tests/test_capabilities_matrix.py`` lists them by name instead, and the
# reachability is bounded by ``IsAuthenticated`` plus the tenancy the session itself
# was issued under.

# Typo room, no more — see the `password_change` rate in settings.
class ChangePasswordView(APIView):
    """Proof you know the current password, then every other sign-in ends.

    The person changing it gets a fresh pair of tokens back, which is what makes
    "revoke every other session" survivable in practice: this tab is handed a new
    credential after the old ones are burned, so it stays signed in while the
    laptop at home and the stranger's phone do not.

    Returning tokens here is also why the answer is not simply "done". A console
    that kept using the old refresh cookie would be bounced to the login screen by
    its own next request — a logout that looks like the password change failed.
    """

    permission_classes = [IsAuthenticated]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "password_change"

    def post(self, request):
        data = request.data or {}
        user = request.user
        current = str(data.get("current_password") or "")
        password = str(data.get("password") or "")

        if not current or not user.check_password(current):
            # 401, not 403: the session is fine but this act needs a credential the
            # caller did not supply. "Wrong password" is said plainly because the
            # person is already inside their own account — the enumeration concern
            # that governs /auth/login/ is about *finding* accounts, and that ship
            # has sailed.
            return _error(
                "invalid_credentials", "That is not your current password.",
                status.HTTP_401_UNAUTHORIZED,
            )

        try:
            check_password_strength(password, user)
        except ResetError as exc:
            return _error(exc.code, exc.message, status.HTTP_400_BAD_REQUEST)

        if password == current:
            # Refused before anything is written, because the alternative is
            # evicting every other device in exchange for no change at all.
            return _error(
                "password_unchanged",
                "The new password has to be different from the current one.",
                status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(password)
        user.save(update_fields=["password", "password_updated_at"])
        # Revoked before the replacement is minted, so the new refresh token is not
        # in the set this call just blacklisted.
        revoked = revoke_sessions(user)

        refresh = RefreshToken.for_user(user)
        return Response(
            {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "revoked_sessions": revoked,
                "user": serialize_user(user),
            }
        )


class SessionListView(APIView):
    """Every sign-in on this account that can still renew itself.

    Straight out of SimpleJWT's ledger — see ``apps/accounts/sessions.py`` for what
    that table knows and, more usefully, what it does not. There is no device name
    or address to show, so there is none in the response either.

    ``current_jti`` is a display hint, supplied by the caller's own server: the BFF
    decodes the refresh token in its httpOnly cookie and passes the id so this tab
    can be labelled "this device". It is not an authorisation — a wrong or missing
    value changes which row carries a label, and nothing a person can do to their
    own sessions.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        current_jti = str(request.query_params.get("current_jti") or "").strip() or None
        user = request.user
        return Response(
            {
                "sessions": [
                    serialize_session(row, current_jti) for row in live_sessions(user)
                ],
                # Belongs here rather than only on /auth/me/: the page that asks
                # "when did I last change this" is the one showing the sign-ins, and
                # a null here means the column predates the record — not "recently".
                "password_updated_at": (
                    user.password_updated_at.isoformat() if user.password_updated_at else None
                ),
            }
        )


class SessionRevokeView(APIView):
    """End one sign-in by id.

    No capability, no confirmation, no grace period: a person revoking their own
    session is the cheapest possible correct action, and the interesting failure is
    the one where the jti is not theirs. That answers 404 — indistinguishable from
    "never existed", so the endpoint cannot be used to probe which sessions other
    accounts hold.
    """

    permission_classes = [IsAuthenticated]

    def delete(self, request, jti: str):
        if not revoke_session(request.user, str(jti).strip()):
            return _error(
                "session_not_found",
                "No live sign-in with that id on your account.",
                status.HTTP_404_NOT_FOUND,
            )
        return Response(status=status.HTTP_204_NO_CONTENT)

