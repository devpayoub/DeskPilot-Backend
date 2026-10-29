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
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.services import ensure_membership

from .models import CustomUser

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
    """
    return {
        "id": str(user.pk),
        "email": user.email,
        "full_name": user.display_name or user.email,
        "is_email_verified": True,
        "date_joined": user.date_joined.isoformat() if user.date_joined else None,
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
            .order_by("created_at")
        )
        # Belt and braces: a user with no membership cannot render the console at
        # all, and /auth/me/ is the first call it makes.
        if not memberships:
            memberships = [ensure_membership(request.user)]

        active = request.membership or memberships[0]
        return Response(
            {
                "user": serialize_user(request.user),
                "memberships": [serialize_membership(m) for m in memberships],
                "active_organization": serialize_membership(active),
            }
        )


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
