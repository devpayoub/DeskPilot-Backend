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

from .models import CustomUser

# DeskPilot is a single-workspace product. The console's session model is built
# around organisations, so it is handed one synthetic membership rather than
# having that whole layer rewritten. `role` is the real DeskPilot role.
WORKSPACE_ID = "deskpilot"
WORKSPACE_NAME = "DeskPilot"
WORKSPACE_SLUG = "deskpilot"


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


def serialize_membership(user) -> dict:
    return {
        "organization_id": WORKSPACE_ID,
        "organization_name": WORKSPACE_NAME,
        "organization_slug": WORKSPACE_SLUG,
        "role": user.role,
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
        return Response(
            {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "user": serialize_user(user),
            }
        )


class MeView(APIView):
    """The current session: who you are, and the workspace you are acting in."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(
            {
                "user": serialize_user(request.user),
                "memberships": [serialize_membership(request.user)],
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
