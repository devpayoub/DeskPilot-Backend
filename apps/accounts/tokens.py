"""Keeping SimpleJWT's session ledger honest across a token rotation.

The blacklist app records an ``OutstandingToken`` row when a refresh token is
*issued* — ``RefreshToken.for_user`` does it. It does not record the one handed
back by a rotation. With ``ROTATE_REFRESH_TOKENS`` on, which this project has on
because a refresh token must be single-use, that gap is not cosmetic:

* a browser that has refreshed once — which is every browser, fifteen minutes
  after sign-in — holds a live refresh token that is in no ledger, so it does not
  appear on the security page; and
* ``revoke_sessions()`` blacklists what the ledger knows, so a password reset or
  change would leave exactly that attacker's session alive, while the console says
  every other sign-in ended.

Storing the rotated row is the fix, and it belongs here rather than in a custom
view because ``/auth/refresh/`` is SimpleJWT's own ``TokenRefreshView``; overriding
its serializer is the documented seam, and one setting keeps every caller — the
console's BFF and anything that posts a refresh directly — on the ledgered path.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
from rest_framework_simplejwt.utils import datetime_from_epoch


class LedgerRefreshTokenSerializer(TokenRefreshSerializer):
    """Rotate the refresh token, then write the new one into the ledger.

    ``super().validate`` blacklists the token it was given and mints the
    replacement, so by the time this runs there is exactly one live session per
    browser — the row added here, the old row already ended.
    """

    def validate(self, attrs):
        data = super().validate(attrs)

        rotated = data.get("refresh")
        if rotated:
            token = self.token_class(rotated)
            # Read from the claims, not the request: this endpoint has no session, and
            # the account can be gone by the time a token is renewed — which is why the
            # column is nullable. A row with no user lists on nobody's page.
            user = get_user_model().objects.filter(
                **{api_settings.USER_ID_FIELD: token[api_settings.USER_ID_CLAIM]}
            ).first()
            OutstandingToken.objects.get_or_create(
                jti=token[api_settings.JTI_CLAIM],
                defaults={
                    "user": user,
                    "token": str(token),
                    "created_at": token.current_time,
                    "expires_at": datetime_from_epoch(token["exp"]),
                },
            )
        return data
