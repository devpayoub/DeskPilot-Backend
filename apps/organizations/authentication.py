"""JWT authentication that also resolves the tenant.

Subclassing rather than wrapping keeps every other property of SimpleJWT —
rotation, blacklist, the ``Bearer`` header — exactly as configured. The only added
behaviour is that a verified token also answers "which organisation?".
"""
from __future__ import annotations

from rest_framework_simplejwt.authentication import JWTAuthentication

from .context import resolve_tenant


class TenantJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        result = super().authenticate(request)
        if result is None:
            return None

        user, _token = result
        # DRF assigns ``request.user`` after this method returns. Tenant
        # resolution needs it now, so it is set early — the setter only stores the
        # value, it does not re-authenticate.
        request.user = user
        resolve_tenant(request)
        return result
