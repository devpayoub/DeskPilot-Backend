from __future__ import annotations

from apps.accounts.models import CustomUser, Role

PASSWORD = "DeskPilot!2026"


def make_user(email: str, role: str = Role.REQUESTER, password: str = PASSWORD, **extra) -> CustomUser:
    extra.setdefault("display_name", email.split("@")[0].title())
    return CustomUser.objects.create_user(email=email, password=password, role=role, **extra)
