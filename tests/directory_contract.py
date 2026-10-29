"""Behaviour both directory backends must share.

Written as a mixin so the *same assertions* run against the database-backed fake
tenant and against a real LDAP server. A subclass supplies a ``directory`` fixture
and guarantees this fixture data exists:

    user  sam=j.doe  display_name="Jane Doe"  email=j.doe@deskpilot.test
    group "VPN Users"      containing j.doe
    group "Domain Admins"  (privileged)

``unlock_account`` is deliberately absent: AD lockout state has no OpenLDAP
equivalent without the ppolicy overlay, so that behaviour is backend-specific and
tested separately rather than faked into the contract.
"""
from __future__ import annotations

import pytest

from toolcore.errors import ToolDenied, ToolExecutionError

SAM = "j.doe"
GROUP = "VPN Users"
PRIVILEGED_GROUP = "Domain Admins"


class DirectoryContract:
    # -- reads --------------------------------------------------------------
    def test_lookup_by_sam(self, directory):
        found = directory.lookup_user(SAM)

        assert found is not None
        assert found["sam"] == SAM
        assert found["display_name"] == "Jane Doe"
        assert found["email"] == "j.doe@deskpilot.test"

    def test_lookup_by_email(self, directory):
        found = directory.lookup_user("j.doe@deskpilot.test")

        assert found is not None
        assert found["sam"] == SAM

    def test_lookup_is_case_insensitive(self, directory):
        assert directory.lookup_user("J.DOE") is not None

    def test_lookup_unknown_user_returns_none(self, directory):
        assert directory.lookup_user("nobody.here") is None

    def test_group_membership_lists_members(self, directory):
        result = directory.get_group_membership(GROUP)

        assert result["group"] == GROUP
        assert SAM in [member["sam"] for member in result["members"]]

    def test_user_groups(self, directory):
        result = directory.get_group_membership(None, SAM)

        assert GROUP in result["groups"]

    def test_group_membership_requires_an_argument(self, directory):
        with pytest.raises(ToolExecutionError):
            directory.get_group_membership(None, None)

    def test_unknown_group_raises(self, directory):
        with pytest.raises(ToolExecutionError):
            directory.get_group_membership("No Such Group")

    def test_unknown_user_raises(self, directory):
        with pytest.raises(ToolExecutionError):
            directory.get_group_membership(None, "nobody.here")

    # -- writes -------------------------------------------------------------
    def test_dry_run_reports_the_plan_without_changing_anything(self, directory):
        before = directory.get_group_membership(None, SAM)["groups"]

        plan = directory.remove_group_member(GROUP, SAM, dry_run=True)

        assert plan["dry_run"] is True
        assert plan["already_member"] is True
        assert directory.get_group_membership(None, SAM)["groups"] == before

    def test_remove_then_add_restores_membership(self, directory):
        removed = directory.remove_group_member(GROUP, SAM, dry_run=False)
        assert removed["dry_run"] is False
        assert GROUP not in directory.get_group_membership(None, SAM)["groups"]

        added = directory.add_group_member(GROUP, SAM, dry_run=False)
        assert added["dry_run"] is False
        assert GROUP in directory.get_group_membership(None, SAM)["groups"]

    def test_privileged_groups_are_refused_before_any_change(self, directory):
        with pytest.raises(ToolDenied, match="privileged group"):
            directory.add_group_member(PRIVILEGED_GROUP, SAM, dry_run=False)

    def test_privileged_groups_are_refused_even_on_dry_run(self, directory):
        with pytest.raises(ToolDenied):
            directory.remove_group_member(PRIVILEGED_GROUP, SAM, dry_run=True)

    def test_password_reset_returns_a_strong_password(self, directory):
        result = directory.reset_password(SAM, True, dry_run=False)

        password = result["password"]
        assert len(password) >= 16
        assert any(c.islower() for c in password)
        assert any(c.isupper() for c in password)
        assert any(c.isdigit() for c in password)

    def test_password_reset_dry_run_generates_nothing(self, directory):
        result = directory.reset_password(SAM, True, dry_run=True)

        assert result["dry_run"] is True
        assert "password" not in result

    def test_password_reset_unknown_user_raises(self, directory):
        with pytest.raises(ToolExecutionError):
            directory.reset_password("nobody.here", True, dry_run=False)
