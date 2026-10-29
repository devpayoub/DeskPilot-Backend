"""The shared directory contract, run against a real LDAP server.

Skipped when no server is reachable, so the suite stays green without Docker. When
it *is* reachable, the same assertions that pass against the fake tenant must pass
here — that is the whole point of the adapter interface.

    docker run -d --rm --name deskpilot-ldap -p 3890:389 \
        -e LDAP_ORGANISATION=DeskPilot -e LDAP_DOMAIN=deskpilot.test \
        -e LDAP_ADMIN_PASSWORD=admin osixia/openldap:1.5.0
"""
from __future__ import annotations

import pytest

ldap3 = pytest.importorskip("ldap3")
from ldap3 import BASE, MODIFY_REPLACE, Connection, Server  # noqa: E402

from tests.directory_contract import SAM, DirectoryContract  # noqa: E402
from toolcore.adapters.ldap_directory import LdapDirectory  # noqa: E402
from toolcore.errors import ToolExecutionError  # noqa: E402

LDAP_URI = "ldap://localhost:3890"
BASE_DN = "dc=deskpilot,dc=test"
BIND_DN = "cn=admin,dc=deskpilot,dc=test"
BIND_PASSWORD = "admin"


def _server_available() -> bool:
    try:
        server = Server(LDAP_URI, connect_timeout=2)
        connection = Connection(server, user=BIND_DN, password=BIND_PASSWORD, auto_bind=True)
        connection.unbind()
        return True
    except Exception:
        return False


AVAILABLE = _server_available()
requires_ldap = pytest.mark.skipif(
    not AVAILABLE, reason="no LDAP server on localhost:3890"
)


def _connect() -> Connection:
    return Connection(
        Server(LDAP_URI),
        user=BIND_DN,
        password=BIND_PASSWORD,
        auto_bind=True,
        raise_exceptions=True,
    )


@pytest.fixture
def ldap_seeded():
    """Recreate the fixture data before every test, so one failure cannot leak."""
    conn = _connect()

    def delete_if_present(dn: str) -> None:
        # With raise_exceptions=True, a BASE search on a missing DN raises rather
        # than returning an empty cursor.
        try:
            conn.search(dn, "(objectClass=*)", attributes=["objectClass"], search_scope=BASE)
        except Exception:
            return
        if conn.entries:
            conn.delete(dn)

    try:
        # Leaves before parents: a subtree delete is not available in ldap3 2.9.
        for uid in (SAM, "j.smith"):
            delete_if_present(f"uid={uid},ou=people,{BASE_DN}")
        for group in ("VPN Users", "Domain Admins"):
            delete_if_present(f"cn={group},ou=groups,{BASE_DN}")
        for ou in ("people", "groups"):
            delete_if_present(f"ou={ou},{BASE_DN}")

        for ou in ("people", "groups"):
            conn.add(f"ou={ou},{BASE_DN}", "organizationalUnit", {"ou": ou})

        conn.add(
            f"uid={SAM},ou=people,{BASE_DN}",
            "inetOrgPerson",
            {
                "uid": SAM,
                "cn": "Jane Doe",
                "sn": "Doe",
                "displayName": "Jane Doe",
                "mail": "j.doe@deskpilot.test",
                "ou": "Finance",
                "title": "Analyst",
                "userPassword": "InitialPass!23",
            },
        )
        # A second member: OpenLDAP's groupOfNames requires at least one, so a group
        # holding only SAM could not be emptied without violating the schema.
        conn.add(
            f"uid=j.smith,ou=people,{BASE_DN}",
            "inetOrgPerson",
            {
                "uid": "j.smith",
                "cn": "John Smith",
                "sn": "Smith",
                "displayName": "John Smith",
                "mail": "j.smith@deskpilot.test",
                "userPassword": "InitialPass!23",
            },
        )
        for group in ("VPN Users", "Domain Admins"):
            conn.add(
                f"cn={group},ou=groups,{BASE_DN}",
                "groupOfNames",
                {
                    "cn": group,
                    "member": [
                        f"uid={SAM},ou=people,{BASE_DN}",
                        f"uid=j.smith,ou=people,{BASE_DN}",
                    ],
                },
            )
        yield
    finally:
        conn.unbind()


@pytest.fixture
def directory(ldap_seeded) -> LdapDirectory:
    return LdapDirectory(
        server_uri=LDAP_URI,
        base_dn=BASE_DN,
        bind_dn=BIND_DN,
        bind_password=BIND_PASSWORD,
    )


@requires_ldap
class TestLdapDirectory(DirectoryContract):
    """The same contract, against OpenLDAP."""

    def test_lockout_state_is_reported_as_unknown(self, directory):
        """OpenLDAP without ppolicy cannot tell us; saying so beats guessing."""
        found = directory.lookup_user(SAM)

        assert found["locked_out"] is None

    def test_unlock_without_ppolicy_raises_a_clear_error(self, directory):
        with pytest.raises(ToolExecutionError, match="ppolicy"):
            directory.unlock_account(SAM, dry_run=False)


@requires_ldap
def test_filter_injection_is_escaped(directory):
    """A crafted query must not widen the search filter."""
    assert directory.lookup_user("j.doe)(uid=*") is None
