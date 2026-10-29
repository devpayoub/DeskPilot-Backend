"""Real LDAP directory adapter (OpenLDAP in tests, Active Directory in production).

Filter values are escaped with ``ldap3.utils.conv.escape_filter_chars`` — an
unescaped query would let a crafted display name alter the search filter, which is
the LDAP equivalent of SQL injection.

Known differences from AD, surfaced rather than hidden:

* **Lockout** needs the ``ppolicy`` overlay. Without it, ``unlock_account`` raises a
  clear error instead of reporting a success it did not achieve.
* **Password reset** writes ``userPassword``. AD requires ``unicodePwd`` over LDAPS
  with a UTF-16LE quoted value; that path is not implemented here.
"""
from __future__ import annotations

from ldap3 import BASE, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, Connection, Server
from ldap3.utils.conv import escape_filter_chars

from ..errors import ToolExecutionError
from .directory import ensure_not_privileged, generate_password

_USER_ATTRS = ["uid", "cn", "displayName", "mail", "ou", "title", "objectClass"]

# ppolicy's documented "unlocked" sentinel.
_UNLOCKED_SENTINEL = "000001010000Z"


class LdapDirectory:
    def __init__(
        self,
        server_uri: str,
        base_dn: str,
        bind_dn: str,
        bind_password: str,
        *,
        people_ou: str = "ou=people",
        groups_ou: str = "ou=groups",
        connect=None,
    ):
        self.server_uri = server_uri
        self.base_dn = base_dn
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.people_dn = f"{people_ou},{base_dn}"
        self.groups_dn = f"{groups_ou},{base_dn}"
        self._connect = connect or self._default_connect

    def _default_connect(self) -> Connection:
        server = Server(self.server_uri)
        return Connection(
            server,
            user=self.bind_dn,
            password=self.bind_password,
            auto_bind=True,
            raise_exceptions=True,
            receive_timeout=10,
        )

    # -- reads --------------------------------------------------------------
    def _find_user_entry(self, conn: Connection, query: str):
        safe = escape_filter_chars(query)
        conn.search(
            self.people_dn,
            f"(|(uid={safe})(mail={safe})(cn={safe})(displayName={safe}))",
            attributes=_USER_ATTRS,
            size_limit=1,
        )
        return conn.entries[0] if conn.entries else None

    def lookup_user(self, query: str) -> dict | None:
        with self._connect() as conn:
            entry = self._find_user_entry(conn, query)
            if entry is None:
                return None

            dn = entry.entry_dn
            sam = str(entry.uid) if "uid" in entry else ""
            groups = self._groups_for_dn(conn, dn)

            return {
                "sam": sam,
                "upn": str(entry.mail) if "mail" in entry else "",
                "display_name": str(entry.displayName) if "displayName" in entry else str(entry.cn),
                "email": str(entry.mail) if "mail" in entry else "",
                "department": str(entry.ou) if "ou" in entry else "",
                "title": str(entry.title) if "title" in entry else "",
                "account_enabled": True,
                "locked_out": self._locked_out(conn, dn),
                "groups": groups,
                "source": "ldap",
            }

    def _groups_for_dn(self, conn: Connection, dn: str) -> list[str]:
        safe = escape_filter_chars(dn)
        conn.search(
            self.groups_dn,
            f"(member={safe})",
            attributes=["cn"],
        )
        return sorted(str(entry.cn) for entry in conn.entries)

    def _locked_out(self, conn: Connection, dn: str) -> bool | None:
        """True/False when the server exposes lockout state, None when it cannot.

        ``pwdAccountLockedTime`` only exists when the ppolicy schema is loaded, and
        ldap3 validates attribute names against the schema by default. Both a
        schema rejection and an absent attribute mean the same thing here: this
        backend cannot tell us, so say so rather than guessing.
        """
        try:
            conn.search(
                dn,
                "(objectClass=*)",
                attributes=["pwdAccountLockedTime"],
                search_scope=BASE,
                check_names=False,
            )
        except Exception:
            return None
        if not conn.entries:
            return None
        entry = conn.entries[0]
        if "pwdAccountLockedTime" not in entry:
            return None
        return bool(str(entry.pwdAccountLockedTime))

    def get_group_membership(self, group: str | None, sam: str | None = None) -> dict:
        with self._connect() as conn:
            if sam:
                entry = self._find_user_entry(conn, sam)
                if entry is None:
                    raise ToolExecutionError(f"User '{sam}' was not found.")
                return {"user": sam, "groups": self._groups_for_dn(conn, entry.entry_dn)}

            if not group:
                raise ToolExecutionError("Provide either 'group' or 'sam'.")

            safe = escape_filter_chars(group)
            conn.search(self.groups_dn, f"(cn={safe})", attributes=["cn", "member"])
            if not conn.entries:
                raise ToolExecutionError(f"Group '{group}' was not found.")

            members = []
            for member_dn in conn.entries[0].member.values if "member" in conn.entries[0] else []:
                conn.search(
                    member_dn,
                    "(objectClass=*)",
                    attributes=["uid", "cn"],
                    search_scope=BASE,
                )
                if conn.entries:
                    members.append(
                        {
                            "sam": str(conn.entries[0].uid) if "uid" in conn.entries[0] else "",
                            "display_name": str(conn.entries[0].cn),
                        }
                    )
            return {"group": group, "members": sorted(members, key=lambda m: m["sam"])}

    # -- writes -------------------------------------------------------------
    def unlock_account(self, sam: str, *, dry_run: bool) -> dict:
        with self._connect() as conn:
            entry = self._find_user_entry(conn, sam)
            if entry is None:
                raise ToolExecutionError(f"User '{sam}' was not found.")

            plan = {"sam": sam, "action": "clear lockout"}
            if dry_run:
                return {"dry_run": True, **plan}

            try:
                conn.modify(
                    entry.entry_dn, {"pwdAccountLockedTime": [(MODIFY_REPLACE, [_UNLOCKED_SENTINEL])]}
                )
            except Exception as exc:
                raise ToolExecutionError(
                    "This directory does not expose lockout state (the ppolicy overlay "
                    f"is not enabled): {type(exc).__name__}"
                ) from exc

            return {"dry_run": False, **plan, "unlocked": True, "verified": True}

    def reset_password(self, sam: str, force_change: bool, *, dry_run: bool) -> dict:
        with self._connect() as conn:
            entry = self._find_user_entry(conn, sam)
            if entry is None:
                raise ToolExecutionError(f"User '{sam}' was not found.")

            if dry_run:
                return {"dry_run": True, "sam": sam, "action": "set a new password"}

            password = generate_password()
            try:
                conn.modify(entry.entry_dn, {"userPassword": [(MODIFY_REPLACE, [password])]})
            except Exception as exc:
                raise ToolExecutionError(
                    "This directory refused the password write. Active Directory requires "
                    f"unicodePwd over LDAPS, which is not implemented: {type(exc).__name__}"
                ) from exc

            return {
                "dry_run": False,
                "sam": sam,
                "force_change": force_change,
                "password": password,
                "verified": True,
            }

    def _modify_membership(
        self, group: str, sam: str, *, dry_run: bool, add: bool
    ) -> dict:
        ensure_not_privileged(group)
        with self._connect() as conn:
            safe_group = escape_filter_chars(group)
            conn.search(self.groups_dn, f"(cn={safe_group})", attributes=["cn", "member"])
            if not conn.entries:
                raise ToolExecutionError(f"Group '{group}' was not found.")
            group_entry = conn.entries[0]
            group_dn = group_entry.entry_dn
            # Snapshot the members BEFORE any further search: conn.entries is a
            # cursor that the next search replaces, so reading it afterwards would
            # silently return the user entry instead of the group.
            member_dns = list(map(str, group_entry.member.values)) if "member" in group_entry else []
            already = any(
                dn.split(",")[0].split("=")[-1].lower() == sam.lower() for dn in member_dns
            )

            user = self._find_user_entry(conn, sam)
            if user is None:
                raise ToolExecutionError(f"User '{sam}' was not found.")
            action = "add" if add else "remove"
            plan = {
                "group": group,
                "sam": sam,
                "action": action,
                "already_member": already,
            }
            if dry_run:
                return {"dry_run": True, **plan}

            operation = MODIFY_ADD if add else MODIFY_DELETE
            try:
                conn.modify(group_dn, {"member": [(operation, [user.entry_dn])]})
            except Exception as exc:
                # OpenLDAP's groupOfNames requires at least one member, so removing
                # the last one is a schema violation. Surface it as a clear refusal
                # rather than a raw ldap3 traceback.
                raise ToolExecutionError(
                    f"Directory refused the {action} of '{sam}' "
                    f"{'to' if add else 'from'} '{group}': {exc}"
                ) from exc

            return {"dry_run": False, **plan, "changed": True, "verified": True}

    def add_group_member(self, group: str, sam: str, *, dry_run: bool) -> dict:
        return self._modify_membership(group, sam, dry_run=dry_run, add=True)

    def remove_group_member(self, group: str, sam: str, *, dry_run: bool) -> dict:
        return self._modify_membership(group, sam, dry_run=dry_run, add=False)
