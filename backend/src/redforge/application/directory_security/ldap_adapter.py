"""Read-only LDAP/Active-Directory-compatible directory adapter — M5.

SAFETY BOUNDARY (Capability 21): this adapter performs SEARCH
operations ONLY. It exposes no method that could add, modify, delete,
bind-reset, or otherwise mutate a directory object — there is no
`execute_ldap_operation()`/`run_directory_command()` escape hatch. The
underlying `ldap3` connection object is never returned to a caller; it
is opened, searched, and closed entirely within `discover()`.

TRANSPORT SECURITY: production callers MUST supply `ldaps://` (implicit
TLS) or set `use_start_tls=True` with `ldap://`. Plaintext LDAP with no
StartTLS is rejected unless the caller explicitly passes
`allow_insecure_plaintext=True` (an explicit, opt-in, non-default
development escape hatch — never silently downgraded). Certificate
validation is enabled by default (`validate_certificates=True`);
disabling it is a separate explicit opt-in, never a default.

CLASSIFICATION: HUMAN vs SERVICE is derived strictly from LDAP
`objectClass` values (a source-schema fact), never a display-name
heuristic. Entries whose objectClass set matches neither a recognized
person schema nor a recognized service/role schema are SKIPPED (an
error is recorded, not a fabricated classification).
"""

from __future__ import annotations

import logging
import ssl

import ldap3
from ldap3.core.exceptions import LDAPBindError, LDAPException, LDAPSocketOpenError

from redforge.application.directory_security.observations import (
    DirectoryDiscoveryResult,
    GroupObservation,
    IdentityObservation,
    MembershipObservation,
)

logger = logging.getLogger(__name__)

_PERSON_OBJECT_CLASSES = {"person", "inetorgperson", "organizationalperson", "user"}
_SERVICE_OBJECT_CLASSES = {"organizationalrole", "simplesecurityobject"}

_IDENTITY_SEARCH_FILTER = "(|(objectClass=person)(objectClass=organizationalRole))"
_GROUP_SEARCH_FILTER = (
    "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))"
)

_IDENTITY_ATTRIBUTES = [
    "objectClass", "entryUUID", "cn", "uid", "displayName", "userAccountControl",
]
_GROUP_ATTRIBUTES = ["objectClass", "entryUUID", "cn", "member", "uniqueMember", "memberUid"]

# userAccountControl bit 0x2 == ACCOUNTDISABLE (Active Directory semantics).
_AD_ACCOUNTDISABLE_BIT = 0x2


class LdapConnectionError(RuntimeError):
    """Sanitized connection/authentication/TLS failure — never includes
    the bind password."""


class LdapDirectoryAdapter:
    """Read-only LDAP directory discovery adapter.

    No write/mutate methods exist on this class by design (Capability 21).
    """

    def discover(
        self,
        server_uri: str,
        base_dn: str,
        bind_dn: str,
        bind_password: str,
        *,
        use_start_tls: bool = False,
        allow_insecure_plaintext: bool = False,
        validate_certificates: bool = True,
        page_size: int = 100,
    ) -> DirectoryDiscoveryResult:
        is_ldaps = server_uri.lower().startswith("ldaps://")
        if not is_ldaps and not use_start_tls and not allow_insecure_plaintext:
            raise LdapConnectionError(
                "Insecure transport rejected: server_uri must be ldaps://, or "
                "use_start_tls=True must be set, or allow_insecure_plaintext=True "
                "must be explicitly opted into (development only)."
            )

        tls = ldap3.Tls(validate=ssl.CERT_REQUIRED if validate_certificates else ssl.CERT_NONE)
        try:
            server = ldap3.Server(server_uri, use_ssl=is_ldaps, tls=tls, get_info=ldap3.NONE)
            conn = ldap3.Connection(server, user=bind_dn, password=bind_password)
            if use_start_tls and not is_ldaps:
                if not conn.open():  # pragma: no cover - exercised via mocks in tests
                    raise LdapConnectionError("Failed to open connection for StartTLS")
                if not conn.start_tls():
                    raise LdapConnectionError("StartTLS negotiation failed")
            if not conn.bind():
                raise LdapConnectionError("Bind failed (sanitized — credentials never logged)")
        except LDAPBindError as exc:
            raise LdapConnectionError("Bind failed (sanitized — credentials never logged)") from exc
        except LDAPSocketOpenError as exc:
            raise LdapConnectionError("Connection failed (sanitized)") from exc
        except LDAPException as exc:
            raise LdapConnectionError(f"LDAP error (sanitized): {type(exc).__name__}") from exc

        errors: list[str] = []
        try:
            identities = self._search_identities(conn, base_dn, page_size, errors)
            groups, memberships = self._search_groups(conn, base_dn, page_size, errors)
        finally:
            conn.unbind()

        return DirectoryDiscoveryResult(
            identities=tuple(identities), groups=tuple(groups),
            memberships=tuple(memberships), errors=tuple(errors),
        )

    def _search_identities(
        self, conn: ldap3.Connection, base_dn: str, page_size: int, errors: list[str]
    ) -> list[IdentityObservation]:
        identities: list[IdentityObservation] = []
        entries = conn.extend.standard.paged_search(
            search_base=base_dn, search_filter=_IDENTITY_SEARCH_FILTER,
            attributes=_IDENTITY_ATTRIBUTES, paged_size=page_size, generator=True,
        )
        for entry in entries:
            if entry.get("type") != "searchResEntry":
                continue
            attrs = entry.get("attributes", {})
            try:
                identities.append(self._map_identity(attrs))
            except _UnsupportedSourceObjectError as exc:
                errors.append(f"skipped unsupported identity object: {exc}")
        return identities

    def _map_identity(self, attrs: dict[str, object]) -> IdentityObservation:
        object_classes = {str(c).lower() for c in _as_list(attrs.get("objectClass"))}
        entry_uuid = _first(attrs.get("entryUUID"))
        if not entry_uuid:
            raise _UnsupportedSourceObjectError("missing entryUUID")

        if object_classes & _PERSON_OBJECT_CLASSES:
            category = "human"
        elif object_classes & _SERVICE_OBJECT_CLASSES:
            category = "service"
        else:
            raise _UnsupportedSourceObjectError(f"unrecognized objectClass set: {object_classes}")

        uac = _first(attrs.get("userAccountControl"))
        source_enabled = True
        if uac is not None:
            try:
                source_enabled = (int(str(uac)) & _AD_ACCOUNTDISABLE_BIT) == 0
            except (TypeError, ValueError):
                source_enabled = True

        display_name = _first(attrs.get("displayName")) or _first(attrs.get("cn")) or ""
        principal_name = _first(attrs.get("uid")) or _first(attrs.get("cn")) or ""

        return IdentityObservation(
            external_id_raw=str(entry_uuid),
            principal_category=category,
            display_name=str(display_name),
            principal_name=str(principal_name),
            source_enabled=source_enabled,
            safe_attributes={"object_class": ",".join(sorted(object_classes))},
        )

    def _search_groups(
        self, conn: ldap3.Connection, base_dn: str, page_size: int, errors: list[str]
    ) -> tuple[list[GroupObservation], list[MembershipObservation]]:
        groups: list[GroupObservation] = []
        memberships: list[MembershipObservation] = []
        dn_to_entry_uuid: dict[str, str] = {}

        # Build a DN -> entryUUID map for membership resolution (member/
        # uniqueMember attributes reference DNs, not entryUUIDs).
        member_entries = conn.extend.standard.paged_search(
            search_base=base_dn, search_filter=_IDENTITY_SEARCH_FILTER,
            attributes=["entryUUID"], paged_size=page_size, generator=True,
        )
        for entry in member_entries:
            if entry.get("type") != "searchResEntry":
                continue
            uuid_val = _first(entry.get("attributes", {}).get("entryUUID"))
            if uuid_val:
                dn_to_entry_uuid[str(entry.get("dn", "")).lower()] = str(uuid_val)

        entries = conn.extend.standard.paged_search(
            search_base=base_dn, search_filter=_GROUP_SEARCH_FILTER,
            attributes=_GROUP_ATTRIBUTES, paged_size=page_size, generator=True,
        )
        for entry in entries:
            if entry.get("type") != "searchResEntry":
                continue
            attrs = entry.get("attributes", {})
            entry_uuid = _first(attrs.get("entryUUID"))
            if not entry_uuid:
                errors.append("skipped group with no entryUUID")
                continue
            display_name = str(_first(attrs.get("cn")) or "")
            groups.append(
                GroupObservation(external_id_raw=str(entry_uuid), display_name=display_name)
            )

            for member_dn in _as_list(attrs.get("member")) + _as_list(attrs.get("uniqueMember")):
                member_uuid = dn_to_entry_uuid.get(str(member_dn).lower())
                if member_uuid is None:
                    errors.append(f"unresolved member reference (not fabricated): {member_dn}")
                    continue
                memberships.append(
                    MembershipObservation(
                        member_identity_external_id_raw=member_uuid,
                        group_external_id_raw=str(entry_uuid),
                    )
                )
        return groups, memberships


class _UnsupportedSourceObjectError(ValueError):
    pass


def _as_list(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _first(value: object) -> object | None:
    items = _as_list(value)
    return items[0] if items else None
