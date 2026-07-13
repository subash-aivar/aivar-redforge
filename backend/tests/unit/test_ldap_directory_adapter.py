"""Contract-level tests for the read-only LDAP directory adapter — M5.

Uses ldap3's own MOCK_SYNC in-memory strategy to exercise the REAL
ldap3 client code paths (bind, paged search, attribute decoding)
against seeded directory entries — this is a real library testing
feature, not a hand-rolled fake, but it is NOT a network-level LDAP
server. Live network-level/live-source protocol acceptance against a
real or containerized directory is separately reported BLOCKED in the
M5 report (no Docker/container runtime is available in this
environment) — these tests prove the adapter's mapping/classification/
pagination/error-handling LOGIC, not live-wire network behavior.
"""

from __future__ import annotations

import ldap3
import pytest

from redforge.application.directory_security import ldap_adapter as ldap_adapter_module
from redforge.application.directory_security.ldap_adapter import (
    LdapConnectionError,
    LdapDirectoryAdapter,
)

_BASE_DN = "dc=example,dc=com"
_BIND_DN = "cn=admin,dc=example,dc=com"


def _seeded_mock_connection() -> ldap3.Connection:
    server = ldap3.Server("mock")
    conn = ldap3.Connection(
        server, user=_BIND_DN, password="x", client_strategy=ldap3.MOCK_SYNC,
    )
    conn.strategy.add_entry(_BIND_DN, {"userPassword": "x", "sn": "admin", "revision": 0})
    conn.strategy.add_entry(
        "cn=alice,ou=people,dc=example,dc=com",
        {
            "objectClass": ["person", "inetOrgPerson"],
            "entryUUID": "550e8400-e29b-41d4-a716-446655440000",
            "cn": "alice",
            "uid": "alice",
            "displayName": "Alice Human",
        },
    )
    conn.strategy.add_entry(
        "cn=svc-backup,ou=service,dc=example,dc=com",
        {
            "objectClass": ["organizationalRole"],
            "entryUUID": "660e8400-e29b-41d4-a716-446655440001",
            "cn": "svc-backup",
            "displayName": "svc-backup",
        },
    )
    conn.strategy.add_entry(
        "cn=disabled-bob,ou=people,dc=example,dc=com",
        {
            "objectClass": ["person", "inetOrgPerson"],
            "entryUUID": "770e8400-e29b-41d4-a716-446655440002",
            "cn": "bob",
            "uid": "bob",
            "displayName": "Bob Disabled",
            "userAccountControl": "2",  # ACCOUNTDISABLE bit set
        },
    )
    conn.strategy.add_entry(
        "cn=no-uuid,ou=people,dc=example,dc=com",
        {
            # Matches the identity search filter (objectClass=person) but
            # is missing entryUUID — must be skipped, not fabricated.
            "objectClass": ["person", "inetOrgPerson"],
            "cn": "no-uuid",
        },
    )
    conn.strategy.add_entry(
        "cn=admins,ou=groups,dc=example,dc=com",
        {
            "objectClass": ["groupOfNames"],
            "entryUUID": "990e8400-e29b-41d4-a716-446655440004",
            "cn": "admins",
            "member": [
                "cn=alice,ou=people,dc=example,dc=com",
                "cn=svc-backup,ou=service,dc=example,dc=com",
                "cn=ghost,ou=people,dc=example,dc=com",  # unresolved reference
            ],
        },
    )
    return conn


@pytest.fixture
def patched_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_conn = _seeded_mock_connection()
    monkeypatch.setattr(
        ldap_adapter_module.ldap3, "Connection", lambda *a, **kw: mock_conn,
    )


def test_insecure_plaintext_rejected_by_default() -> None:
    adapter = LdapDirectoryAdapter()
    with pytest.raises(LdapConnectionError, match="Insecure transport"):
        adapter.discover(
            server_uri="ldap://directory.example.com", base_dn=_BASE_DN,
            bind_dn=_BIND_DN, bind_password="x",
        )


def test_ldaps_allowed_without_explicit_insecure_flag(patched_connection: None) -> None:
    adapter = LdapDirectoryAdapter()
    result = adapter.discover(
        server_uri="ldaps://directory.example.com", base_dn=_BASE_DN,
        bind_dn=_BIND_DN, bind_password="x",
    )
    assert len(result.identities) == 3  # alice, svc-backup, bob (disabled) — unrecognized skipped


def test_human_identity_classified_from_object_class(patched_connection: None) -> None:
    adapter = LdapDirectoryAdapter()
    result = adapter.discover(
        server_uri="ldaps://directory.example.com", base_dn=_BASE_DN,
        bind_dn=_BIND_DN, bind_password="x",
    )
    alice = next(i for i in result.identities if i.display_name == "Alice Human")
    assert alice.principal_category == "human"
    assert alice.source_enabled is True


def test_service_identity_classified_from_object_class(patched_connection: None) -> None:
    adapter = LdapDirectoryAdapter()
    result = adapter.discover(
        server_uri="ldaps://directory.example.com", base_dn=_BASE_DN,
        bind_dn=_BIND_DN, bind_password="x",
    )
    svc = next(i for i in result.identities if i.display_name == "svc-backup")
    assert svc.principal_category == "service"


def test_disabled_identity_mapped_from_useraccountcontrol(patched_connection: None) -> None:
    adapter = LdapDirectoryAdapter()
    result = adapter.discover(
        server_uri="ldaps://directory.example.com", base_dn=_BASE_DN,
        bind_dn=_BIND_DN, bind_password="x",
    )
    bob = next(i for i in result.identities if i.display_name == "Bob Disabled")
    assert bob.source_enabled is False


def test_entry_missing_entry_uuid_skipped_not_fabricated(patched_connection: None) -> None:
    adapter = LdapDirectoryAdapter()
    result = adapter.discover(
        server_uri="ldaps://directory.example.com", base_dn=_BASE_DN,
        bind_dn=_BIND_DN, bind_password="x",
    )
    assert not any(i.display_name == "no-uuid" for i in result.identities)
    assert any("missing entryUUID" in e for e in result.errors)


def test_group_discovered_with_direct_members(patched_connection: None) -> None:
    adapter = LdapDirectoryAdapter()
    result = adapter.discover(
        server_uri="ldaps://directory.example.com", base_dn=_BASE_DN,
        bind_dn=_BIND_DN, bind_password="x",
    )
    assert len(result.groups) == 1
    assert result.groups[0].display_name == "admins"
    # 2 resolved (alice, svc-backup) + 1 unresolved reference recorded as error, not fabricated
    assert len(result.memberships) == 2
    assert any("unresolved member reference" in e for e in result.errors)


def test_no_write_methods_exposed() -> None:
    """Capability 21 safety boundary: no add/modify/delete method exists
    on the adapter at all."""
    public_methods = {m for m in dir(LdapDirectoryAdapter) if not m.startswith("_")}
    assert public_methods == {"discover"}
