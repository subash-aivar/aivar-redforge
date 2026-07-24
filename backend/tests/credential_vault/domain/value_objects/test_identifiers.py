"""Tests for UUID identity value objects."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from credential_vault.domain.value_objects.identifiers import (
    AuditEntryId,
    AuditLogId,
    CredentialId,
    ExpirationPolicyId,
    PrincipalId,
    RotationPolicyId,
    TenantId,
    VaultBackendId,
    VersionId,
)

NIL_UUID = UUID(int=0)

ID_CLASSES = [
    CredentialId,
    TenantId,
    VersionId,
    PrincipalId,
    RotationPolicyId,
    ExpirationPolicyId,
    VaultBackendId,
    AuditLogId,
    AuditEntryId,
]


class TestIdentifiers:
    @pytest.mark.parametrize("id_cls", ID_CLASSES)
    def test_valid_uuid(self, id_cls: type) -> None:
        value = uuid4()
        obj = id_cls(value)
        assert obj.value == value
        assert str(obj) == str(value)

    @pytest.mark.parametrize(
        "id_cls",
        [c for c in ID_CLASSES if c is not TenantId],
    )
    def test_nil_uuid_rejected(self, id_cls: type) -> None:
        with pytest.raises(ValueError, match="nil UUID"):
            id_cls(NIL_UUID)

    def test_tenant_id_is_entity_id_and_has_no_nil_concept(self) -> None:
        """TenantId is the shared ULID-backed EntityId per ADR-0005.

        Unlike the local UUID-backed value objects, EntityId has no nil/zero
        sentinel to reject -- ULIDs generated via EntityId.generate() (or
        parsed via EntityId.from_string()) are always valid once constructed.
        """
        tid = TenantId.generate()
        assert str(tid)

    def test_cross_type_inequality(self) -> None:
        shared = uuid4()
        assert CredentialId(shared) != TenantId(shared)
        assert CredentialId(shared) == CredentialId(shared)
