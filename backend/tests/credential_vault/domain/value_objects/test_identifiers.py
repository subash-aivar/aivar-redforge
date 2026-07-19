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

    @pytest.mark.parametrize("id_cls", ID_CLASSES)
    def test_nil_uuid_rejected(self, id_cls: type) -> None:
        with pytest.raises(ValueError, match="nil UUID"):
            id_cls(NIL_UUID)

    def test_cross_type_inequality(self) -> None:
        shared = uuid4()
        assert CredentialId(shared) != TenantId(shared)
        assert CredentialId(shared) == CredentialId(shared)
