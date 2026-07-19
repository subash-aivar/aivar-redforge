"""Tests for CredentialVersion entity."""

from __future__ import annotations

import pytest

from credential_vault.domain.exceptions.domain_exceptions import InvalidStateTransition
from credential_vault.domain.value_objects.states import VersionState
from tests.credential_vault.conftest import make_credential_version


class TestCredentialVersion:
    def test_promote_pending_to_active(
        self,
        version_id,
        credential_id,
        tenant_id,
        principal_id,
        encrypted_payload,
        key_envelope,
        now,
    ) -> None:
        version = make_credential_version(
            version_id=version_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            encrypted_payload=encrypted_payload,
            key_envelope=key_envelope,
            now=now,
            version_state=VersionState.PENDING,
        )
        version.promote()
        assert version.version_state == VersionState.ACTIVE

    def test_supersede_active(
        self,
        version_id,
        credential_id,
        tenant_id,
        principal_id,
        encrypted_payload,
        key_envelope,
        now,
    ) -> None:
        version = make_credential_version(
            version_id=version_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            encrypted_payload=encrypted_payload,
            key_envelope=key_envelope,
            now=now,
        )
        version.supersede()
        assert version.version_state == VersionState.SUPERSEDED

    def test_revoke(
        self,
        version_id,
        credential_id,
        tenant_id,
        principal_id,
        encrypted_payload,
        key_envelope,
        now,
    ) -> None:
        version = make_credential_version(
            version_id=version_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            encrypted_payload=encrypted_payload,
            key_envelope=key_envelope,
            now=now,
        )
        version.revoke()
        assert version.version_state == VersionState.REVOKED

    def test_rewrap_key(
        self,
        version_id,
        credential_id,
        tenant_id,
        principal_id,
        encrypted_payload,
        key_envelope,
        now,
    ) -> None:
        version = make_credential_version(
            version_id=version_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            encrypted_payload=encrypted_payload,
            key_envelope=key_envelope,
            now=now,
        )
        new_envelope = key_envelope
        version.rewrap_key(new_envelope)
        assert version.key_envelope == new_envelope

    def test_is_resolvable_only_when_active(
        self,
        version_id,
        credential_id,
        tenant_id,
        principal_id,
        encrypted_payload,
        key_envelope,
        now,
    ) -> None:
        version = make_credential_version(
            version_id=version_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            encrypted_payload=encrypted_payload,
            key_envelope=key_envelope,
            now=now,
        )
        assert version.is_resolvable() is True
        version.supersede()
        assert version.is_resolvable() is False

    def test_promote_from_active_fails(
        self,
        version_id,
        credential_id,
        tenant_id,
        principal_id,
        encrypted_payload,
        key_envelope,
        now,
    ) -> None:
        version = make_credential_version(
            version_id=version_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            encrypted_payload=encrypted_payload,
            key_envelope=key_envelope,
            now=now,
        )
        with pytest.raises(InvalidStateTransition):
            version.promote()

    def test_version_number_must_be_positive(
        self,
        version_id,
        credential_id,
        tenant_id,
        principal_id,
        encrypted_payload,
        key_envelope,
        now,
    ) -> None:
        with pytest.raises(ValueError, match="version_number"):
            make_credential_version(
                version_id=version_id,
                credential_id=credential_id,
                tenant_id=tenant_id,
                owner_principal=principal_id,
                encrypted_payload=encrypted_payload,
                key_envelope=key_envelope,
                now=now,
                version_number=0,
            )
