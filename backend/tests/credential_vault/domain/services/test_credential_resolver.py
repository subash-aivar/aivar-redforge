"""Tests for CredentialResolverService."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from credential_vault.domain.events.credential_events import BreakGlassAccessed, CredentialAccessed
from credential_vault.domain.exceptions.domain_exceptions import (
    AccessDenied,
    ActiveVersionNotFound,
    ResolvedSecretZeroized,
)
from credential_vault.domain.ports.i_approval_port import IApprovalPort
from credential_vault.domain.ports.i_encryption_port import IEncryptionPort
from credential_vault.domain.ports.i_key_management_port import IKeyManagementPort
from credential_vault.domain.ports.i_permission_port import IPermissionPort
from credential_vault.domain.services.access_control_policy import AccessControlPolicyService
from credential_vault.domain.services.break_glass_service import BreakGlassService
from credential_vault.domain.services.credential_resolver import CredentialResolverService
from credential_vault.domain.value_objects.access_context import AccessContext
from credential_vault.domain.value_objects.states import VersionState
from tests.credential_vault.conftest import make_active_credential, make_credential_version


@pytest.fixture
def encryption_port() -> AsyncMock:
    port = AsyncMock(spec=IEncryptionPort)
    port.decrypt.return_value = b"plaintext-secret"
    return port


@pytest.fixture
def key_mgmt_port() -> AsyncMock:
    port = AsyncMock(spec=IKeyManagementPort)
    port.unwrap_dek.return_value = b"dek-bytes"
    return port


@pytest.fixture
def permission_port() -> AsyncMock:
    port = AsyncMock(spec=IPermissionPort)
    port.has_permission.return_value = True
    return port


@pytest.fixture
def approval_port() -> AsyncMock:
    port = AsyncMock(spec=IApprovalPort)
    port.is_approved.return_value = True
    return port


@pytest.fixture
def resolver(
    encryption_port,
    key_mgmt_port,
    permission_port,
    approval_port,
) -> CredentialResolverService:
    access_control = AccessControlPolicyService(permission_port)
    break_glass = BreakGlassService(approval_port)
    return CredentialResolverService(
        encryption_port=encryption_port,
        key_mgmt_port=key_mgmt_port,
        permission_port=permission_port,
        access_control=access_control,
        break_glass_svc=break_glass,
    )


@pytest.fixture
def read_context(principal_id) -> AccessContext:
    return AccessContext(
        principal_id=principal_id,
        purpose="deployment",
        client_ip="10.0.0.1",
        request_id="req-1",
    )


class TestCredentialResolverService:
    async def test_normal_resolution(
        self,
        resolver,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
        encrypted_payload,
        key_envelope,
        read_context,
        now,
    ) -> None:
        credential = make_active_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            version_id=version_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        credential.pop_events()
        version = make_credential_version(
            version_id=version_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            encrypted_payload=encrypted_payload,
            key_envelope=key_envelope,
            now=now,
        )
        secret = await resolver.resolve(credential, version, read_context)
        assert secret.get_plaintext() == b"plaintext-secret"
        events = credential.pop_events()
        assert len(events) == 1
        assert isinstance(events[0], CredentialAccessed)

    async def test_access_denied(
        self,
        resolver,
        permission_port,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
        encrypted_payload,
        key_envelope,
        read_context,
        now,
    ) -> None:
        permission_port.has_permission.return_value = False
        credential = make_active_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            version_id=version_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        credential.pop_events()
        version = make_credential_version(
            version_id=version_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            encrypted_payload=encrypted_payload,
            key_envelope=key_envelope,
            now=now,
        )
        with pytest.raises(AccessDenied):
            await resolver.resolve(credential, version, read_context)

    async def test_break_glass_success_emits_event(
        self,
        resolver,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
        encrypted_payload,
        key_envelope,
        now,
    ) -> None:
        credential = make_active_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            version_id=version_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        credential.pop_events()
        version = make_credential_version(
            version_id=version_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            encrypted_payload=encrypted_payload,
            key_envelope=key_envelope,
            now=now,
        )
        context = AccessContext(
            principal_id=principal_id,
            purpose="emergency",
            client_ip=None,
            request_id=None,
            break_glass=True,
            justification="incident response",
        )
        await resolver.resolve(credential, version, context)
        events = credential.pop_events()
        assert len(events) == 1
        assert isinstance(events[0], BreakGlassAccessed)

    async def test_break_glass_without_justification(
        self,
        resolver,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
        encrypted_payload,
        key_envelope,
        now,
    ) -> None:
        credential = make_active_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            version_id=version_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        credential.pop_events()
        make_credential_version(
            version_id=version_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            encrypted_payload=encrypted_payload,
            key_envelope=key_envelope,
            now=now,
        )
        with pytest.raises(ValueError, match="justification required"):
            AccessContext(
                principal_id=principal_id,
                purpose="emergency",
                client_ip=None,
                request_id=None,
                break_glass=True,
            )

    async def test_superseded_version_raises_active_version_not_found(
        self,
        resolver,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
        encrypted_payload,
        key_envelope,
        read_context,
        now,
    ) -> None:
        credential = make_active_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            version_id=version_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        credential.pop_events()
        version = make_credential_version(
            version_id=version_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            encrypted_payload=encrypted_payload,
            key_envelope=key_envelope,
            now=now,
            version_state=VersionState.SUPERSEDED,
        )
        with pytest.raises(ActiveVersionNotFound):
            await resolver.resolve(credential, version, read_context)

    async def test_resolved_secret_zero(
        self,
        credential_id,
        tenant_id,
        version_id,
        now,
    ) -> None:
        from credential_vault.domain.value_objects.payloads import ResolvedSecret

        secret = ResolvedSecret(
            plaintext=b"secret",
            credential_id=credential_id,
            version_id=version_id,
            resolved_at=now,
        )
        secret.zero()
        with pytest.raises(ResolvedSecretZeroized):
            secret.get_plaintext()
