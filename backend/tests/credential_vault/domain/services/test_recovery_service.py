"""Tests for RecoveryService."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from credential_vault.domain.exceptions.domain_exceptions import (
    InsufficientApprovers,
    InvalidStateTransition,
    RecoveryVersionInvalid,
    TenantMismatch,
)
from credential_vault.domain.ports.i_approval_port import IApprovalPort
from credential_vault.domain.services.recovery_service import RecoveryService
from credential_vault.domain.value_objects.access_context import AccessContext
from credential_vault.domain.value_objects.states import VersionState
from tests.credential_vault.conftest import make_active_credential, make_credential_version


@pytest.fixture
def approval_port() -> AsyncMock:
    port = AsyncMock(spec=IApprovalPort)
    port.is_approved.return_value = True
    return port


@pytest.fixture
def access_context(principal_id) -> AccessContext:
    return AccessContext(
        principal_id=principal_id,
        purpose="recovery",
        client_ip=None,
        request_id=None,
    )


class TestRecoveryService:
    async def test_validate_recovery_success(
        self,
        approval_port,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
        encrypted_payload,
        key_envelope,
        access_context,
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
        credential.revoke(tenant_id, principal_id, "test", now)
        target = make_credential_version(
            version_id=version_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            encrypted_payload=encrypted_payload,
            key_envelope=key_envelope,
            now=now,
            version_state=VersionState.SUPERSEDED,
        )
        svc = RecoveryService(approval_port)
        await svc.validate_recovery(credential, target, access_context)

    async def test_validate_recovery_not_revoked(
        self,
        approval_port,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
        encrypted_payload,
        key_envelope,
        access_context,
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
        target = make_credential_version(
            version_id=version_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            encrypted_payload=encrypted_payload,
            key_envelope=key_envelope,
            now=now,
            version_state=VersionState.SUPERSEDED,
        )
        svc = RecoveryService(approval_port)
        with pytest.raises(InvalidStateTransition):
            await svc.validate_recovery(credential, target, access_context)

    async def test_validate_recovery_invalid_version_state(
        self,
        approval_port,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
        encrypted_payload,
        key_envelope,
        access_context,
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
        credential.revoke(tenant_id, principal_id, "test", now)
        target = make_credential_version(
            version_id=version_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            encrypted_payload=encrypted_payload,
            key_envelope=key_envelope,
            now=now,
            version_state=VersionState.ACTIVE,
        )
        svc = RecoveryService(approval_port)
        with pytest.raises(RecoveryVersionInvalid):
            await svc.validate_recovery(credential, target, access_context)

    async def test_validate_recovery_tenant_mismatch(
        self,
        approval_port,
        credential_id,
        tenant_id,
        other_tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
        encrypted_payload,
        key_envelope,
        access_context,
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
        credential.revoke(tenant_id, principal_id, "test", now)
        target = make_credential_version(
            version_id=version_id,
            credential_id=credential_id,
            tenant_id=other_tenant_id,
            owner_principal=principal_id,
            encrypted_payload=encrypted_payload,
            key_envelope=key_envelope,
            now=now,
            version_state=VersionState.SUPERSEDED,
        )
        svc = RecoveryService(approval_port)
        with pytest.raises(TenantMismatch):
            await svc.validate_recovery(credential, target, access_context)

    async def test_validate_recovery_insufficient_approvers(
        self,
        approval_port,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
        encrypted_payload,
        key_envelope,
        access_context,
        now,
    ) -> None:
        approval_port.is_approved.return_value = False
        approval_port.get_approver_count.return_value = (1, 2)
        credential = make_active_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            version_id=version_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        credential.revoke(tenant_id, principal_id, "test", now)
        target = make_credential_version(
            version_id=version_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            encrypted_payload=encrypted_payload,
            key_envelope=key_envelope,
            now=now,
            version_state=VersionState.REVOKED,
        )
        svc = RecoveryService(approval_port)
        with pytest.raises(InsufficientApprovers):
            await svc.validate_recovery(credential, target, access_context)
