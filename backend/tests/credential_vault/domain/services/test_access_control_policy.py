"""Tests for AccessControlPolicyService."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from credential_vault.domain.exceptions.domain_exceptions import (
    AccessDenied,
    CredentialIsDeleted,
    CredentialIsExpired,
    CredentialIsRevoked,
    InvalidStateTransition,
)
from credential_vault.domain.ports.i_permission_port import IPermissionPort
from credential_vault.domain.services.access_control_policy import AccessControlPolicyService
from credential_vault.domain.value_objects.access_context import AccessContext
from tests.credential_vault.conftest import make_active_credential, make_credential


@pytest.fixture
def permission_port() -> AsyncMock:
    port = AsyncMock(spec=IPermissionPort)
    port.has_permission.return_value = True
    return port


@pytest.fixture
def access_context(principal_id) -> AccessContext:
    return AccessContext(
        principal_id=principal_id,
        purpose="read",
        client_ip="10.0.0.1",
        request_id="req-1",
    )


class TestAccessControlPolicyService:
    async def test_assert_can_read_success(
        self,
        permission_port,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
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
        svc = AccessControlPolicyService(permission_port)
        await svc.assert_can_read(credential, access_context)

    async def test_assert_can_read_denied(
        self,
        permission_port,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
        access_context,
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
        svc = AccessControlPolicyService(permission_port)
        with pytest.raises(AccessDenied):
            await svc.assert_can_read(credential, access_context)

    async def test_assert_can_read_revoked(
        self,
        permission_port,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
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
        svc = AccessControlPolicyService(permission_port)
        with pytest.raises(CredentialIsRevoked):
            await svc.assert_can_read(credential, access_context)

    async def test_assert_can_read_expired(
        self,
        permission_port,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
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
        credential.expire(tenant_id, now)
        svc = AccessControlPolicyService(permission_port)
        with pytest.raises(CredentialIsExpired):
            await svc.assert_can_read(credential, access_context)

    async def test_assert_can_read_deleted(
        self,
        permission_port,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
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
        credential.hard_delete(tenant_id, principal_id, now)
        svc = AccessControlPolicyService(permission_port)
        with pytest.raises(CredentialIsDeleted):
            await svc.assert_can_read(credential, access_context)

    async def test_assert_can_read_pending_denied(
        self,
        permission_port,
        credential_id,
        tenant_id,
        principal_id,
        vault_backend_id,
        access_context,
        now,
    ) -> None:
        credential = make_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        svc = AccessControlPolicyService(permission_port)
        with pytest.raises(AccessDenied):
            await svc.assert_can_read(credential, access_context)

    async def test_assert_can_rotate_requires_active(
        self,
        permission_port,
        credential_id,
        tenant_id,
        principal_id,
        vault_backend_id,
        access_context,
        now,
    ) -> None:
        credential = make_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        svc = AccessControlPolicyService(permission_port)
        with pytest.raises(InvalidStateTransition):
            await svc.assert_can_rotate(credential, access_context)

    async def test_assert_can_delete_rejects_active(
        self,
        permission_port,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
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
        svc = AccessControlPolicyService(permission_port)
        with pytest.raises(InvalidStateTransition):
            await svc.assert_can_delete(credential, access_context)
