"""Tests for BreakGlassService."""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import AsyncMock

import pytest

from credential_vault.domain.exceptions.domain_exceptions import (
    BreakGlassJustificationRequired,
    CredentialIsDeleted,
    InsufficientApprovers,
)
from credential_vault.domain.ports.i_approval_port import IApprovalPort
from credential_vault.domain.services.break_glass_service import BreakGlassService
from credential_vault.domain.value_objects.identifiers import PrincipalId
from tests.credential_vault.conftest import make_active_credential


@dataclass
class BreakGlassContext:
    """Minimal stand-in when AccessContext validation must be bypassed."""

    principal_id: PrincipalId
    purpose: str
    client_ip: str | None
    request_id: str | None
    break_glass: bool = False
    justification: str | None = None


@pytest.fixture
def approval_port() -> AsyncMock:
    port = AsyncMock(spec=IApprovalPort)
    port.is_approved.return_value = True
    return port


class TestBreakGlassService:
    async def test_validate_break_glass_success(
        self,
        approval_port,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
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
        context = BreakGlassContext(
            principal_id=principal_id,
            purpose="emergency",
            client_ip=None,
            request_id=None,
            break_glass=True,
            justification="incident response",
        )
        svc = BreakGlassService(approval_port)
        await svc.validate_break_glass(credential, context)  # type: ignore[arg-type]

    async def test_validate_break_glass_without_flag(
        self,
        approval_port,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
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
        context = BreakGlassContext(
            principal_id=principal_id,
            purpose="emergency",
            client_ip=None,
            request_id=None,
            break_glass=False,
            justification="incident response",
        )
        svc = BreakGlassService(approval_port)
        with pytest.raises(BreakGlassJustificationRequired):
            await svc.validate_break_glass(credential, context)  # type: ignore[arg-type]

    async def test_validate_break_glass_without_justification(
        self,
        approval_port,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
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
        context = BreakGlassContext(
            principal_id=principal_id,
            purpose="emergency",
            client_ip=None,
            request_id=None,
            break_glass=True,
            justification=None,
        )
        svc = BreakGlassService(approval_port)
        with pytest.raises(BreakGlassJustificationRequired):
            await svc.validate_break_glass(credential, context)  # type: ignore[arg-type]

    async def test_validate_break_glass_deleted_credential(
        self,
        approval_port,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
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
        context = BreakGlassContext(
            principal_id=principal_id,
            purpose="emergency",
            client_ip=None,
            request_id=None,
            break_glass=True,
            justification="incident response",
        )
        svc = BreakGlassService(approval_port)
        with pytest.raises(CredentialIsDeleted):
            await svc.validate_break_glass(credential, context)  # type: ignore[arg-type]

    async def test_validate_break_glass_insufficient_approvers(
        self,
        approval_port,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
        now,
    ) -> None:
        approval_port.is_approved.return_value = False
        approval_port.get_approver_count.return_value = (0, 2)
        credential = make_active_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            version_id=version_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        context = BreakGlassContext(
            principal_id=principal_id,
            purpose="emergency",
            client_ip=None,
            request_id=None,
            break_glass=True,
            justification="incident response",
        )
        svc = BreakGlassService(approval_port)
        with pytest.raises(InsufficientApprovers):
            await svc.validate_break_glass(credential, context)  # type: ignore[arg-type]
