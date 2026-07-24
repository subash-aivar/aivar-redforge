"""Tests for AuditQueryService."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from tests.credential_vault.application.conftest import make_audit_log

from credential_vault.application.dtos.audit_dtos import AuditEntryDTO
from credential_vault.application.exceptions import ApplicationValidationError
from credential_vault.application.queries.audit_queries import ListAuditEntriesQuery
from credential_vault.application.services.audit_query_service import AuditQueryService
from credential_vault.domain.entities.audit_entry import AuditEntry
from credential_vault.domain.exceptions.domain_exceptions import AccessDenied
from credential_vault.domain.ports.i_permission_port import IPermissionPort
from credential_vault.domain.repositories.i_audit_log_repository import IAuditLogRepository
from credential_vault.domain.repositories.i_credential_repository import (
    ICredentialRepository,
)
from credential_vault.domain.value_objects.audit_types import AuditOperation, AuditOutcome
from credential_vault.domain.value_objects.identifiers import (
    AuditEntryId,
    AuditLogId,
    CredentialId,
    PrincipalId,
    TenantId,
)
from redforge.shared.identifiers import EntityId


@pytest.fixture
def audit_log_repo() -> AsyncMock:
    return AsyncMock(spec=IAuditLogRepository)


@pytest.fixture
def credential_repo() -> AsyncMock:
    return AsyncMock(spec=ICredentialRepository)


@pytest.fixture
def service(
    audit_log_repo: AsyncMock,
    credential_repo: AsyncMock,
    mock_permission_port: AsyncMock,
) -> AuditQueryService:
    return AuditQueryService(
        audit_log_repo=audit_log_repo,
        credential_repo=credential_repo,
        permission_port=mock_permission_port,
    )


def _make_audit_entry(
    *,
    audit_log_id: AuditLogId,
    credential_id: CredentialId,
    tenant_id: TenantId,
    principal_id: PrincipalId | None = None,
    operation: AuditOperation = AuditOperation.ACCESSED,
    now: datetime | None = None,
) -> AuditEntry:
    return AuditEntry(
        entry_id=AuditEntryId(uuid4()),
        audit_log_id=audit_log_id,
        credential_id=credential_id,
        tenant_id=tenant_id,
        operation=operation,
        outcome=AuditOutcome.SUCCESS,
        principal_id=principal_id or PrincipalId(uuid4()),
        occurred_at=now or datetime(2026, 7, 19, 12, 0, 0, tzinfo=UTC),
        version_id=None,
        client_ip="127.0.0.1",
        request_id="req-1",
        detail="accessed",
        state_before=None,
        state_after=None,
    )


async def test_list_audit_entries_success(
    service: AuditQueryService,
    audit_log_repo: AsyncMock,
    credential_repo: AsyncMock,
    mock_permission_port: AsyncMock,
) -> None:
    tenant_uuid = EntityId.generate()
    credential_uuid = uuid4()
    tenant_id = tenant_uuid
    credential_id = CredentialId(credential_uuid)
    audit_log = make_audit_log(credential_id=credential_id, tenant_id=tenant_id)
    entries = [
        _make_audit_entry(
            audit_log_id=audit_log.audit_log_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            operation=AuditOperation.CREATED,
        ),
        _make_audit_entry(
            audit_log_id=audit_log.audit_log_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            operation=AuditOperation.ACCESSED,
        ),
    ]
    audit_log_repo.get_by_credential.return_value = audit_log
    audit_log_repo.list_entries.return_value = entries
    since = datetime(2026, 7, 1, tzinfo=UTC)
    qry = ListAuditEntriesQuery(
        tenant_id=tenant_uuid,
        credential_id=credential_uuid,
        principal_id=uuid4(),
        since=since,
        operations=["CREATED", "ACCESSED"],
        limit=50,
        offset=5,
    )

    result = await service.list_audit_entries(qry)

    assert len(result) == 2
    assert all(isinstance(dto, AuditEntryDTO) for dto in result)
    assert result[0].operation == AuditOperation.CREATED.value
    assert result[1].operation == AuditOperation.ACCESSED.value
    assert result[0].detail == "accessed"
    mock_permission_port.has_permission.assert_awaited_once()
    assert mock_permission_port.has_permission.await_args.args[2] == IPermissionPort.PERMISSION_READ
    audit_log_repo.get_by_credential.assert_awaited_once_with(credential_id, tenant_id)
    audit_log_repo.list_entries.assert_awaited_once_with(
        audit_log.audit_log_id,
        tenant_id,
        since,
        [AuditOperation.CREATED, AuditOperation.ACCESSED],
        50,
        5,
    )
    audit_log_repo.append_entry.assert_not_called()
    credential_repo.get_by_id.assert_not_called()


async def test_list_audit_entries_access_denied(
    service: AuditQueryService,
    audit_log_repo: AsyncMock,
    mock_permission_port: AsyncMock,
) -> None:
    mock_permission_port.has_permission.return_value = False
    qry = ListAuditEntriesQuery(
        tenant_id=EntityId.generate(),
        credential_id=uuid4(),
        principal_id=uuid4(),
    )

    with pytest.raises(AccessDenied) as exc_info:
        await service.list_audit_entries(qry)

    assert exc_info.value.required_permission == IPermissionPort.PERMISSION_READ
    audit_log_repo.get_by_credential.assert_not_called()
    audit_log_repo.list_entries.assert_not_called()
    audit_log_repo.append_entry.assert_not_called()


async def test_list_audit_entries_invalid_operation_string(
    service: AuditQueryService,
    audit_log_repo: AsyncMock,
) -> None:
    qry = ListAuditEntriesQuery(
        tenant_id=EntityId.generate(),
        credential_id=uuid4(),
        principal_id=uuid4(),
        operations=["NOT_AN_OPERATION"],
    )

    with pytest.raises(ApplicationValidationError) as exc_info:
        await service.list_audit_entries(qry)

    assert exc_info.value.field == "operations"
    assert "NOT_AN_OPERATION" in exc_info.value.reason
    audit_log_repo.get_by_credential.assert_not_called()
    audit_log_repo.list_entries.assert_not_called()
    audit_log_repo.append_entry.assert_not_called()


async def test_list_audit_entries_never_calls_append_entry(
    service: AuditQueryService,
    audit_log_repo: AsyncMock,
) -> None:
    tenant_uuid = EntityId.generate()
    credential_uuid = uuid4()
    tenant_id = tenant_uuid
    credential_id = CredentialId(credential_uuid)
    audit_log = make_audit_log(credential_id=credential_id, tenant_id=tenant_id)
    audit_log_repo.get_by_credential.return_value = audit_log
    audit_log_repo.list_entries.return_value = []
    qry = ListAuditEntriesQuery(
        tenant_id=tenant_uuid,
        credential_id=credential_uuid,
        principal_id=uuid4(),
    )

    await service.list_audit_entries(qry)

    audit_log_repo.append_entry.assert_not_called()
    audit_log_repo.get_by_credential.assert_awaited_once()
    audit_log_repo.list_entries.assert_awaited_once()


async def test_list_audit_entries_uses_get_by_credential_then_list_entries(
    service: AuditQueryService,
    audit_log_repo: AsyncMock,
) -> None:
    tenant_uuid = EntityId.generate()
    credential_uuid = uuid4()
    tenant_id = tenant_uuid
    credential_id = CredentialId(credential_uuid)
    audit_log = make_audit_log(credential_id=credential_id, tenant_id=tenant_id)
    audit_log_repo.get_by_credential.return_value = audit_log
    audit_log_repo.list_entries.return_value = []
    qry = ListAuditEntriesQuery(
        tenant_id=tenant_uuid,
        credential_id=credential_uuid,
        principal_id=uuid4(),
    )

    await service.list_audit_entries(qry)

    assert audit_log_repo.mock_calls[0][0] == "get_by_credential"
    assert audit_log_repo.mock_calls[1][0] == "list_entries"


async def test_list_audit_entries_invalid_limit(
    service: AuditQueryService,
    audit_log_repo: AsyncMock,
) -> None:
    qry = ListAuditEntriesQuery(
        tenant_id=EntityId.generate(),
        credential_id=uuid4(),
        principal_id=uuid4(),
        limit=0,
    )

    with pytest.raises(ApplicationValidationError) as exc_info:
        await service.list_audit_entries(qry)

    assert exc_info.value.field == "limit"
    audit_log_repo.get_by_credential.assert_not_called()
