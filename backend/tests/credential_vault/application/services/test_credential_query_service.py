"""Tests for CredentialQueryService."""

from __future__ import annotations

from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from tests.credential_vault.application.conftest import make_credential, make_version

from credential_vault.application.dtos.credential_dtos import CredentialDTO, VersionDTO
from credential_vault.application.exceptions import ApplicationValidationError
from credential_vault.application.queries.credential_queries import (
    GetCredentialQuery,
    GetVersionQuery,
    ListCredentialsQuery,
    ListVersionsQuery,
)
from credential_vault.application.services.credential_query_service import (
    CredentialQueryService,
)
from credential_vault.domain.exceptions.domain_exceptions import AccessDenied
from credential_vault.domain.ports.i_permission_port import IPermissionPort
from credential_vault.domain.repositories.i_credential_repository import (
    ICredentialRepository,
)
from credential_vault.domain.repositories.i_credential_version_repository import (
    ICredentialVersionRepository,
)
from credential_vault.domain.value_objects.identifiers import (
    CredentialId,
    VersionId,
)
from credential_vault.domain.value_objects.states import CredentialState, VersionState
from redforge.shared.identifiers import EntityId


@pytest.fixture
def credential_repo() -> AsyncMock:
    return AsyncMock(spec=ICredentialRepository)


@pytest.fixture
def version_repo() -> AsyncMock:
    return AsyncMock(spec=ICredentialVersionRepository)


@pytest.fixture
def service(
    credential_repo: AsyncMock,
    version_repo: AsyncMock,
    mock_permission_port: AsyncMock,
) -> CredentialQueryService:
    return CredentialQueryService(
        credential_repo=credential_repo,
        version_repo=version_repo,
        permission_port=mock_permission_port,
    )


# --- get_credential ---


async def test_get_credential_success(
    service: CredentialQueryService,
    credential_repo: AsyncMock,
    mock_permission_port: AsyncMock,
) -> None:
    tenant_uuid = EntityId.generate()
    credential_uuid = uuid4()
    credential = make_credential(
        tenant_id=tenant_uuid,
        credential_id=CredentialId(credential_uuid),
        name="query-me",
    )
    credential_repo.get_by_id.return_value = credential
    qry = GetCredentialQuery(
        tenant_id=tenant_uuid,
        credential_id=credential_uuid,
        principal_id=EntityId.generate(),
    )

    dto = await service.get_credential(qry)

    assert isinstance(dto, CredentialDTO)
    assert dto.name == "query-me"
    assert dto.credential_id == str(credential_uuid)
    assert dto.state == CredentialState.ACTIVE.value
    mock_permission_port.has_permission.assert_awaited_once()
    assert mock_permission_port.has_permission.await_args.args[2] == IPermissionPort.PERMISSION_READ
    credential_repo.get_by_id.assert_awaited_once_with(
        CredentialId(credential_uuid),
        tenant_uuid,
    )


async def test_get_credential_access_denied(
    service: CredentialQueryService,
    credential_repo: AsyncMock,
    mock_permission_port: AsyncMock,
) -> None:
    mock_permission_port.has_permission.return_value = False
    qry = GetCredentialQuery(
        tenant_id=EntityId.generate(),
        credential_id=uuid4(),
        principal_id=EntityId.generate(),
    )

    with pytest.raises(AccessDenied) as exc_info:
        await service.get_credential(qry)

    assert exc_info.value.required_permission == IPermissionPort.PERMISSION_READ
    credential_repo.get_by_id.assert_not_called()


# --- list_credentials ---


async def test_list_credentials_success(
    service: CredentialQueryService,
    credential_repo: AsyncMock,
    mock_permission_port: AsyncMock,
) -> None:
    tenant_uuid = EntityId.generate()
    credentials = [
        make_credential(tenant_id=tenant_uuid, name="one"),
        make_credential(tenant_id=tenant_uuid, name="two"),
    ]
    credential_repo.list_by_tenant.return_value = credentials
    qry = ListCredentialsQuery(
        tenant_id=tenant_uuid,
        principal_id=EntityId.generate(),
        states=["ACTIVE"],
        limit=50,
        offset=10,
    )

    result = await service.list_credentials(qry)

    assert len(result) == 2
    assert all(isinstance(dto, CredentialDTO) for dto in result)
    assert {dto.name for dto in result} == {"one", "two"}
    mock_permission_port.has_permission.assert_not_called()
    credential_repo.list_by_tenant.assert_awaited_once_with(
        tenant_uuid,
        [CredentialState.ACTIVE],
        50,
        10,
    )


async def test_list_credentials_invalid_state_string(
    service: CredentialQueryService,
    credential_repo: AsyncMock,
) -> None:
    qry = ListCredentialsQuery(
        tenant_id=EntityId.generate(),
        principal_id=EntityId.generate(),
        states=["NOT_A_STATE"],
    )

    with pytest.raises(ApplicationValidationError) as exc_info:
        await service.list_credentials(qry)

    assert exc_info.value.field == "states"
    assert "NOT_A_STATE" in exc_info.value.reason
    credential_repo.list_by_tenant.assert_not_called()


async def test_list_credentials_invalid_limit(
    service: CredentialQueryService,
    credential_repo: AsyncMock,
) -> None:
    qry = ListCredentialsQuery(
        tenant_id=EntityId.generate(),
        principal_id=EntityId.generate(),
        limit=0,
    )

    with pytest.raises(ApplicationValidationError) as exc_info:
        await service.list_credentials(qry)

    assert exc_info.value.field == "limit"
    credential_repo.list_by_tenant.assert_not_called()


async def test_list_credentials_invalid_offset(
    service: CredentialQueryService,
    credential_repo: AsyncMock,
) -> None:
    qry = ListCredentialsQuery(
        tenant_id=EntityId.generate(),
        principal_id=EntityId.generate(),
        offset=-1,
    )

    with pytest.raises(ApplicationValidationError) as exc_info:
        await service.list_credentials(qry)

    assert exc_info.value.field == "offset"
    credential_repo.list_by_tenant.assert_not_called()


async def test_list_credentials_clamps_limit(
    service: CredentialQueryService,
    credential_repo: AsyncMock,
) -> None:
    tenant_uuid = EntityId.generate()
    credential_repo.list_by_tenant.return_value = []
    qry = ListCredentialsQuery(
        tenant_id=tenant_uuid,
        principal_id=EntityId.generate(),
        limit=5000,
        offset=0,
    )

    await service.list_credentials(qry)

    credential_repo.list_by_tenant.assert_awaited_once_with(
        tenant_uuid,
        None,
        1000,
        0,
    )


# --- get_version ---


async def test_get_version_success(
    service: CredentialQueryService,
    version_repo: AsyncMock,
    mock_permission_port: AsyncMock,
) -> None:
    tenant_uuid = EntityId.generate()
    credential_uuid = uuid4()
    version_uuid = uuid4()
    version = make_version(
        tenant_id=tenant_uuid,
        credential_id=CredentialId(credential_uuid),
        version_id=VersionId(version_uuid),
        state=VersionState.ACTIVE,
    )
    version_repo.get_by_id.return_value = version
    qry = GetVersionQuery(
        tenant_id=tenant_uuid,
        credential_id=credential_uuid,
        version_id=version_uuid,
        principal_id=EntityId.generate(),
    )

    dto = await service.get_version(qry)

    assert isinstance(dto, VersionDTO)
    assert dto.version_id == str(version_uuid)
    assert dto.credential_id == str(credential_uuid)
    assert not hasattr(dto, "encrypted_payload")
    mock_permission_port.has_permission.assert_awaited_once()
    version_repo.get_by_id.assert_awaited_once_with(
        VersionId(version_uuid),
        tenant_uuid,
    )


async def test_get_version_access_denied(
    service: CredentialQueryService,
    version_repo: AsyncMock,
    mock_permission_port: AsyncMock,
) -> None:
    mock_permission_port.has_permission.return_value = False
    qry = GetVersionQuery(
        tenant_id=EntityId.generate(),
        credential_id=uuid4(),
        version_id=uuid4(),
        principal_id=EntityId.generate(),
    )

    with pytest.raises(AccessDenied):
        await service.get_version(qry)

    version_repo.get_by_id.assert_not_called()


# --- list_versions ---


async def test_list_versions_success(
    service: CredentialQueryService,
    version_repo: AsyncMock,
    mock_permission_port: AsyncMock,
) -> None:
    tenant_uuid = EntityId.generate()
    credential_uuid = uuid4()
    versions = [
        make_version(
            tenant_id=tenant_uuid,
            credential_id=CredentialId(credential_uuid),
            version_number=1,
        ),
        make_version(
            tenant_id=tenant_uuid,
            credential_id=CredentialId(credential_uuid),
            version_number=2,
            state=VersionState.PENDING,
        ),
    ]
    version_repo.list_by_credential.return_value = versions
    qry = ListVersionsQuery(
        tenant_id=tenant_uuid,
        credential_id=credential_uuid,
        principal_id=EntityId.generate(),
        states=["ACTIVE", "PENDING"],
    )

    result = await service.list_versions(qry)

    assert len(result) == 2
    assert all(isinstance(dto, VersionDTO) for dto in result)
    mock_permission_port.has_permission.assert_awaited_once()
    version_repo.list_by_credential.assert_awaited_once_with(
        CredentialId(credential_uuid),
        tenant_uuid,
        [VersionState.ACTIVE, VersionState.PENDING],
    )


async def test_list_versions_access_denied(
    service: CredentialQueryService,
    version_repo: AsyncMock,
    mock_permission_port: AsyncMock,
) -> None:
    mock_permission_port.has_permission.return_value = False
    qry = ListVersionsQuery(
        tenant_id=EntityId.generate(),
        credential_id=uuid4(),
        principal_id=EntityId.generate(),
    )

    with pytest.raises(AccessDenied):
        await service.list_versions(qry)

    version_repo.list_by_credential.assert_not_called()


async def test_list_versions_invalid_state_string(
    service: CredentialQueryService,
    version_repo: AsyncMock,
) -> None:
    qry = ListVersionsQuery(
        tenant_id=EntityId.generate(),
        credential_id=uuid4(),
        principal_id=EntityId.generate(),
        states=["BOGUS"],
    )

    with pytest.raises(ApplicationValidationError) as exc_info:
        await service.list_versions(qry)

    assert exc_info.value.field == "states"
    version_repo.list_by_credential.assert_not_called()
