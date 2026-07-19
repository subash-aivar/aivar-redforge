"""FastAPI dependencies for credential vault routes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from fastapi import Depends, Request

from credential_vault.application.services.audit_query_service import AuditQueryService
from credential_vault.application.services.credential_application_service import (
    CredentialApplicationService,
)
from credential_vault.application.services.credential_query_service import CredentialQueryService
from credential_vault.application.services.expiration_policy_application_service import (
    ExpirationPolicyApplicationService,
)
from credential_vault.application.services.rotation_policy_application_service import (
    RotationPolicyApplicationService,
)
from credential_vault.application.services.vault_backend_application_service import (
    VaultBackendApplicationService,
)
from redforge.api.dependencies import get_session_factory
from redforge.api.security import TenantContext, get_tenant_context

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from credential_vault.infrastructure.container import CredentialVaultContainer


async def get_cv_container(request: Request) -> CredentialVaultContainer:
    container: CredentialVaultContainer = request.app.state.cv_container
    return container


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    factory: async_sessionmaker[AsyncSession] = get_session_factory()
    async with factory() as session:
        yield session


def get_tenant_uuid(tenant: TenantContext = Depends(get_tenant_context)) -> UUID:
    return UUID(tenant.organization_id)


def get_principal_uuid(tenant: TenantContext = Depends(get_tenant_context)) -> UUID:
    return UUID(tenant.user_id)


async def get_credential_service(
    container: CredentialVaultContainer = Depends(get_cv_container),
) -> CredentialApplicationService:
    return container._inner_credential_service


async def get_rotation_policy_service(
    container: CredentialVaultContainer = Depends(get_cv_container),
) -> RotationPolicyApplicationService:
    return container.rotation_policy_service


async def get_expiration_policy_service(
    container: CredentialVaultContainer = Depends(get_cv_container),
) -> ExpirationPolicyApplicationService:
    return container.expiration_policy_service


async def get_vault_backend_service(
    container: CredentialVaultContainer = Depends(get_cv_container),
) -> VaultBackendApplicationService:
    return container.vault_backend_service


async def get_credential_query_service(
    container: CredentialVaultContainer = Depends(get_cv_container),
    session: AsyncSession = Depends(get_async_session),
) -> CredentialQueryService:
    return container.make_credential_query_service(session)


async def get_audit_query_service(
    container: CredentialVaultContainer = Depends(get_cv_container),
    session: AsyncSession = Depends(get_async_session),
) -> AuditQueryService:
    return container.make_audit_query_service(session)


CredentialServiceDep = Annotated[CredentialApplicationService, Depends(get_credential_service)]
CredentialQueryServiceDep = Annotated[CredentialQueryService, Depends(get_credential_query_service)]
RotationPolicyServiceDep = Annotated[
    RotationPolicyApplicationService, Depends(get_rotation_policy_service)
]
ExpirationPolicyServiceDep = Annotated[
    ExpirationPolicyApplicationService, Depends(get_expiration_policy_service)
]
VaultBackendServiceDep = Annotated[
    VaultBackendApplicationService, Depends(get_vault_backend_service)
]
AuditQueryServiceDep = Annotated[AuditQueryService, Depends(get_audit_query_service)]
TenantIdDep = Annotated[UUID, Depends(get_tenant_uuid)]
PrincipalIdDep = Annotated[UUID, Depends(get_principal_uuid)]
