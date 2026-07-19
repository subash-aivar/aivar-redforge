"""FastAPI fixtures for credential vault API integration tests."""

from __future__ import annotations

from collections.abc import AsyncIterator
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from credential_vault.api.dependencies import get_async_session
from credential_vault.api.exception_handlers import register_credential_vault_exception_handlers
from credential_vault.api.v1 import router as credential_vault_router
from credential_vault.infrastructure.container import CredentialVaultContainer
from redforge.api.dependencies import get_session_factory
from redforge.api.security import TenantContext, get_tenant_context
from redforge.domain.identity.value_objects import MembershipRole, Permission


@pytest.fixture(autouse=True)
def open_permission_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CREDENTIAL_VAULT_PERMISSION_MODE", "open")


@pytest.fixture
def organization_id() -> UUID:
    return uuid4()


@pytest.fixture
def user_id() -> UUID:
    return uuid4()


@pytest_asyncio.fixture
async def app(
    pg_session_factory: object,
    organization_id: UUID,
    user_id: UUID,
) -> AsyncIterator[FastAPI]:
    application = FastAPI()
    register_credential_vault_exception_handlers(application)
    application.include_router(credential_vault_router, prefix="/api/v1")
    application.state.cv_container = CredentialVaultContainer(session_factory=pg_session_factory)

    def override_tenant_context() -> TenantContext:
        return TenantContext(
            user_id=str(user_id),
            email="cv-test@example.com",
            organization_id=str(organization_id),
            role=MembershipRole.OWNER,
            permissions=frozenset(Permission),
        )

    async def override_async_session() -> AsyncIterator[object]:
        async with pg_session_factory() as session:  # type: ignore[attr-defined]
            yield session

    application.dependency_overrides[get_tenant_context] = override_tenant_context
    application.dependency_overrides[get_session_factory] = lambda: pg_session_factory
    application.dependency_overrides[get_async_session] = override_async_session
    yield application
    application.dependency_overrides.clear()


@pytest_asyncio.fixture
async def async_client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest_asyncio.fixture
async def other_tenant_client(
    pg_session_factory: object,
) -> AsyncIterator[AsyncClient]:
    other_org = uuid4()
    other_user = uuid4()
    application = FastAPI()
    register_credential_vault_exception_handlers(application)
    application.include_router(credential_vault_router, prefix="/api/v1")
    application.state.cv_container = CredentialVaultContainer(session_factory=pg_session_factory)

    def override_tenant_context() -> TenantContext:
        return TenantContext(
            user_id=str(other_user),
            email="other@example.com",
            organization_id=str(other_org),
            role=MembershipRole.OWNER,
            permissions=frozenset(Permission),
        )

    async def override_async_session() -> AsyncIterator[object]:
        async with pg_session_factory() as session:  # type: ignore[attr-defined]
            yield session

    application.dependency_overrides[get_tenant_context] = override_tenant_context
    application.dependency_overrides[get_session_factory] = lambda: pg_session_factory
    application.dependency_overrides[get_async_session] = override_async_session
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    application.dependency_overrides.clear()
