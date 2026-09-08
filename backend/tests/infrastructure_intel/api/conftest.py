"""FastAPI fixtures for infrastructure_intel API integration tests —
mirrors `tests/tool_intel/api/conftest.py`'s shape exactly: a real ASGI
app with the infrastructure_intel router mounted, `TenantContext`/
`PlatformContext` overridden via FastAPI's `dependency_overrides`
(never a spoofable request header), and a real Postgres-backed
`InfrastructureIntelContainer`."""

from __future__ import annotations

import os
import warnings
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from infrastructure_intel.api.dependencies import get_optional_tenant_context
from infrastructure_intel.api.exception_handlers import (
    register_infrastructure_intel_exception_handlers,
)
from infrastructure_intel.api.v1 import router as infrastructure_intel_router
from infrastructure_intel.infrastructure.container import InfrastructureIntelContainer
from redforge.api.dependencies import get_organization_service
from redforge.api.security import (
    PlatformContext,
    TenantContext,
    get_platform_context,
    get_tenant_context,
)
from redforge.domain.identity.value_objects import MembershipRole, Permission
from redforge.domain.platform_identity.value_objects import PlatformPermission
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware
from redforge.shared.identifiers import EntityId

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test",
)


def _run_alembic(*targets: str) -> None:
    os.environ["REDFORGE_DATABASE_URL"] = TEST_DATABASE_URL
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        cfg = Config("alembic.ini")
        for target in targets:
            command.upgrade(cfg, target)


@pytest.fixture(scope="session", autouse=True)
def _apply_infrastructure_intel_migrations() -> None:
    if not os.environ.get("TEST_DATABASE_URL"):
        yield
        return
    _run_alembic("0166")
    yield


@pytest_asyncio.fixture
async def ii_api_engine() -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def ii_api_session_factory(
    ii_api_engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(ii_api_engine, expire_on_commit=False)


class _OrgStub:
    async def get_by_id(self, organization_id: str) -> object:
        class _Org:
            status = "active"

        return _Org()


@pytest.fixture
def organization_id() -> EntityId:
    return EntityId.generate()


@pytest.fixture
def user_id() -> EntityId:
    return EntityId.generate()


def _build_app(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    organization_id: EntityId,
    user_id: EntityId,
    role: MembershipRole = MembershipRole.OWNER,
    permissions: frozenset[Permission] | None = None,
    platform_permissions: frozenset[PlatformPermission] | None = None,
) -> FastAPI:
    application = FastAPI()
    application.add_middleware(ErrorHandlerMiddleware)
    register_infrastructure_intel_exception_handlers(application)
    application.include_router(infrastructure_intel_router, prefix="/api/v1")
    application.state.infrastructure_intel_container = InfrastructureIntelContainer(
        session_factory=session_factory
    )

    def override_tenant_context() -> TenantContext:
        return TenantContext(
            user_id=str(user_id),
            email="infrastructure-intel-test@example.com",
            organization_id=str(organization_id),
            role=role,
            permissions=permissions if permissions is not None else frozenset(Permission),
        )

    def override_platform_context() -> PlatformContext:
        return PlatformContext(
            user_id=str(user_id),
            email="infrastructure-intel-test@example.com",
            platform_roles=(),
            permissions=platform_permissions if platform_permissions is not None else frozenset(),
        )

    application.dependency_overrides[get_tenant_context] = override_tenant_context
    application.dependency_overrides[get_optional_tenant_context] = override_tenant_context
    application.dependency_overrides[get_platform_context] = override_platform_context
    application.dependency_overrides[get_organization_service] = lambda: _OrgStub()
    return application


async def _client_for(
    session_factory: async_sessionmaker[AsyncSession],
    **kwargs: object,
) -> AsyncIterator[AsyncClient]:
    application = _build_app(session_factory, **kwargs)  # type: ignore[arg-type]
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    application.dependency_overrides.clear()


@pytest_asyncio.fixture
async def owner_client(
    ii_api_session_factory: async_sessionmaker[AsyncSession],
    organization_id: EntityId,
    user_id: EntityId,
) -> AsyncIterator[AsyncClient]:
    async for client in _client_for(
        ii_api_session_factory,
        organization_id=organization_id,
        user_id=user_id,
        role=MembershipRole.OWNER,
    ):
        yield client


@pytest_asyncio.fixture
async def other_tenant_client(
    ii_api_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncClient]:
    async for client in _client_for(
        ii_api_session_factory,
        organization_id=EntityId.generate(),
        user_id=EntityId.generate(),
    ):
        yield client


@pytest_asyncio.fixture
async def no_permission_client(
    ii_api_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncClient]:
    async for client in _client_for(
        ii_api_session_factory,
        organization_id=EntityId.generate(),
        user_id=EntityId.generate(),
        role=MembershipRole.VIEWER,
        permissions=frozenset(),
    ):
        yield client


@pytest_asyncio.fixture
async def platform_admin_client(
    ii_api_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncClient]:
    """A genuinely platform-authorized caller — holds
    `PLATFORM_INFRASTRUCTURE_READ`/`_MANAGE` via `PlatformContext`, but
    deliberately NO tenant `Permission` at all."""
    async for client in _client_for(
        ii_api_session_factory,
        organization_id=EntityId.generate(),
        user_id=EntityId.generate(),
        role=MembershipRole.VIEWER,
        permissions=frozenset(),
        platform_permissions=frozenset(
            {
                PlatformPermission.PLATFORM_INFRASTRUCTURE_READ,
                PlatformPermission.PLATFORM_INFRASTRUCTURE_MANAGE,
            }
        ),
    ):
        yield client
