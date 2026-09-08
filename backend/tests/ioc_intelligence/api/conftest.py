"""FastAPI fixtures for ioc_intelligence API integration tests —
mirrors `tests/threat_actor_intel/api/conftest.py`'s shape: a real
ASGI app with the ioc_intelligence router mounted, `TenantContext`/
`PlatformContext` overridden via FastAPI's `dependency_overrides`
(never a spoofable request header), and a real Postgres-backed
`IocIntelContainer` built from a shared session factory."""

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

from ioc_intelligence.api.dependencies import get_optional_tenant_context
from ioc_intelligence.api.exception_handlers import register_ioc_intelligence_exception_handlers
from ioc_intelligence.api.v1 import router as ioc_intelligence_router
from ioc_intelligence.infrastructure.container import IocIntelContainer
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
def _apply_ioc_intelligence_migrations() -> None:
    if not os.environ.get("TEST_DATABASE_URL"):
        yield
        return
    _run_alembic("0160")
    yield


@pytest_asyncio.fixture
async def ioc_api_engine() -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def ioc_api_session_factory(
    ioc_api_engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(ioc_api_engine, expire_on_commit=False)


class _OrgStub:
    """Stubs `OrganizationService.get_by_id` so `require_permission`'s
    suspension check doesn't need a real `organizations` table row."""

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
    register_ioc_intelligence_exception_handlers(application)
    application.include_router(ioc_intelligence_router, prefix="/api/v1")
    application.state.ioc_intel_container = IocIntelContainer(session_factory=session_factory)

    def override_tenant_context() -> TenantContext:
        return TenantContext(
            user_id=str(user_id),
            email="ioc-intel-test@example.com",
            organization_id=str(organization_id),
            role=role,
            permissions=permissions if permissions is not None else frozenset(Permission),
        )

    def override_platform_context() -> PlatformContext:
        return PlatformContext(
            user_id=str(user_id),
            email="ioc-intel-test@example.com",
            platform_roles=(),
            permissions=platform_permissions if platform_permissions is not None else frozenset(),
        )

    application.dependency_overrides[get_tenant_context] = override_tenant_context
    # `get_optional_tenant_context` (used by the canonical `{ioc_id}`
    # routes) does not call `get_tenant_context` through FastAPI's
    # `Depends()` graph — it calls the real function directly with its
    # own resolved sub-dependencies, specifically so it can catch
    # `AuthorizationError` and fall back to `None`. That means
    # overriding `get_tenant_context` alone has no effect on it; it
    # must be overridden separately, with the same fixed value.
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
    ioc_api_session_factory: async_sessionmaker[AsyncSession],
    organization_id: EntityId,
    user_id: EntityId,
) -> AsyncIterator[AsyncClient]:
    """Organization OWNER — full tenant permissions, but NO platform
    permissions. Used to prove OWNER cannot reach global endpoints."""
    async for client in _client_for(
        ioc_api_session_factory,
        organization_id=organization_id,
        user_id=user_id,
        role=MembershipRole.OWNER,
    ):
        yield client


@pytest_asyncio.fixture
async def other_tenant_client(
    ioc_api_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncClient]:
    async for client in _client_for(
        ioc_api_session_factory,
        organization_id=EntityId.generate(),
        user_id=EntityId.generate(),
    ):
        yield client


async def _role_client(
    session_factory: async_sessionmaker[AsyncSession],
    role: MembershipRole,
) -> AsyncIterator[tuple[AsyncClient, EntityId]]:
    """Builds a client for the real, product-defined permission set of
    `role` (via `ROLE_PERMISSIONS`), not a hand-picked subset — proves
    the actual shipped role policy."""
    from redforge.domain.identity.value_objects import ROLE_PERMISSIONS

    org_id = EntityId.generate()
    application = _build_app(
        session_factory,
        organization_id=org_id,
        user_id=EntityId.generate(),
        role=role,
        permissions=ROLE_PERMISSIONS[role],
    )
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, org_id
    application.dependency_overrides.clear()


@pytest_asyncio.fixture
async def analyst_client(
    ioc_api_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[tuple[AsyncClient, EntityId]]:
    async for pair in _role_client(ioc_api_session_factory, MembershipRole.ANALYST):
        yield pair


@pytest_asyncio.fixture
async def member_client(
    ioc_api_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[tuple[AsyncClient, EntityId]]:
    async for pair in _role_client(ioc_api_session_factory, MembershipRole.MEMBER):
        yield pair


@pytest_asyncio.fixture
async def viewer_client(
    ioc_api_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[tuple[AsyncClient, EntityId]]:
    async for pair in _role_client(ioc_api_session_factory, MembershipRole.VIEWER):
        yield pair


@pytest_asyncio.fixture
async def no_permission_client(
    ioc_api_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncClient]:
    async for client in _client_for(
        ioc_api_session_factory,
        organization_id=EntityId.generate(),
        user_id=EntityId.generate(),
        role=MembershipRole.VIEWER,
        permissions=frozenset(),
    ):
        yield client


@pytest_asyncio.fixture
async def platform_admin_client(
    ioc_api_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncClient]:
    """A genuinely platform-authorized caller — holds
    `PLATFORM_IOC_INTEL_READ`/`_MANAGE` via `PlatformContext`, but
    deliberately NO tenant `Permission` at all (proves the global
    endpoints are gated purely on platform authority, never falling
    back to tenant permission)."""
    async for client in _client_for(
        ioc_api_session_factory,
        organization_id=EntityId.generate(),
        user_id=EntityId.generate(),
        role=MembershipRole.VIEWER,
        permissions=frozenset(),
        platform_permissions=frozenset(
            {
                PlatformPermission.PLATFORM_IOC_INTEL_READ,
                PlatformPermission.PLATFORM_IOC_INTEL_MANAGE,
            }
        ),
    ):
        yield client
