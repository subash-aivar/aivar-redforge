"""FastAPI fixtures for threat_actor_intel API integration tests —
mirrors `tests/risk_engine/api/conftest.py`'s shape: a real ASGI app
with the threat_actor_intel router mounted, `TenantContext` overridden
via FastAPI's `dependency_overrides` (never a spoofable request
header), and a real Postgres-backed `ThreatActorIntelContainer` built
from a shared session factory."""

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

from redforge.api.dependencies import get_organization_service
from redforge.api.security import TenantContext, get_tenant_context
from redforge.domain.identity.value_objects import MembershipRole, Permission
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware
from redforge.shared.identifiers import EntityId
from threat_actor_intel.api.exception_handlers import (
    register_threat_actor_intel_exception_handlers,
)
from threat_actor_intel.api.v1 import router as threat_actor_intel_router
from threat_actor_intel.infrastructure.container import ThreatActorIntelContainer

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
def _apply_threat_actor_intel_migrations() -> None:
    if not os.environ.get("TEST_DATABASE_URL"):
        yield
        return
    _run_alembic("0159")
    yield


@pytest_asyncio.fixture
async def tai_api_engine() -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def tai_api_session_factory(
    tai_api_engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(tai_api_engine, expire_on_commit=False)


class _OrgStub:
    """Stubs `OrganizationService.get_by_id` so `require_permission`'s
    suspension check doesn't need a real `organizations` table row —
    matches `tests/attack_surface_management/api/conftest.py`'s
    `_OrgStub` precedent."""

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
) -> FastAPI:
    application = FastAPI()
    application.add_middleware(ErrorHandlerMiddleware)
    register_threat_actor_intel_exception_handlers(application)
    application.include_router(threat_actor_intel_router, prefix="/api/v1")
    application.state.threat_actor_intel_container = ThreatActorIntelContainer(
        session_factory=session_factory
    )

    def override_tenant_context() -> TenantContext:
        return TenantContext(
            user_id=str(user_id),
            email="threat-actor-intel-test@example.com",
            organization_id=str(organization_id),
            role=role,
            permissions=permissions if permissions is not None else frozenset(Permission),
        )

    application.dependency_overrides[get_tenant_context] = override_tenant_context
    application.dependency_overrides[get_organization_service] = lambda: _OrgStub()
    return application


@pytest_asyncio.fixture
async def app(
    tai_api_session_factory: async_sessionmaker[AsyncSession],
    organization_id: EntityId,
    user_id: EntityId,
) -> AsyncIterator[FastAPI]:
    application = _build_app(
        tai_api_session_factory, organization_id=organization_id, user_id=user_id
    )
    yield application
    application.dependency_overrides.clear()


@pytest_asyncio.fixture
async def async_client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest_asyncio.fixture
async def other_tenant_client(
    tai_api_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncClient]:
    application = _build_app(
        tai_api_session_factory,
        organization_id=EntityId.generate(),
        user_id=EntityId.generate(),
    )
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    application.dependency_overrides.clear()


@pytest_asyncio.fixture
async def viewer_only_client(
    tai_api_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncClient]:
    """A tenant context holding only `THREAT_INTEL_READ` — used to prove
    admin/analyst-gated routes reject a read-only caller."""
    application = _build_app(
        tai_api_session_factory,
        organization_id=EntityId.generate(),
        user_id=EntityId.generate(),
        role=MembershipRole.VIEWER,
        permissions=frozenset({Permission.THREAT_INTEL_READ}),
    )
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    application.dependency_overrides.clear()


@pytest_asyncio.fixture
async def no_permission_client(
    tai_api_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncClient]:
    application = _build_app(
        tai_api_session_factory,
        organization_id=EntityId.generate(),
        user_id=EntityId.generate(),
        role=MembershipRole.VIEWER,
        permissions=frozenset(),
    )
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    application.dependency_overrides.clear()


async def _role_client(
    session_factory: async_sessionmaker[AsyncSession],
    role: MembershipRole,
) -> AsyncIterator[tuple[AsyncClient, EntityId]]:
    """Builds a client for the real, product-defined permission set of
    `role` (via `ROLE_PERMISSIONS`), not a hand-picked subset — proves
    the actual role policy, not an idealized one."""
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
    tai_api_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[tuple[AsyncClient, EntityId]]:
    async for pair in _role_client(tai_api_session_factory, MembershipRole.ANALYST):
        yield pair


@pytest_asyncio.fixture
async def member_client(
    tai_api_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[tuple[AsyncClient, EntityId]]:
    async for pair in _role_client(tai_api_session_factory, MembershipRole.MEMBER):
        yield pair


@pytest_asyncio.fixture
async def role_viewer_client(
    tai_api_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[tuple[AsyncClient, EntityId]]:
    async for pair in _role_client(tai_api_session_factory, MembershipRole.VIEWER):
        yield pair


@pytest_asyncio.fixture
async def admin_client(
    tai_api_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[tuple[AsyncClient, EntityId]]:
    async for pair in _role_client(tai_api_session_factory, MembershipRole.ADMIN):
        yield pair
