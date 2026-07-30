"""FastAPI fixtures for attack_surface_management API integration
tests — mirrors `tests/risk_engine/api/conftest.py`'s shape: a real
ASGI app with the attack_surface_management router mounted,
`TenantContext` overridden via FastAPI's `dependency_overrides` (never
a spoofable request header), and a real Postgres-backed
`AttackSurfaceManagementContainer` built from a locally-scoped
session-factory fixture."""

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

from attack_surface_management.api.exception_handlers import (
    register_attack_surface_management_exception_handlers,
)
from attack_surface_management.api.v1 import router as attack_surface_management_router
from attack_surface_management.infrastructure.container import AttackSurfaceManagementContainer
from redforge.api.dependencies import get_organization_service
from redforge.api.security import TenantContext, get_tenant_context
from redforge.domain.identity.value_objects import MembershipRole, Permission
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware
from redforge.shared.identifiers import EntityId

# Self-contained DB fixtures (deliberately not shared via a
# cross-directory `pytest_plugins` entry — sibling-directory conftest
# module reuse via `pytest_plugins` collides with pytest's own
# directory-walk conftest auto-registration under pytest 9, raising
# "Plugin already registered under a different name"). Mirrors
# `tests/attack_surface_management/infrastructure/conftest.py`'s
# fixtures, scoped locally to `tests/attack_surface_management/api/`.

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
def _apply_attack_surface_management_migrations() -> None:
    if not os.environ.get("TEST_DATABASE_URL"):
        yield
        return
    _run_alembic("0157")
    yield


@pytest_asyncio.fixture
async def asm_engine() -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def asm_session_factory(asm_engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(asm_engine, expire_on_commit=False)


class _OrgStub:
    """Stubs `OrganizationService.get_by_id` so `require_permission`'s
    suspension check doesn't need a real `organizations` table row —
    matches `tests/risk_engine/api/conftest.py`'s `_OrgStub` exactly."""

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
) -> FastAPI:
    application = FastAPI()
    application.add_middleware(ErrorHandlerMiddleware)
    register_attack_surface_management_exception_handlers(application)
    application.include_router(attack_surface_management_router, prefix="/api/v1")
    application.state.attack_surface_management_container = AttackSurfaceManagementContainer(
        session_factory=session_factory
    )

    def override_tenant_context() -> TenantContext:
        return TenantContext(
            user_id=str(user_id),
            email="attack-surface-management-test@example.com",
            organization_id=str(organization_id),
            role=MembershipRole.OWNER,
            permissions=frozenset(Permission),
        )

    application.dependency_overrides[get_tenant_context] = override_tenant_context
    application.dependency_overrides[get_organization_service] = lambda: _OrgStub()
    return application


@pytest_asyncio.fixture
async def app(
    asm_session_factory: async_sessionmaker[AsyncSession],
    organization_id: EntityId,
    user_id: EntityId,
) -> AsyncIterator[FastAPI]:
    application = _build_app(asm_session_factory, organization_id=organization_id, user_id=user_id)
    yield application
    application.dependency_overrides.clear()


@pytest_asyncio.fixture
async def async_client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest_asyncio.fixture
async def other_tenant_client(
    asm_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncClient]:
    application = _build_app(
        asm_session_factory,
        organization_id=EntityId.generate(),
        user_id=EntityId.generate(),
    )
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    application.dependency_overrides.clear()
