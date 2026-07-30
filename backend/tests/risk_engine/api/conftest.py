"""FastAPI fixtures for risk_engine API integration tests — mirrors
`tests/credential_vault/api/conftest.py`'s shape: a real ASGI app with
the risk_engine router mounted, `TenantContext` overridden via
FastAPI's `dependency_overrides` (never a spoofable request header),
and a real Postgres-backed `RiskEngineContainer` built from the shared
`re_session_factory` fixture already used by
`tests/risk_engine/infrastructure/conftest.py`."""

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
from redforge.shared.identifiers import EntityId
from risk_engine.api.exception_handlers import register_risk_engine_exception_handlers
from risk_engine.api.v1 import router as risk_engine_router
from risk_engine.infrastructure.container import RiskEngineContainer

# Self-contained DB fixtures (deliberately not shared via a
# cross-directory `pytest_plugins` entry — sibling-directory conftest
# module reuse via `pytest_plugins` collides with pytest's own
# directory-walk conftest auto-registration under pytest 9, raising
# "Plugin already registered under a different name"). Mirrors
# `tests/risk_engine/infrastructure/conftest.py`'s fixtures exactly,
# scoped locally to `tests/risk_engine/api/`.

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
def _apply_risk_engine_migrations() -> None:
    if not os.environ.get("TEST_DATABASE_URL"):
        yield
        return
    _run_alembic("0156")
    yield


@pytest_asyncio.fixture
async def re_engine() -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def re_session_factory(re_engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(re_engine, expire_on_commit=False)


class _OrgStub:
    """Stubs `OrganizationService.get_by_id` so `require_permission`'s
    suspension check doesn't need a real `organizations` table row —
    matches `tests/detection/api/conftest.py`'s `_OrgStub` exactly."""

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
    register_risk_engine_exception_handlers(application)
    application.include_router(risk_engine_router, prefix="/api/v1")
    application.state.risk_engine_container = RiskEngineContainer(session_factory=session_factory)

    def override_tenant_context() -> TenantContext:
        return TenantContext(
            user_id=str(user_id),
            email="risk-engine-test@example.com",
            organization_id=str(organization_id),
            role=MembershipRole.OWNER,
            permissions=frozenset(Permission),
        )

    application.dependency_overrides[get_tenant_context] = override_tenant_context
    application.dependency_overrides[get_organization_service] = lambda: _OrgStub()
    return application


@pytest_asyncio.fixture
async def app(
    re_session_factory: async_sessionmaker[AsyncSession],
    organization_id: EntityId,
    user_id: EntityId,
) -> AsyncIterator[FastAPI]:
    application = _build_app(re_session_factory, organization_id=organization_id, user_id=user_id)
    yield application
    application.dependency_overrides.clear()


@pytest_asyncio.fixture
async def async_client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest_asyncio.fixture
async def other_tenant_client(
    re_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncClient]:
    application = _build_app(
        re_session_factory,
        organization_id=EntityId.generate(),
        user_id=EntityId.generate(),
    )
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    application.dependency_overrides.clear()
