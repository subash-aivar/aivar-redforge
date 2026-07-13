"""Tests for POST /api/v1/runtime/circuits/{name}/reset — Sprint 28 + 29.

Verifies:
- 204 on successful reset of an OPEN circuit breaker
- 404 when circuit name not found
- 401/403 without authentication
- 403 when caller lacks ORG_MANAGE (MEMBER/VIEWER roles) — Sprint 29 RBAC
- Circuit state returns to closed after reset
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from redforge.api.dependencies import get_organization_service, get_user_status_service
from redforge.api.security import get_tenant_context
from redforge.app import create_app
from redforge.application.platform.runtime_container import build_runtime_container
from redforge.core.config import Settings


def _test_settings() -> Settings:
    return Settings(
        app_name="AIVAR RedForge Test",
        debug=True,
        environment="test",
        database_url="postgresql+asyncpg://x:x@localhost/x",
        log_level="DEBUG",
        log_format="console",
    )


def _make_tenant(role_name: str = "admin") -> object:
    from redforge.api.security import TenantContext
    from redforge.domain.identity.value_objects import ROLE_PERMISSIONS, MembershipRole

    role = MembershipRole(role_name)
    return TenantContext(
        user_id="user-1",
        email=f"{role_name}@test.com",
        organization_id="org-abc",
        role=role,
        permissions=ROLE_PERMISSIONS[role],
    )


def _make_org_service_mock() -> object:
    """Mock OrganizationService that returns an active org (not suspended)."""
    mock_svc = AsyncMock()
    # require_permission checks org.status != "suspended"
    mock_org = AsyncMock()
    mock_org.status = "active"
    mock_svc.get_by_id.return_value = mock_org
    return mock_svc


class _AlwaysActiveUserStatusService:
    """Test double: every user is ACTIVE."""

    async def get_status(self, user_id: str) -> str:
        return "active"


@pytest.fixture
def mock_tenant() -> object:
    return _make_tenant("admin")


@pytest.fixture
async def authed_client(mock_tenant: object) -> AsyncGenerator[tuple[AsyncClient, object], None]:
    settings = _test_settings()
    runtime = build_runtime_container(settings)
    await runtime.coordinator.startup()

    with (
        patch("redforge.app.create_engine"),
        patch("redforge.app.dispose_engine"),
        patch("redforge.app.build_runtime_container", return_value=runtime),
    ):
        app = create_app(settings=settings)
        app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
        app.state.runtime = runtime
        app.dependency_overrides[get_tenant_context] = lambda: mock_tenant
        app.dependency_overrides[get_organization_service] = lambda: _make_org_service_mock()
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac, runtime


@pytest.fixture
async def unauthed_client() -> AsyncGenerator[AsyncClient, None]:
    settings = _test_settings()
    runtime = build_runtime_container(settings)
    await runtime.coordinator.startup()

    with (
        patch("redforge.app.create_engine"),
        patch("redforge.app.dispose_engine"),
        patch("redforge.app.build_runtime_container", return_value=runtime),
    ):
        app = create_app(settings=settings)
        app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
        app.state.runtime = runtime
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac


# ── Authentication guard ───────────────────────────────────────────────────────


async def test_reset_unauthenticated_returns_403(unauthed_client: AsyncClient) -> None:
    response = await unauthed_client.post("/api/v1/runtime/circuits/database/reset")
    assert response.status_code in (401, 403)


# ── RBAC guard (Sprint 29) ─────────────────────────────────────────────────────


@pytest.mark.parametrize("role", ["member", "viewer"])
async def test_reset_insufficient_role_returns_403(role: str) -> None:
    """MEMBER and VIEWER lack ORG_MANAGE and must receive 403."""
    settings = _test_settings()
    runtime = build_runtime_container(settings)
    await runtime.coordinator.startup()

    low_priv_tenant = _make_tenant(role)

    with (
        patch("redforge.app.create_engine"),
        patch("redforge.app.dispose_engine"),
        patch("redforge.app.build_runtime_container", return_value=runtime),
    ):
        app = create_app(settings=settings)
        app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
        app.state.runtime = runtime
        app.dependency_overrides[get_tenant_context] = lambda: low_priv_tenant
        app.dependency_overrides[get_organization_service] = lambda: _make_org_service_mock()
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post("/api/v1/runtime/circuits/database/reset")
    assert response.status_code == 403


async def test_reset_admin_role_succeeds() -> None:
    """ADMIN role has ORG_MANAGE and must receive 204."""
    settings = _test_settings()
    runtime = build_runtime_container(settings)
    await runtime.coordinator.startup()

    admin_tenant = _make_tenant("admin")

    with (
        patch("redforge.app.create_engine"),
        patch("redforge.app.dispose_engine"),
        patch("redforge.app.build_runtime_container", return_value=runtime),
    ):
        app = create_app(settings=settings)
        app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
        app.state.runtime = runtime
        app.dependency_overrides[get_tenant_context] = lambda: admin_tenant
        app.dependency_overrides[get_organization_service] = lambda: _make_org_service_mock()
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post("/api/v1/runtime/circuits/database/reset")
    assert response.status_code == 204


async def test_reset_owner_role_succeeds() -> None:
    """OWNER role has all permissions and must receive 204."""
    settings = _test_settings()
    runtime = build_runtime_container(settings)
    await runtime.coordinator.startup()

    owner_tenant = _make_tenant("owner")

    with (
        patch("redforge.app.create_engine"),
        patch("redforge.app.dispose_engine"),
        patch("redforge.app.build_runtime_container", return_value=runtime),
    ):
        app = create_app(settings=settings)
        app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
        app.state.runtime = runtime
        app.dependency_overrides[get_tenant_context] = lambda: owner_tenant
        app.dependency_overrides[get_organization_service] = lambda: _make_org_service_mock()
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post("/api/v1/runtime/circuits/database/reset")
    assert response.status_code == 204


# ── Not found ─────────────────────────────────────────────────────────────────


async def test_reset_unknown_circuit_returns_404(
    authed_client: tuple[AsyncClient, object],
) -> None:
    ac, _ = authed_client
    response = await ac.post("/api/v1/runtime/circuits/nonexistent-circuit/reset")
    assert response.status_code == 404
    assert "nonexistent-circuit" in response.json()["detail"]


# ── Successful reset ───────────────────────────────────────────────────────────


async def test_reset_open_circuit_returns_204(
    authed_client: tuple[AsyncClient, object],
) -> None:
    ac, runtime = authed_client
    from redforge.application.platform.runtime_container import RuntimeContainer
    assert isinstance(runtime, RuntimeContainer)

    # Drive the database circuit to OPEN
    db_cb = runtime.circuit_registry.get("database")
    assert db_cb is not None
    import contextlib
    for _ in range(db_cb._failure_threshold):
        with contextlib.suppress(RuntimeError):
            await db_cb.execute(lambda: (_ for _ in ()).throw(RuntimeError("fail")))

    from redforge.application.platform.runtime_contracts import CircuitState
    assert db_cb.state == CircuitState.OPEN

    response = await ac.post("/api/v1/runtime/circuits/database/reset")
    assert response.status_code == 204


async def test_circuit_closed_after_reset(
    authed_client: tuple[AsyncClient, object],
) -> None:
    ac, runtime = authed_client
    from redforge.application.platform.runtime_container import RuntimeContainer
    assert isinstance(runtime, RuntimeContainer)

    db_cb = runtime.circuit_registry.get("database")
    assert db_cb is not None

    # Open it
    import contextlib
    for _ in range(db_cb._failure_threshold):
        with contextlib.suppress(RuntimeError):
            await db_cb.execute(lambda: (_ for _ in ()).throw(RuntimeError("fail")))

    # Reset via API
    await ac.post("/api/v1/runtime/circuits/database/reset")

    # Verify CLOSED via circuits endpoint
    body = (await ac.get("/api/v1/runtime/circuits")).json()
    assert body["database"] == "closed"


async def test_reset_already_closed_circuit_returns_204(
    authed_client: tuple[AsyncClient, object],
) -> None:
    ac, _ = authed_client
    # Circuit is CLOSED at startup — reset should still succeed
    response = await ac.post("/api/v1/runtime/circuits/database/reset")
    assert response.status_code == 204
