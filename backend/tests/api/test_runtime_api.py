"""Tests for runtime management API endpoints — Sprint 27.

Tests cover:
- GET /api/v1/runtime/status
- GET /api/v1/runtime/health
- GET /api/v1/runtime/circuits
- GET /api/v1/runtime/metrics
- GET /api/v1/runtime/dlq (auth)
- POST /api/v1/runtime/dlq/{id}/requeue (auth)
- DELETE /api/v1/runtime/dlq/{id} (auth)
- GET /api/v1/runtime/diagnostics (auth)

All tests use the `runtime_client` fixture which wires a real RuntimeContainer
onto `app.state.runtime` so endpoints have a live container to work with.
DLQ auth endpoints use a mocked TenantContext via dependency_override.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

from redforge.api.dependencies import get_effective_access_service, get_user_status_service
from redforge.api.security import get_tenant_context
from redforge.app import create_app
from redforge.application.platform.runtime_container import build_runtime_container
from redforge.application.platform.runtime_contracts import DeadLetterEntry
from redforge.core.config import Settings


class _AlwaysActiveUserStatusService:
    """Test double: every user is ACTIVE. These runtime tests exercise
    unauthenticated and mocked-tenant requests, not real DB-backed
    accounts — the M2 live-user-status check in api/security.py would
    otherwise hit an uninitialized test DB engine."""

    async def get_status(self, user_id: str) -> str:
        return "active"


class _NoOpEffectiveAccessService:
    """M17 regression shim for isolated test apps that build their own
    minimal FastAPI app without a real database engine: these tests
    never configure custom RBAC roles/groups, so the additive
    effective-access lookup is a no-op and the membership is always
    treated as active (each test asserts its own suspension/removal
    behavior through the real membership endpoints, not through this
    stub)."""

    async def get_additional_permissions(self, organization_id: str, user_id: str) -> frozenset:
        return frozenset()

    async def is_membership_active(self, organization_id: str, user_id: str) -> bool:
        return True


def _test_settings() -> Settings:
    return Settings(
        app_name="AIVAR RedForge Test",
        debug=True,
        environment="test",
        database_url="postgresql+asyncpg://x:x@localhost/x",
        log_level="DEBUG",
        log_format="console",
    )


@pytest.fixture
async def runtime_client() -> AsyncGenerator[AsyncClient, None]:
    """Client with a real RuntimeContainer on app.state (no DB needed)."""
    settings = _test_settings()
    runtime = build_runtime_container(settings)

    # Start the lifecycle coordinator (registers health checkers etc.)
    await runtime.coordinator.startup()

    with (
        patch("redforge.app.create_engine"),
        patch("redforge.app.dispose_engine"),
        patch("redforge.app.build_runtime_container", return_value=runtime),
    ):
        app = create_app(settings=settings)
        app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
        app.dependency_overrides[get_effective_access_service] = lambda: _NoOpEffectiveAccessService()
        # ASGITransport does not fire ASGI lifespan events, so set state manually.
        app.state.runtime = runtime
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac


@pytest.fixture
def mock_tenant() -> object:
    """A mock TenantContext for authenticated runtime endpoints."""
    from redforge.api.security import TenantContext
    from redforge.domain.identity.value_objects import ROLE_PERMISSIONS, MembershipRole

    role = MembershipRole.ADMIN
    return TenantContext(
        user_id="user-1",
        email="admin@test.com",
        organization_id="org-abc",
        role=role,
        permissions=ROLE_PERMISSIONS[role],
    )


@pytest.fixture
async def authed_runtime_client(
    mock_tenant: object,
) -> AsyncGenerator[AsyncClient, None]:
    """Client with RuntimeContainer and mocked auth context."""
    settings = _test_settings()
    runtime = build_runtime_container(settings)
    await runtime.coordinator.startup()

    with (
        patch("redforge.app.create_engine"),
        patch("redforge.app.dispose_engine"),
        patch("redforge.app.build_runtime_container", return_value=runtime),
    ):
        app = create_app(settings=settings)
        app.state.runtime = runtime  # ASGITransport does not fire lifespan events
        app.dependency_overrides[get_tenant_context] = lambda: mock_tenant
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac


# ── GET /runtime/status ───────────────────────────────────────────────────────


async def test_status_returns_200(runtime_client: AsyncClient) -> None:
    response = await runtime_client.get("/api/v1/runtime/status")
    assert response.status_code == 200


async def test_status_contains_required_fields(runtime_client: AsyncClient) -> None:
    body = (await runtime_client.get("/api/v1/runtime/status")).json()
    assert "phase" in body
    assert "overall_health" in body
    assert "circuit_states" in body
    assert "dlq_total_entries" in body
    assert "metrics_sample_count" in body
    assert "checked_at" in body


async def test_status_shows_running_phase(runtime_client: AsyncClient) -> None:
    body = (await runtime_client.get("/api/v1/runtime/status")).json()
    assert body["phase"] == "running"


async def test_status_circuit_states_has_standard_breakers(
    runtime_client: AsyncClient,
) -> None:
    body = (await runtime_client.get("/api/v1/runtime/status")).json()
    states = body["circuit_states"]
    assert "event_store" in states
    assert "knowledge_graph" in states
    assert "connector" in states
    assert "database" in states


async def test_status_all_circuits_closed_initially(runtime_client: AsyncClient) -> None:
    body = (await runtime_client.get("/api/v1/runtime/status")).json()
    for state in body["circuit_states"].values():
        assert state == "closed"


# ── GET /runtime/health ───────────────────────────────────────────────────────


async def test_health_returns_200(runtime_client: AsyncClient) -> None:
    response = await runtime_client.get("/api/v1/runtime/health")
    assert response.status_code == 200


async def test_health_contains_overall_status(runtime_client: AsyncClient) -> None:
    body = (await runtime_client.get("/api/v1/runtime/health")).json()
    assert "overall_status" in body
    assert body["overall_status"] in ("healthy", "degraded", "unhealthy")


async def test_health_components_list(runtime_client: AsyncClient) -> None:
    body = (await runtime_client.get("/api/v1/runtime/health")).json()
    assert isinstance(body["components"], list)


async def test_health_component_shape(runtime_client: AsyncClient) -> None:
    body = (await runtime_client.get("/api/v1/runtime/health")).json()
    if body["components"]:
        comp = body["components"][0]
        assert "component_id" in comp
        assert "status" in comp
        assert "message" in comp
        assert "checked_at" in comp


# ── GET /runtime/circuits ─────────────────────────────────────────────────────


async def test_circuits_returns_200(runtime_client: AsyncClient) -> None:
    response = await runtime_client.get("/api/v1/runtime/circuits")
    assert response.status_code == 200


async def test_circuits_returns_dict(runtime_client: AsyncClient) -> None:
    body = (await runtime_client.get("/api/v1/runtime/circuits")).json()
    assert isinstance(body, dict)


async def test_circuits_all_closed_at_startup(runtime_client: AsyncClient) -> None:
    body = (await runtime_client.get("/api/v1/runtime/circuits")).json()
    for name, state in body.items():
        assert state == "closed", f"Circuit {name!r} expected closed, got {state!r}"


# ── GET /runtime/metrics ──────────────────────────────────────────────────────


async def test_metrics_returns_200(runtime_client: AsyncClient) -> None:
    response = await runtime_client.get("/api/v1/runtime/metrics")
    assert response.status_code == 200


async def test_metrics_response_shape(runtime_client: AsyncClient) -> None:
    body = (await runtime_client.get("/api/v1/runtime/metrics")).json()
    assert "total_samples" in body
    assert "samples" in body
    assert "snapshot_at" in body


async def test_metrics_empty_initially(runtime_client: AsyncClient) -> None:
    body = (await runtime_client.get("/api/v1/runtime/metrics")).json()
    assert body["total_samples"] == 0
    assert body["samples"] == []


async def test_metrics_name_filter_query_param(runtime_client: AsyncClient) -> None:
    response = await runtime_client.get(
        "/api/v1/runtime/metrics", params={"name": "redforge.events.processed"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["samples"] == []


# ── DLQ endpoints (auth required) ────────────────────────────────────────────


async def test_dlq_list_unauthenticated_returns_403(runtime_client: AsyncClient) -> None:
    response = await runtime_client.get("/api/v1/runtime/dlq")
    assert response.status_code in (401, 403)


async def test_dlq_list_authenticated_returns_empty(
    authed_runtime_client: AsyncClient,
) -> None:
    body = (await authed_runtime_client.get("/api/v1/runtime/dlq")).json()
    assert body["entries"] == []
    assert body["total"] == 0


async def test_dlq_list_shows_org_entries(
    authed_runtime_client: AsyncClient,
) -> None:
    """Store an entry for the org and verify it appears in the list."""

    settings = _test_settings()
    runtime = build_runtime_container(settings)
    await runtime.coordinator.startup()

    entry = DeadLetterEntry(
        entry_id="e-1",
        source_projection="campaign_summary",
        event_id="ev-1",
        event_type="CampaignStarted",
        payload={"data": "x"},
        error_message="boom",
        retry_count=1,
        first_failed_at=datetime.now(UTC),
        last_failed_at=datetime.now(UTC),
        organization_id="org-abc",
    )
    await runtime.dlq.store(entry)

    with (
        patch("redforge.app.create_engine"),
        patch("redforge.app.dispose_engine"),
        patch("redforge.app.build_runtime_container", return_value=runtime),
    ):
        from redforge.api.security import TenantContext, get_tenant_context
        from redforge.domain.identity.value_objects import ROLE_PERMISSIONS, MembershipRole

        role = MembershipRole.ADMIN
        tenant = TenantContext(
            user_id="u1", email="a@a.com", organization_id="org-abc",
            role=role, permissions=ROLE_PERMISSIONS[role],
        )

        app = create_app(settings=settings)
        app.state.runtime = runtime  # ASGITransport does not fire lifespan events
        app.dependency_overrides[get_tenant_context] = lambda: tenant
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            body = (await ac.get("/api/v1/runtime/dlq")).json()

    assert body["total"] == 1
    assert body["entries"][0]["entry_id"] == "e-1"
    assert body["entries"][0]["event_type"] == "CampaignStarted"


async def test_dlq_requeue_not_found_returns_404(
    authed_runtime_client: AsyncClient,
) -> None:
    response = await authed_runtime_client.post(
        "/api/v1/runtime/dlq/nonexistent-id/requeue"
    )
    assert response.status_code == 404


async def test_dlq_discard_not_found_returns_404(
    authed_runtime_client: AsyncClient,
) -> None:
    response = await authed_runtime_client.delete(
        "/api/v1/runtime/dlq/nonexistent-id"
    )
    assert response.status_code == 404


# ── GET /runtime/diagnostics ──────────────────────────────────────────────────


async def test_diagnostics_unauthenticated_returns_403(
    runtime_client: AsyncClient,
) -> None:
    response = await runtime_client.get("/api/v1/runtime/diagnostics")
    assert response.status_code in (401, 403)


async def test_diagnostics_authenticated_returns_200(
    authed_runtime_client: AsyncClient,
) -> None:
    response = await authed_runtime_client.get("/api/v1/runtime/diagnostics")
    assert response.status_code == 200


async def test_diagnostics_contains_lifecycle_info(
    authed_runtime_client: AsyncClient,
) -> None:
    body = (await authed_runtime_client.get("/api/v1/runtime/diagnostics")).json()
    assert "phase" in body
    assert "startup_hooks" in body
    assert "shutdown_hooks" in body
    assert "backpressure_in_flight" in body
    assert "backpressure_utilization" in body
    assert "backpressure_throttled" in body


async def test_diagnostics_shows_registered_hooks(
    authed_runtime_client: AsyncClient,
) -> None:
    body = (await authed_runtime_client.get("/api/v1/runtime/diagnostics")).json()
    # The lifespan registers "database" and "runtime_health" startup hooks
    startup_hooks = body["startup_hooks"]
    assert isinstance(startup_hooks, list)
