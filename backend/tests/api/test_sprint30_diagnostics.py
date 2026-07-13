"""Sprint 30 — Projection diagnostic endpoint tests.

Verifies:
- GET /api/v1/runtime/projections returns all 9 registered projections
- GET /api/v1/runtime/projections/{name} returns projection detail
- GET /api/v1/runtime/projections/{name} returns 404 for unknown name
- GET /api/v1/runtime/replay/status returns worker stats (no worker → defaults)
- GET /api/v1/runtime/checkpoints returns one entry per registered projection
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

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


@pytest.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    settings = _test_settings()
    runtime = build_runtime_container(settings)
    await runtime.coordinator.startup()

    with (
        patch("redforge.app.create_engine"),
        patch("redforge.app.dispose_engine"),
        patch("redforge.app.build_runtime_container", return_value=runtime),
    ):
        app = create_app(settings=settings)
        app.state.runtime = runtime
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac


# ── GET /api/v1/runtime/projections ───────────────────────────────────────────


async def test_projections_list_returns_all_nine(client: AsyncClient) -> None:
    response = await client.get("/api/v1/runtime/projections")
    assert response.status_code == 200
    body = response.json()
    assert body["count"] >= 9
    names = [p["name"] for p in body["projections"]]
    for expected in (
        "campaign",
        "inventory",
        "validation",
        "risk",
        "intelligence",
        "evidence",
        "connector_activity",
        "asset_timeline",
        "organization_activity",
    ):
        assert expected in names, f"Missing projection: {expected}"


async def test_projections_list_includes_type_field(client: AsyncClient) -> None:
    response = await client.get("/api/v1/runtime/projections")
    assert response.status_code == 200
    for p in response.json()["projections"]:
        assert "name" in p
        assert "type" in p
        assert p["type"]


# ── GET /api/v1/runtime/projections/{name} ─────────────────────────────────────


async def test_projection_detail_returns_200_for_known(client: AsyncClient) -> None:
    response = await client.get("/api/v1/runtime/projections/campaign")
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "campaign"
    assert "type" in body
    assert "checkpoint_position" in body


async def test_projection_detail_returns_404_for_unknown(client: AsyncClient) -> None:
    response = await client.get("/api/v1/runtime/projections/does_not_exist")
    assert response.status_code == 404
    assert "does_not_exist" in response.json()["detail"]


# ── GET /api/v1/runtime/replay/status ─────────────────────────────────────────


async def test_replay_status_no_worker_returns_defaults(client: AsyncClient) -> None:
    """When no DLQReplayWorker has started, status returns zeroed defaults."""
    response = await client.get("/api/v1/runtime/replay/status")
    assert response.status_code == 200
    body = response.json()
    assert body["worker_running"] is False
    assert body["replayed"] == 0
    assert body["failed"] == 0
    assert body["skipped"] == 0
    assert body["in_flight"] == 0


# ── GET /api/v1/runtime/checkpoints ───────────────────────────────────────────


async def test_checkpoints_returns_one_per_projection(client: AsyncClient) -> None:
    response = await client.get("/api/v1/runtime/checkpoints")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] >= 9
    names = [c["projection_name"] for c in body["projections"]]
    assert "campaign" in names
    assert "inventory" in names


async def test_checkpoints_all_positions_are_integers(client: AsyncClient) -> None:
    response = await client.get("/api/v1/runtime/checkpoints")
    assert response.status_code == 200
    for cp in response.json()["projections"]:
        assert isinstance(cp["last_global_position"], int)
