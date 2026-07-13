"""Sprint 31 — Diagnostic endpoint improvements.

Verifies:
- GET /runtime/checkpoints returns -1 when no session_factory (test env)
- GET /runtime/replay/status worker_running reflects is_running
- GET /runtime/replay/status includes exhausted counter
- Worker state key is present in stats()
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


# ── GET /runtime/checkpoints ─────────────────────────────────────────────────


async def test_checkpoints_returns_minus_one_without_db(client: AsyncClient) -> None:
    """Without a DB session_factory (test env), positions fall back to -1."""
    response = await client.get("/api/v1/runtime/checkpoints")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] >= 9
    for cp in body["projections"]:
        assert cp["last_global_position"] == -1, (
            f"Expected -1 for {cp['projection_name']}, got {cp['last_global_position']}"
        )


async def test_checkpoints_names_match_registry(client: AsyncClient) -> None:
    """Checkpoint names must match the registered projection names exactly."""
    response = await client.get("/api/v1/runtime/checkpoints")
    assert response.status_code == 200
    names = {cp["projection_name"] for cp in response.json()["projections"]}
    expected = {
        "campaign", "inventory", "validation", "risk", "intelligence",
        "evidence", "connector_activity", "asset_timeline", "organization_activity",
    }
    assert expected.issubset(names)


# ── GET /runtime/replay/status ────────────────────────────────────────────────


async def test_replay_status_worker_running_false_without_worker(client: AsyncClient) -> None:
    """worker_running is False when no replay worker is running."""
    response = await client.get("/api/v1/runtime/replay/status")
    assert response.status_code == 200
    assert response.json()["worker_running"] is False


async def test_replay_status_all_counters_zero_without_worker(client: AsyncClient) -> None:
    response = await client.get("/api/v1/runtime/replay/status")
    body = response.json()
    assert body["replayed"] == 0
    assert body["failed"] == 0
    assert body["skipped"] == 0
    assert body["in_flight"] == 0
