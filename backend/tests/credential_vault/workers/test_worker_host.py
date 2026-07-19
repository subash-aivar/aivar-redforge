"""Integration tests for CredentialVaultWorkerHost."""

from __future__ import annotations

import pytest
from tests.credential_vault.workers.conftest import build_worker_host

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_all_workers_start(
    rotation_scheduler_worker,
    expiration_scanner_worker,
    version_pruner_worker,
    dek_rewrap_worker,
) -> None:
    host = build_worker_host(
        rotation_scheduler_worker,
        expiration_scanner_worker,
        version_pruner_worker,
        dek_rewrap_worker,
    )
    await host.start()
    assert host.is_healthy is True
    await host.stop()


@pytest.mark.asyncio
async def test_stop_stops_all_workers(
    rotation_scheduler_worker,
    expiration_scanner_worker,
    version_pruner_worker,
    dek_rewrap_worker,
) -> None:
    host = build_worker_host(
        rotation_scheduler_worker,
        expiration_scanner_worker,
        version_pruner_worker,
        dek_rewrap_worker,
    )
    await host.start()
    await host.stop()
    assert rotation_scheduler_worker.is_running is False
    assert expiration_scanner_worker.is_running is False
    assert version_pruner_worker.is_running is False
    assert dek_rewrap_worker.is_running is False


@pytest.mark.asyncio
async def test_stats_returns_per_worker_stats(
    rotation_scheduler_worker,
    expiration_scanner_worker,
    version_pruner_worker,
) -> None:
    host = build_worker_host(
        rotation_scheduler_worker,
        expiration_scanner_worker,
        version_pruner_worker,
        rewrap_worker=None,
    )
    stats = host.stats()
    assert "rotation-test" in stats
    assert "expiration-test" in stats
    assert "pruner-test" in stats
    assert "rewrap-test" not in stats
    assert stats["rotation-test"]["running"] is False


@pytest.mark.asyncio
async def test_rewrap_worker_absent_when_not_configured(
    rotation_scheduler_worker,
    expiration_scanner_worker,
    version_pruner_worker,
) -> None:
    host = build_worker_host(
        rotation_scheduler_worker,
        expiration_scanner_worker,
        version_pruner_worker,
        rewrap_worker=None,
    )
    worker_ids = {worker.worker_id for worker in host._workers}
    assert worker_ids == {"rotation-test", "expiration-test", "pruner-test"}
