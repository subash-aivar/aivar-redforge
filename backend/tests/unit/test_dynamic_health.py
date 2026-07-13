"""Tests for dynamic health probes — Sprint 28.

Verifies:
- make_database_health_probe returns HEALTHY on successful SELECT 1
- make_database_health_probe returns UNHEALTHY when DB raises
- make_replay_worker_health_probe reflects worker.is_running
- make_dlq_depth_health_probe degrades at warn_threshold and fails at critical
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from redforge.application.platform.dynamic_health import (
    make_database_health_probe,
    make_dlq_depth_health_probe,
    make_replay_worker_health_probe,
)
from redforge.application.platform.runtime_contracts import HealthStatus


class TestDatabaseHealthProbe:
    async def test_healthy_when_select_succeeds(self) -> None:
        mock_engine = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value=None)
        mock_engine.connect = MagicMock(
            return_value=mock_conn.__aenter__.return_value.__aenter__.return_value
        )

        # Simulate the context manager properly
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_conn)
        cm.__aexit__ = AsyncMock(return_value=None)
        mock_engine.connect = MagicMock(return_value=cm)

        probe = make_database_health_probe(mock_engine)
        result = await probe()

        assert result.status == HealthStatus.HEALTHY
        assert result.component_id == "database"

    async def test_unhealthy_when_db_raises(self) -> None:
        mock_engine = MagicMock()
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(side_effect=OSError("connection refused"))
        cm.__aexit__ = AsyncMock(return_value=None)
        mock_engine.connect = MagicMock(return_value=cm)

        probe = make_database_health_probe(mock_engine)
        result = await probe()

        assert result.status == HealthStatus.UNHEALTHY
        assert "OSError" in result.message
        assert result.component_id == "database"

    async def test_returns_component_health_shape(self) -> None:
        mock_engine = MagicMock()
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=AsyncMock())
        cm.__aexit__ = AsyncMock(return_value=None)
        mock_engine.connect = MagicMock(return_value=cm)

        probe = make_database_health_probe(mock_engine)
        result = await probe()

        assert hasattr(result, "component_id")
        assert hasattr(result, "component_type")
        assert hasattr(result, "status")
        assert hasattr(result, "message")
        assert hasattr(result, "checked_at")


class TestReplayWorkerHealthProbe:
    async def test_healthy_when_worker_is_running(self) -> None:
        mock_worker = MagicMock()
        mock_worker.is_running = True

        probe = make_replay_worker_health_probe(mock_worker)
        result = await probe()

        assert result.status == HealthStatus.HEALTHY
        assert result.component_id == "replay_worker"

    async def test_degraded_when_worker_is_stopped(self) -> None:
        mock_worker = MagicMock()
        mock_worker.is_running = False

        probe = make_replay_worker_health_probe(mock_worker)
        result = await probe()

        assert result.status == HealthStatus.DEGRADED
        assert result.component_id == "replay_worker"


class TestDLQDepthHealthProbe:
    async def test_healthy_below_warn_threshold(self) -> None:
        mock_dlq = AsyncMock()
        mock_dlq.total_depth = AsyncMock(return_value=100)

        probe = make_dlq_depth_health_probe(mock_dlq, warn_threshold=1000, critical_threshold=9000)
        result = await probe()

        assert result.status == HealthStatus.HEALTHY
        assert result.component_id == "dlq"

    async def test_degraded_at_warn_threshold(self) -> None:
        mock_dlq = AsyncMock()
        mock_dlq.total_depth = AsyncMock(return_value=1000)

        probe = make_dlq_depth_health_probe(mock_dlq, warn_threshold=1000, critical_threshold=9000)
        result = await probe()

        assert result.status == HealthStatus.DEGRADED

    async def test_unhealthy_at_critical_threshold(self) -> None:
        mock_dlq = AsyncMock()
        mock_dlq.total_depth = AsyncMock(return_value=9000)

        probe = make_dlq_depth_health_probe(mock_dlq, warn_threshold=1000, critical_threshold=9000)
        result = await probe()

        assert result.status == HealthStatus.UNHEALTHY

    async def test_unhealthy_when_depth_raises(self) -> None:
        mock_dlq = AsyncMock()
        mock_dlq.total_depth = AsyncMock(side_effect=RuntimeError("db down"))

        probe = make_dlq_depth_health_probe(mock_dlq)
        result = await probe()

        assert result.status == HealthStatus.UNHEALTHY
        assert "RuntimeError" in result.message
