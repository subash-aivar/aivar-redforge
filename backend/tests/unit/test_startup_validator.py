"""Tests for startup_validator — Sprint 28.

Verifies:
- validate_startup passes when environment == "test" (no DB check)
- validate_startup passes when DB is reachable
- validate_startup raises StartupValidationError when DB is unreachable
- validate_startup raises for invalid config values
- All config errors are collected and reported together
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from redforge.application.platform.startup_validator import (
    StartupValidationError,
    validate_startup,
)
from redforge.core.config import Settings


def _test_settings(**overrides: object) -> Settings:
    base = dict(
        app_name="Test",
        debug=True,
        environment="test",
        database_url="postgresql+asyncpg://x:x@localhost/x",
    )
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


class TestStartupValidatorInTestEnv:
    async def test_passes_without_db_check_in_test_env(self) -> None:
        settings = _test_settings(environment="test")
        mock_engine = MagicMock()
        # No DB call should happen
        await validate_startup(settings, mock_engine)
        mock_engine.connect.assert_not_called()

    async def test_raises_for_invalid_poll_interval(self) -> None:
        settings = _test_settings(runtime_replay_poll_interval_s=0.0)
        mock_engine = MagicMock()
        with pytest.raises(StartupValidationError, match="runtime_replay_poll_interval_s"):
            await validate_startup(settings, mock_engine)

    async def test_raises_for_invalid_max_concurrent(self) -> None:
        settings = _test_settings(runtime_replay_max_concurrent=0)
        mock_engine = MagicMock()
        with pytest.raises(StartupValidationError, match="runtime_replay_max_concurrent"):
            await validate_startup(settings, mock_engine)

    async def test_raises_for_invalid_batch_size(self) -> None:
        settings = _test_settings(runtime_replay_batch_size=0)
        mock_engine = MagicMock()
        with pytest.raises(StartupValidationError, match="runtime_replay_batch_size"):
            await validate_startup(settings, mock_engine)

    async def test_raises_for_invalid_poison_threshold(self) -> None:
        settings = _test_settings(runtime_dlq_poison_threshold=0)
        mock_engine = MagicMock()
        with pytest.raises(StartupValidationError, match="runtime_dlq_poison_threshold"):
            await validate_startup(settings, mock_engine)

    async def test_collects_multiple_errors(self) -> None:
        settings = _test_settings(
            runtime_replay_poll_interval_s=0.0,
            runtime_replay_max_concurrent=0,
        )
        mock_engine = MagicMock()
        with pytest.raises(StartupValidationError) as exc_info:
            await validate_startup(settings, mock_engine)
        msg = str(exc_info.value)
        assert "runtime_replay_poll_interval_s" in msg
        assert "runtime_replay_max_concurrent" in msg


class TestStartupValidatorDBConnectivity:
    async def test_passes_when_db_is_reachable(self) -> None:
        settings = _test_settings(environment="development")
        mock_engine = MagicMock()
        mock_conn = AsyncMock()
        # SELECT 1 returns an ignored result; migration check needs fetchone() = head
        migration_result = MagicMock()
        migration_result.fetchone.return_value = ("0070",)
        mock_conn.execute = AsyncMock(side_effect=[None, migration_result])
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_conn)
        cm.__aexit__ = AsyncMock(return_value=None)
        mock_engine.connect = MagicMock(return_value=cm)

        await validate_startup(settings, mock_engine)

    async def test_raises_when_db_is_unreachable(self) -> None:
        from sqlalchemy.exc import OperationalError

        settings = _test_settings(environment="development")
        mock_engine = MagicMock()
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(
            side_effect=OperationalError("connection refused", None, None)
        )
        cm.__aexit__ = AsyncMock(return_value=None)
        mock_engine.connect = MagicMock(return_value=cm)

        with pytest.raises(StartupValidationError, match="Database unreachable"):
            await validate_startup(settings, mock_engine)

    async def test_error_message_includes_exception_type(self) -> None:
        settings = _test_settings(environment="development")
        mock_engine = MagicMock()
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(side_effect=OSError("timeout"))
        cm.__aexit__ = AsyncMock(return_value=None)
        mock_engine.connect = MagicMock(return_value=cm)

        with pytest.raises(StartupValidationError, match="OSError"):
            await validate_startup(settings, mock_engine)
