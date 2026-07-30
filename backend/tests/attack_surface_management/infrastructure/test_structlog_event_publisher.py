"""Unit tests for StructlogEventPublisher — no DB needed."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from attack_surface_management.domain.events.asset_events import AssetDiscovered
from attack_surface_management.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)


@pytest.mark.asyncio
async def test_publish_batch_logs_each_event() -> None:
    publisher = StructlogEventPublisher()
    event = AssetDiscovered(
        tenant_id="tenant-1",
        aggregate_id="asset-1",
        aggregate_type="Asset",
        occurred_at=datetime.now(UTC),
        asset_type="external",
        primary_identifier="example.com",
    )
    # Should not raise.
    await publisher.publish_batch([event])


@pytest.mark.asyncio
async def test_publish_batch_empty_list_is_noop() -> None:
    publisher = StructlogEventPublisher()
    await publisher.publish_batch([])


@pytest.mark.asyncio
async def test_publish_batch_swallows_logging_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    publisher = StructlogEventPublisher()

    def _boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("logger exploded")

    monkeypatch.setattr(publisher._logger, "info", _boom)
    event = AssetDiscovered(
        tenant_id="tenant-1",
        aggregate_id="asset-1",
        aggregate_type="Asset",
        occurred_at=datetime.now(UTC),
        asset_type="external",
        primary_identifier="example.com",
    )
    # Must not raise even though the logger call fails.
    await publisher.publish_batch([event])
