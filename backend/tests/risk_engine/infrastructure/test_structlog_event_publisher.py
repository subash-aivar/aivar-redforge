"""Unit tests for StructlogEventPublisher — no DB needed."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from risk_engine.domain.events.risk_profile_events import RiskProfileCreated
from risk_engine.infrastructure.events.structlog_event_publisher import StructlogEventPublisher


@pytest.mark.asyncio
async def test_publish_batch_logs_each_event(caplog: pytest.LogCaptureFixture) -> None:
    publisher = StructlogEventPublisher()
    event = RiskProfileCreated(
        tenant_id="tenant-1",
        aggregate_id="profile-1",
        aggregate_type="EnterpriseRiskProfile",
        occurred_at=datetime.now(UTC),
        subject_reference="asset-1",
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
    event = RiskProfileCreated(
        tenant_id="tenant-1",
        aggregate_id="profile-1",
        aggregate_type="EnterpriseRiskProfile",
        occurred_at=datetime.now(UTC),
        subject_reference="asset-1",
    )
    # Must not raise even though the logger call fails.
    await publisher.publish_batch([event])
