"""Unit tests for StructlogEventPublisher — no database needed."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from threat_actor_intel.domain.events.threat_actor_events import ThreatActorRegistered
from threat_actor_intel.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)


@pytest.mark.asyncio
async def test_publish_batch_does_not_raise() -> None:
    publisher = StructlogEventPublisher()
    event = ThreatActorRegistered(
        event_id="evt-1",
        occurred_at=datetime.now(UTC),
        tenant_id="",
        aggregate_id="actor-1",
        aggregate_type="ThreatActor",
        name="APT29",
        origin="nation_state",
    )
    await publisher.publish_batch([event])


@pytest.mark.asyncio
async def test_publish_batch_handles_empty_list() -> None:
    publisher = StructlogEventPublisher()
    await publisher.publish_batch([])
