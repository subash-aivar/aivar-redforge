"""Unit tests for StructlogEventPublisher."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid7

import pytest

from credential_vault.domain.events.base import BaseDomainEvent
from credential_vault.domain.value_objects.identifiers import TenantId
from credential_vault.infrastructure.events.structlog_event_publisher import StructlogEventPublisher


@dataclass(frozen=True, slots=True, kw_only=True)
class _FakeEvent(BaseDomainEvent):
    pass


@pytest.mark.asyncio
async def test_publish_batch_never_raises() -> None:
    publisher = StructlogEventPublisher()
    event = _FakeEvent(
        event_id=str(uuid7()),
        occurred_at=datetime.now(UTC),
        tenant_id=TenantId(uuid7()),
        aggregate_id="agg-1",
        aggregate_type="Credential",
    )
    await publisher.publish_batch([event])
    await publisher.publish_batch([])


@pytest.mark.asyncio
async def test_publish_batch_swallows_logger_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    publisher = StructlogEventPublisher()

    def _fail(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("logger unavailable")

    monkeypatch.setattr(publisher._logger, "info", _fail)
    event = _FakeEvent(
        event_id=str(uuid7()),
        occurred_at=datetime.now(UTC),
        tenant_id=TenantId(uuid7()),
        aggregate_id="agg-2",
        aggregate_type="Credential",
    )
    await publisher.publish_batch([event])
