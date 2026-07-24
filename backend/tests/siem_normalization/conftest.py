from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from redforge.shared.identifiers import EntityId
from siem_normalization.application.commands.normalization_commands import (
    NormalizeEventCommand,
)
from siem_normalization.domain.value_objects.enums import NormalizationRole
from siem_shared.domain.value_objects.event_category import EventCategory
from siem_shared.domain.value_objects.event_outcome import EventOutcome
from siem_shared.domain.value_objects.event_source import EventSourceType
from siem_shared.domain.value_objects.schema_version import SchemaVersion

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from datetime import datetime

    from siem_normalization.application.ports.normalized_event_draft import NormalizedEventDraft
    from siem_shared.domain.value_objects.canonical_event import CanonicalEvent

EXECUTOR_ROLES = (NormalizationRole.EXECUTOR.value,)


class FakeNormalizer:
    """Test double for IEventNormalizer — a stand-in for a future
    provider-specific implementation, never a real one."""

    def __init__(
        self,
        provider: str,
        schema_version: SchemaVersion,
        source_type: EventSourceType = EventSourceType.CUSTOM,
        mapper: Callable[[Mapping[str, object], EntityId], NormalizedEventDraft] | None = None,
    ) -> None:
        self._provider = provider
        self._schema_version = schema_version
        self._source_type = source_type
        self._mapper = mapper

    @property
    def provider(self) -> str:
        return self._provider

    @property
    def source_type(self) -> EventSourceType:
        return self._source_type

    @property
    def schema_version(self) -> SchemaVersion:
        return self._schema_version

    def normalize(
        self, raw_payload: Mapping[str, object], tenant_id: EntityId
    ) -> NormalizedEventDraft:
        if self._mapper is None:
            raise AssertionError("FakeNormalizer.normalize called with no mapper configured")
        return self._mapper(raw_payload, tenant_id)


def make_draft(
    *,
    category: EventCategory = EventCategory.CUSTOM,
    outcome: EventOutcome = EventOutcome.SUCCESS,
    occurred_at: datetime,
    **overrides: object,
) -> NormalizedEventDraft:
    from siem_normalization.application.ports.normalized_event_draft import NormalizedEventDraft

    defaults: dict[str, object] = {
        "category": category,
        "outcome": outcome,
        "occurred_at": occurred_at,
        "attributes": {},
    }
    defaults.update(overrides)
    return NormalizedEventDraft(**defaults)  # type: ignore[arg-type]


class RecordingReceiver:
    def __init__(self) -> None:
        self.received: list[CanonicalEvent] = []

    def receive(self, event: CanonicalEvent) -> None:
        self.received.append(event)


@pytest.fixture
def receiver() -> RecordingReceiver:
    return RecordingReceiver()


def normalize_event_command(**overrides: object) -> NormalizeEventCommand:
    defaults: dict[str, object] = {
        "tenant_id": EntityId.generate(),
        "provider": "acme",
        "raw_payload": {"raw": "payload"},
        "declared_schema_version_raw": "1.0",
        "actor_roles": EXECUTOR_ROLES,
    }
    defaults.update(overrides)
    return NormalizeEventCommand(**defaults)  # type: ignore[arg-type]


SCHEMA_V1_0 = SchemaVersion(1, 0)
