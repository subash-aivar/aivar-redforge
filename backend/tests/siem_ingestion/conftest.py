from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from redforge.shared.identifiers import EntityId
from siem_ingestion.application.commands.ingestion_commands import SubmitEventCommand
from siem_ingestion.domain.value_objects.enums import IngestionRole
from siem_shared.domain.value_objects.event_source import EventSourceType

if TYPE_CHECKING:
    from siem_shared.domain.value_objects.canonical_event import CanonicalEvent

SUBMITTER_ROLES = (IngestionRole.SUBMITTER.value,)


class RecordingReceiver:
    """Test double for ICanonicalEventReceiver — records everything it
    receives, implements no other behavior."""

    def __init__(self) -> None:
        self.received: list[CanonicalEvent] = []

    def receive(self, event: CanonicalEvent) -> None:
        self.received.append(event)


class AllowAllRateLimiter:
    """Test double for IIngestionRateLimiter — never throttles, records
    every call for assertion."""

    def __init__(self) -> None:
        self.calls: list[tuple[EntityId, int]] = []

    def check_and_consume(self, tenant_id: EntityId, event_count: int) -> bool:
        self.calls.append((tenant_id, event_count))
        return True


class DenyAllRateLimiter:
    """Test double for IIngestionRateLimiter — always throttles."""

    def __init__(self) -> None:
        self.calls: list[tuple[EntityId, int]] = []

    def check_and_consume(self, tenant_id: EntityId, event_count: int) -> bool:
        self.calls.append((tenant_id, event_count))
        return False


@pytest.fixture
def receiver() -> RecordingReceiver:
    return RecordingReceiver()


@pytest.fixture
def allow_all_rate_limiter() -> AllowAllRateLimiter:
    return AllowAllRateLimiter()


@pytest.fixture
def deny_all_rate_limiter() -> DenyAllRateLimiter:
    return DenyAllRateLimiter()


def valid_event_command(**overrides: object) -> SubmitEventCommand:
    defaults: dict[str, object] = {
        "tenant_id": EntityId.generate(),
        "source_type": EventSourceType.IDENTITY,
        "vendor": "okta",
        "category_raw": "authentication",
        "outcome_raw": "success",
        "occurred_at": datetime.now(UTC),
        "schema_version_raw": "1.0",
        "attributes": {"mfa": True},
        "actor_roles": SUBMITTER_ROLES,
    }
    defaults.update(overrides)
    return SubmitEventCommand(**defaults)  # type: ignore[arg-type]
