"""CQRS commands for siem_ingestion's Event Ingestion Pipeline (M42
Phase 3). Follows the platform's existing command convention: a plain,
frozen dataclass carrying `tenant_id` + `actor_roles` alongside the
request payload — no framework types, no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from redforge.shared.identifiers import EntityId
    from siem_shared.domain.value_objects.entity_ref import EntityRef
    from siem_shared.domain.value_objects.event_source import EventSourceType


@dataclass(frozen=True, slots=True)
class SubmitEventCommand:
    """A single source event, not yet validated or normalized into a
    `CanonicalEvent` — that happens inside `IngestionApplicationService`."""

    tenant_id: EntityId
    source_type: EventSourceType
    vendor: str
    category_raw: str
    outcome_raw: str
    occurred_at: datetime
    schema_version_raw: str
    source_connector_id: EntityId | None = None
    severity_raw: str | None = None
    actor: EntityRef | None = None
    target: EntityRef | None = None
    raw_payload_ref: str | None = None
    attributes: Mapping[str, object] = field(default_factory=dict)
    event_id: EntityId | None = None
    fingerprint_raw: str | None = None
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SubmitBatchCommand:
    """A bounded group of `SubmitEventCommand`s submitted together
    (M37 §3 — batching, not a single event, is the throughput-relevant
    admission unit)."""

    tenant_id: EntityId
    events: tuple[SubmitEventCommand, ...]
    actor_roles: tuple[str, ...] = ()
    batch_fingerprint: str | None = None
