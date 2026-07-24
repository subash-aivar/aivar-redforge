"""CQRS commands for siem_storage's Storage Foundation (M42 Phase 5).
Every command is immutable; none of them, nor the service that handles
them, ever performs physical persistence (M43E §2's explicit rule).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from siem_storage.domain.value_objects.enums import StorageTier

if TYPE_CHECKING:
    from redforge.shared.identifiers import EntityId
    from siem_shared.domain.value_objects.canonical_event import CanonicalEvent
    from siem_storage.domain.value_objects.retention import RetentionPolicy


@dataclass(frozen=True, slots=True)
class StoreCanonicalEventCommand:
    tenant_id: EntityId
    canonical_event: CanonicalEvent
    requested_tier: StorageTier = StorageTier.HOT
    retention_policy: RetentionPolicy | None = None
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class StoreBatchCommand:
    tenant_id: EntityId
    events: tuple[CanonicalEvent, ...] = field(default_factory=tuple)
    requested_tier: StorageTier = StorageTier.HOT
    retention_policy: RetentionPolicy | None = None
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ArchiveEventCommand:
    """A lifecycle-transition planning request for an already-stored
    event, referenced by identity — archiving doesn't need the full
    `CanonicalEvent` payload, only what tier it's moving from/to."""

    tenant_id: EntityId
    event_fingerprint: str
    event_category: str
    current_tier: StorageTier
    retention_policy: RetentionPolicy
    target_tier: StorageTier = StorageTier.ARCHIVE
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ApplyRetentionPolicyCommand:
    tenant_id: EntityId
    retention_policy: RetentionPolicy
    actor_roles: tuple[str, ...] = ()
