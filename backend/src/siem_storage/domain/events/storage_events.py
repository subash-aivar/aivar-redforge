"""Domain events produced by siem_storage (M37 §2.4).

Retention lifecycle is auditable by construction — a tier transition or
expiry is always an emitted event, never a silent delete (M37 §4).
"""

from __future__ import annotations

from dataclasses import dataclass

from siem_storage.domain.events.base import BaseDomainEvent
from siem_storage.domain.value_objects.enums import StorageTier


@dataclass(frozen=True, slots=True)
class RetentionTierTransitioned(BaseDomainEvent):
    event_ref: str = ""
    from_tier: StorageTier = StorageTier.HOT
    to_tier: StorageTier = StorageTier.WARM


@dataclass(frozen=True, slots=True)
class RetentionExpired(BaseDomainEvent):
    event_ref: str = ""
    final_tier: StorageTier = StorageTier.ARCHIVE
