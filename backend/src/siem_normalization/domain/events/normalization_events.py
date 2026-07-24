"""Domain events produced by siem_normalization (M37 §2.4)."""

from __future__ import annotations

from dataclasses import dataclass

from siem_normalization.domain.events.base import BaseDomainEvent
from siem_normalization.domain.value_objects.enums import NormalizationFailureReason


@dataclass(frozen=True, slots=True)
class EventsNormalized(BaseDomainEvent):
    batch_fingerprint: str = ""
    schema_version: str = ""
    normalized_event_count: int = 0


@dataclass(frozen=True, slots=True)
class NormalizationFailed(BaseDomainEvent):
    batch_fingerprint: str = ""
    source_vendor: str = ""
    reason: NormalizationFailureReason = NormalizationFailureReason.MAPPING_ERROR
    detail: str = ""
