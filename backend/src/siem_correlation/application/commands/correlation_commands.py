"""CQRS commands for siem_correlation's Correlation Engine (M42 Phase 7).

Correlation consumes a `DetectionMatch` (M44A) together with the
`CanonicalEvent` (M43B) it was raised against, and accumulates it into
a bounded `CorrelationSession` (M43A) — never creating an `Alert`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from siem_correlation.domain.value_objects.enums import CorrelationKind

if TYPE_CHECKING:
    from redforge.shared.identifiers import EntityId
    from siem_detection.application.dtos.detection_match import DetectionMatch
    from siem_shared.domain.value_objects.canonical_event import CanonicalEvent


@dataclass(frozen=True, slots=True)
class CorrelationInput:
    """One `DetectionMatch` + the `CanonicalEvent` it was raised
    against, destined for one correlation rule's session."""

    correlation_rule_id: str
    detection_match: DetectionMatch
    canonical_event: CanonicalEvent
    correlation_kind: CorrelationKind = CorrelationKind.ENTITY


@dataclass(frozen=True, slots=True)
class CorrelateDetectionMatchCommand:
    tenant_id: EntityId
    item: CorrelationInput
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CorrelateBatchCommand:
    tenant_id: EntityId
    items: tuple[CorrelationInput, ...] = field(default_factory=tuple)
    actor_roles: tuple[str, ...] = ()
