"""Domain events produced by siem_detection (M37 §2.4)."""

from __future__ import annotations

from dataclasses import dataclass, field

from siem_detection.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class DetectionRuleActivated(BaseDomainEvent):
    rule_version: int = 0


@dataclass(frozen=True, slots=True)
class DetectionRuleDeprecated(BaseDomainEvent):
    rule_version: int = 0
    reason: str = ""


@dataclass(frozen=True, slots=True)
class DetectionRuleVersionPublished(BaseDomainEvent):
    rule_version: int = 0


@dataclass(frozen=True, slots=True)
class DetectionMatched(BaseDomainEvent):
    """Carries enough context to be independently useful to alerting and
    future SOAR consumers without a follow-up query (M42 Phase 6 §
    acceptance criteria) — matched_event_ids is plural because a rule
    evaluation can match a window of events, not only a single one."""

    rule_id: str = ""
    matched_event_ids: tuple[str, ...] = field(default_factory=tuple)
    confidence: float = 0.0
