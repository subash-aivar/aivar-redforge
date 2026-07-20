"""Domain events for DetectionPack aggregate."""

from __future__ import annotations

from dataclasses import dataclass

from detection.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionPackCreated(BaseDomainEvent):
    pack_key: str
    category: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionPackPublished(BaseDomainEvent):
    pack_key: str
    version: str


@dataclass(frozen=True, slots=True, kw_only=True)
class RuleAddedToPack(BaseDomainEvent):
    rule_id: str
    rule_version: str | None


@dataclass(frozen=True, slots=True, kw_only=True)
class RuleRemovedFromPack(BaseDomainEvent):
    rule_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionPackVersionReleased(BaseDomainEvent):
    version: str
    rule_count: int


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionPackDeprecated(BaseDomainEvent):
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class PackSubscriptionChanged(BaseDomainEvent):
    subscribed_tenant_id: str
    action: str  # subscribed | unsubscribed


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionCoverageUpdated(BaseDomainEvent):
    technique_count: int
    covered_technique_count: int
