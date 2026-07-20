"""Domain events raised by the DetectionRule aggregate."""

from __future__ import annotations

from dataclasses import dataclass

from detection.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionRuleCreated(BaseDomainEvent):
    rule_key: str
    category: str
    severity: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionRuleVersionPublished(BaseDomainEvent):
    semver: str
    published_by: str
    change_summary: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionRulePromoted(BaseDomainEvent):
    previous_state: str
    new_state: str
    actor: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionRuleDemoted(BaseDomainEvent):
    previous_state: str
    new_state: str
    actor: str
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionRuleActivated(BaseDomainEvent):
    semver: str
    actor: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionRuleDeprecated(BaseDomainEvent):
    actor: str
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionRuleArchived(BaseDomainEvent):
    actor: str
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class RuleTestSuiteUpdated(BaseDomainEvent):
    test_case_count: int
    actor: str


@dataclass(frozen=True, slots=True, kw_only=True)
class RuleTestResultRecorded(BaseDomainEvent):
    test_case_id: str
    status: str
    duration_ms: int


@dataclass(frozen=True, slots=True, kw_only=True)
class MitreAttackMappingUpdated(BaseDomainEvent):
    mapping_count: int
    actor: str


@dataclass(frozen=True, slots=True, kw_only=True)
class FalsePositiveProfileUpdated(BaseDomainEvent):
    fp_rate: float
    total_findings: int
    fp_count: int
