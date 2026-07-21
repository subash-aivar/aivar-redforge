"""Domain events for ai_posture Phase 1 + Phase 2."""

from __future__ import annotations

from dataclasses import dataclass

from ai_posture.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class AISystemAssetDiscovered(BaseDomainEvent):
    asset_ref_id: str
    discovery_source: str


@dataclass(frozen=True, slots=True)
class AISystemAssetClassified(BaseDomainEvent):
    ai_system_kind: str


@dataclass(frozen=True, slots=True)
class AISystemAssetOwnerAssigned(BaseDomainEvent):
    owner_id: str


@dataclass(frozen=True, slots=True)
class AISystemAssetRegistered(BaseDomainEvent):
    ai_system_kind: str


@dataclass(frozen=True, slots=True)
class AISystemAssetDeprecated(BaseDomainEvent):
    reason: str


@dataclass(frozen=True, slots=True)
class AISystemAssetDecommissioned(BaseDomainEvent):
    reason: str


@dataclass(frozen=True, slots=True)
class ShadowAIStatusAssigned(BaseDomainEvent):
    registration_status: str


@dataclass(frozen=True, slots=True)
class ShadowAIAlertRaised(BaseDomainEvent):
    fingerprint_hash: str
    discovery_source: str


@dataclass(frozen=True, slots=True)
class ShadowAIAlertTriaged(BaseDomainEvent):
    alert_id: str
    triaged_by: str


@dataclass(frozen=True, slots=True)
class ShadowAIAlertConfirmed(BaseDomainEvent):
    alert_id: str
    confirmed_state: str


@dataclass(frozen=True, slots=True)
class ShadowAIAlertDismissedFalsePositive(BaseDomainEvent):
    alert_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class ShadowAIAlertResolved(BaseDomainEvent):
    alert_id: str
    resolution_action: str


@dataclass(frozen=True, slots=True)
class AIThreatProfileCreated(BaseDomainEvent):
    ai_system_asset_id: str
    ai_system_kind: str


@dataclass(frozen=True, slots=True)
class ThreatCategoryAssessed(BaseDomainEvent):
    category: str
    exposure_level: str


@dataclass(frozen=True, slots=True)
class ExposureLevelChanged(BaseDomainEvent):
    category: str
    previous_level: str
    new_level: str


@dataclass(frozen=True, slots=True)
class ThreatProfileFlaggedStale(BaseDomainEvent):
    ai_system_asset_id: str
    days_since_assessment: int


@dataclass(frozen=True, slots=True)
class AIRiskScoreComputed(BaseDomainEvent):
    ai_system_asset_id: str
    composite_score: float
    score_input_version: str


@dataclass(frozen=True, slots=True)
class AIRiskScoreStalenessExceeded(BaseDomainEvent):
    ai_system_asset_id: str
    snapshot_id: str


@dataclass(frozen=True, slots=True)
class AIComplianceMappingRecorded(BaseDomainEvent):
    ai_system_asset_id: str
    framework_id: str
    control_id: str
    control_status: str
    requires_human_attestation: bool
    evaluation_mode: str


@dataclass(frozen=True, slots=True)
class AIComplianceGapIdentified(BaseDomainEvent):
    ai_system_asset_id: str
    framework_id: str
    control_id: str
